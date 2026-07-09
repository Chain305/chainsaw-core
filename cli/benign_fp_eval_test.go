package cli

// benign_fp_eval_test.go — measures the guard's FALSE-BLOCK rate on a corpus of
// real, top-download benign packages. Where detection_lead_eval (package
// intelligence) reports "any own-bytes signal fired" on benign input, this runs
// the actual guard verdict — analyzeArtifact, the exact BLOCK/WARN decision a
// user feels on install — so the published number is "benign top packages that
// would be REFUSED", not merely "flagged".
//
// Corpus: scripts/detection-eval builds a small checked-in set; for a large run
// point CHAINSAW_DETECTION_EVAL_CORPUS at a manifest.jsonl of top npm/pypi
// tarballs (see scratchpad builder). Skips when unset, so CI stays hermetic.
//
// Run:
//   CHAINSAW_DETECTION_EVAL_CORPUS=<dir> go test ./core/cli/ -run TestBenignFalseBlockRate -v

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type benignSample struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Label     string `json:"label"`
	File      string `json:"file"`
	Fetched   bool   `json:"fetched"`
}

func TestBenignFalseBlockRate(t *testing.T) {
	dir := os.Getenv("CHAINSAW_DETECTION_EVAL_CORPUS")
	if dir == "" {
		t.Skip("set CHAINSAW_DETECTION_EVAL_CORPUS=<dir> with a benign manifest.jsonl")
	}
	f, err := os.Open(filepath.Join(dir, "manifest.jsonl"))
	if err != nil {
		t.Fatalf("open manifest: %v", err)
	}
	defer f.Close()

	var (
		total, blocked, warned int
		byEco                  = map[string]int{}
		blockedEco             = map[string]int{}
		blockedSet, warnedSet  []string
	)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var s benignSample
		if json.Unmarshal([]byte(line), &s) != nil || s.Label != "benign" || !s.Fetched || s.File == "" {
			continue
		}
		tgz, err := os.ReadFile(s.File)
		if err != nil || len(tgz) == 0 {
			continue
		}
		total++
		byEco[s.Ecosystem]++
		v := analyzeArtifact(s.Ecosystem, tgz)
		label := s.Ecosystem + ":" + s.Name + "@" + s.Version
		switch {
		case v.Block:
			blocked++
			blockedEco[s.Ecosystem]++
			blockedSet = append(blockedSet, label+"  ["+v.Reason+"]")
		case v.Severity != "":
			warned++
			warnedSet = append(warnedSet, label+"  ["+v.Reason+"]")
		}
	}
	sort.Strings(blockedSet)
	sort.Strings(warnedSet)

	rate := func(n int) float64 {
		if total == 0 {
			return 0
		}
		return 100 * float64(n) / float64(total)
	}
	t.Logf("=== BENIGN FALSE-BLOCK EVAL (guard verdict on real top packages) ===")
	t.Logf("corpus: %d benign packages scanned (%v)", total, byEco)
	t.Logf("FALSE-BLOCK: %d/%d = %.2f%%   (by ecosystem: %v)", blocked, total, rate(blocked), blockedEco)
	t.Logf("soft-WARN:   %d/%d = %.2f%%", warned, total, rate(warned))
	if len(blockedSet) > 0 {
		t.Logf("BLOCKED (false positives — must be 0 for the block claim):\n  %s", strings.Join(blockedSet, "\n  "))
	} else {
		t.Logf("BLOCKED: none — 0 false blocks across %d top packages.", total)
	}
	if len(warnedSet) > 0 {
		t.Logf("WARNED (soft, does not break install):\n  %s", strings.Join(warnedSet, "\n  "))
	}
}

// TestBlockCatchRate is the paired half of TestBenignFalseBlockRate: over a
// combined corpus (benign + real malicious, e.g. the DataDog dataset) it reports
// the guard's HARD-BLOCK catch-rate on malware alongside the false-block rate on
// benign — both via the same analyzeArtifact verdict, so the numbers are directly
// comparable ("blocks X% of real malware at Y% false-block"). Offline behavioral
// subset only; the name/feed floor (228k OpenSSF) and server-side
// ioc/import-time providers catch more on top of this.
func TestBlockCatchRate(t *testing.T) {
	dir := os.Getenv("CHAINSAW_DETECTION_EVAL_CORPUS")
	if dir == "" {
		t.Skip("set CHAINSAW_DETECTION_EVAL_CORPUS=<combined benign+malicious corpus>")
	}
	f, err := os.Open(filepath.Join(dir, "manifest.jsonl"))
	if err != nil {
		t.Fatalf("open manifest: %v", err)
	}
	defer f.Close()

	var malTotal, malBlocked, benTotal, benBlocked int
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var s benignSample
		if json.Unmarshal([]byte(line), &s) != nil || !s.Fetched || s.File == "" {
			continue
		}
		tgz, err := os.ReadFile(s.File)
		if err != nil || len(tgz) == 0 {
			continue
		}
		blocked := analyzeArtifact(s.Ecosystem, tgz).Block
		switch s.Label {
		case "malicious":
			malTotal++
			if blocked {
				malBlocked++
			}
		case "benign":
			benTotal++
			if blocked {
				benBlocked++
			}
		}
	}
	pct := func(n, d int) float64 {
		if d == 0 {
			return 0
		}
		return 100 * float64(n) / float64(d)
	}
	t.Logf("=== BLOCK-BASED CATCH vs FP (analyzeArtifact hard-block; offline behavioral subset) ===")
	t.Logf("malware HARD-BLOCK catch: %d/%d = %.1f%%", malBlocked, malTotal, pct(malBlocked, malTotal))
	t.Logf("benign  false-block:      %d/%d = %.2f%%", benBlocked, benTotal, pct(benBlocked, benTotal))
	t.Logf("(offline subset — excludes name/feed floor + server-side ioc/import-time providers)")
}
