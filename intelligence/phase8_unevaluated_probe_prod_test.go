package intelligence

// TestPhase8UnevaluatedProbe counts the CI-exit population Wave C creates:
// coordinates that come back VerdictUnknown, which core/cli's treeExitCode
// maps to ExitOpError(2) for the whole lockfile.
//
// WHY A THIRD HARNESS. TestPhase8VerdictSnapshot replays a persisted report
// through two engines, which sees every change inside ProjectToRiskInput and
// core/risk but cannot see a warning the NEXT scan will add.
// TestPhase8RescanProbe adds the one P8-05 stamps. Neither can see P8-04:
// its warning depends on a live package-level probe against the registry.
//
// This test models that probe from the persisted evidence, and the model is
// stated rather than hidden:
//
//   - A row carrying a registrymetadata `not_found` is a row whose metadata
//     endpoint 404ed. That is the precondition for P8-04 and the only
//     coordinates it can touch.
//   - For the packument ecosystems (npm, composer, cocoapods, pub) the
//     document that 404ed IS the package object, so package-absence is
//     CERTAIN from the persisted report.
//   - For the per-version ecosystems (pypi, cargo, rubygems, nuget, maven,
//     go) the persisted warning came from the per-version endpoint and the
//     package-level probe's answer is not in the report. The model assumes
//     the probe also 404s, which makes the count an UPPER BOUND on the
//     P8-04 population. That is the conservative direction for a fix whose
//     purpose is to shrink it.
//
// Both sides of the single-canonical-registry rule are evaluated in one
// process, because the rule is a pure function of the ecosystem string and
// needs no second checkout: `before` applies WarnPackageNotFound to every
// definite absence (what Wave C shipped), `after` applies it only where the
// ecosystem has one canonical registry (the correction).
//
// Opt-in: CHAINSAW_FLIP_CORPUS=/abs/reports.jsonl, same row shape as its two
// siblings. CHAINSAW_SNAPSHOT_OUT=/abs/out.txt writes the per-coordinate
// detail.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/risk"
)

// androidCoordinate reports whether a Maven-family coordinate is an
// Android/AndroidX artifact — the population published to
// maven.google.com and absent from repo1, which is what the unrestricted
// rule mislabelled.
func androidCoordinate(pkg string) bool {
	for _, prefix := range []string{"androidx.", "com.android.", "android.arch."} {
		if strings.HasPrefix(pkg, prefix) {
			return true
		}
	}
	return false
}

// syntheticUpload reports whether a coordinate is one of the QA/smoke
// uploads. Those are REAL absences and are correctly caught; they are
// counted separately so they cannot flatter or muddy a before/after delta.
func syntheticUpload(pkg string) bool {
	lower := strings.ToLower(pkg)
	for _, marker := range []string{"t_est", "t-est", "t.est", "smoke", "wave-v", "wave-aa", "wave-ab"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func TestPhase8UnevaluatedProbe(t *testing.T) {
	path := os.Getenv("CHAINSAW_FLIP_CORPUS")
	if path == "" {
		t.Skip("set CHAINSAW_FLIP_CORPUS=<jsonl> to count the unevaluated population")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open corpus: %v", err)
	}
	defer f.Close()

	type row struct {
		Eco       string          `json:"eco"`
		Pkg       string          `json:"pkg"`
		Ver       string          `json:"ver"`
		Persisted string          `json:"persisted_verdict"`
		Report    json.RawMessage `json:"report"`
	}

	at := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	var (
		total, parsed                     int
		unevalBefore, unevalAfter         int
		p8_04Before, p8_04After           int
		androidRescued, syntheticAffected int
		lines                             []string
	)

	// verdictWith rebuilds the report from the raw bytes each time so the
	// two arms cannot contaminate each other through the merged warnings.
	verdictWith := func(raw json.RawMessage, eco string, restrict bool) (string, bool) {
		var rep Report
		if err := json.Unmarshal(raw, &rep); err != nil {
			return "", false
		}
		promoted := false
		for i := range rep.Observation.Warnings {
			w := &rep.Observation.Warnings[i]
			if w.Provider != "registrymetadata" || !isDefiniteAbsence(w) {
				continue
			}
			if restrict && !ecosystemHasSingleCanonicalRegistry(eco) {
				continue
			}
			w.Code = WarnPackageNotFound
			promoted = true
		}
		markNoAdvisoryCoverage(&rep, at)
		ev := risk.EvaluatePackage(ProjectToRiskInput(&rep), risk.Options{})
		if ev == nil {
			return "", promoted
		}
		return string(ev.Verdict), promoted
	}

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		total++
		var r row
		if err := json.Unmarshal(line, &r); err != nil {
			continue
		}
		var probe Report
		if err := json.Unmarshal(r.Report, &probe); err != nil {
			continue
		}
		parsed++

		before, promotedBefore := verdictWith(r.Report, r.Eco, false)
		after, promotedAfter := verdictWith(r.Report, r.Eco, true)
		if promotedBefore {
			p8_04Before++
		}
		if promotedAfter {
			p8_04After++
		}
		if before == string(risk.VerdictUnknown) {
			unevalBefore++
		}
		if after == string(risk.VerdictUnknown) {
			unevalAfter++
		}
		if promotedBefore && !promotedAfter {
			if androidCoordinate(r.Pkg) {
				androidRescued++
			}
			if syntheticUpload(r.Pkg) {
				syntheticAffected++
			}
			lines = append(lines, fmt.Sprintf("%s/%s@%s\t%s -> %s\tandroid=%v\tsynthetic=%v",
				r.Eco, r.Pkg, r.Ver, before, after,
				androidCoordinate(r.Pkg), syntheticUpload(r.Pkg)))
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan corpus: %v", err)
	}
	sort.Strings(lines)

	pct := func(n int) float64 {
		if parsed == 0 {
			return 0
		}
		return 100 * float64(n) / float64(parsed)
	}
	summary := fmt.Sprintf(
		"UNEVALUATED total=%d parsed=%d\n"+
			"  before(unrestricted P8-04): unevaluated=%d (%.2f%%) package_not_found=%d\n"+
			"  after (single-canonical)  : unevaluated=%d (%.2f%%) package_not_found=%d\n"+
			"  no longer mislabelled=%d  of which android=%d synthetic=%d",
		total, parsed,
		unevalBefore, pct(unevalBefore), p8_04Before,
		unevalAfter, pct(unevalAfter), p8_04After,
		len(lines), androidRescued, syntheticAffected)

	if out := os.Getenv("CHAINSAW_SNAPSHOT_OUT"); out != "" {
		w, err := os.Create(out)
		if err != nil {
			t.Fatalf("create out: %v", err)
		}
		bw := bufio.NewWriter(w)
		fmt.Fprintln(bw, "# "+strings.ReplaceAll(summary, "\n", "\n# "))
		for _, l := range lines {
			fmt.Fprintln(bw, l)
		}
		if err := bw.Flush(); err != nil {
			t.Fatalf("flush: %v", err)
		}
		if err := w.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
	}
	t.Log("\n" + summary)
}
