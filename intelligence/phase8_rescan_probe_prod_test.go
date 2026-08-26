package intelligence

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/risk"
)

// TestPhase8RescanProbe measures the ONE Phase-8 change whose effect a
// fixed-report replay cannot see.
//
// TestPhase8VerdictSnapshot holds the persisted report blob constant and
// diffs two engines. That is the right instrument for every change inside
// ProjectToRiskInput and core/risk, but Wave C's P8-05 stamps its warning
// during the SCAN (markNoAdvisoryCoverage, called post-merge), so a report
// written before the fix does not carry WarnUnsupported and the replay reads
// as "no change" for the entire uncovered-ecosystem population.
//
// This test therefore applies markNoAdvisoryCoverage to each persisted
// report — exactly what the next scan of that coordinate will do, on facts
// that a rescan does not change (the ecosystem string, and whether any
// vulnerability lane ever produced a ScannedAt) — and reports how many rows
// move to VerdictUnknown as a result. That count is the P8-05 half of the
// CI-exit-code delta, because treeExitCode (core/cli/intel_scan.go:294-308)
// returns ExitOpError(2) when any node is unevaluated and that outranks warn.
//
// HEAD-ONLY BY CONSTRUCTION: markNoAdvisoryCoverage does not exist at the
// base commit, so this file cannot be copied into the base checkout the way
// phase8_snapshot_prod_test.go must be. The base-side number it is compared
// against is the base tree's snapshot output.
//
// What it does NOT cover, and cannot: P8-04 (a package that 404s upstream)
// depends on a live package-level probe against the registry, so its
// post-fix warning cannot be derived from a persisted report at all.
func TestPhase8RescanProbe(t *testing.T) {
	path := os.Getenv("CHAINSAW_FLIP_CORPUS")
	if path == "" {
		t.Skip("set CHAINSAW_FLIP_CORPUS=<jsonl> to probe a snapshot")
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

	var lines []string
	at := time.Date(2026, 8, 25, 0, 0, 0, 0, time.UTC)
	total, parsed, stamped := 0, 0, 0

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
		var rep Report
		if err := json.Unmarshal(r.Report, &rep); err != nil {
			continue
		}
		parsed++

		// Verdict with the report exactly as persisted.
		asIs := risk.EvaluatePackage(ProjectToRiskInput(&rep), risk.Options{})

		// Verdict after the next scan stamps what this build now stamps.
		if markNoAdvisoryCoverage(&rep, at) {
			stamped++
		}
		rescanned := risk.EvaluatePackage(ProjectToRiskInput(&rep), risk.Options{})

		if asIs == nil || rescanned == nil || asIs.Verdict == rescanned.Verdict {
			continue
		}
		lines = append(lines, fmt.Sprintf("%s/%s@%s\t%s -> %s",
			r.Eco, r.Pkg, r.Ver, string(asIs.Verdict), string(rescanned.Verdict)))
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan corpus: %v", err)
	}
	sort.Strings(lines)

	out := os.Getenv("CHAINSAW_SNAPSHOT_OUT")
	if out == "" {
		for _, l := range lines {
			t.Log(l)
		}
	} else {
		w, err := os.Create(out)
		if err != nil {
			t.Fatalf("create out: %v", err)
		}
		bw := bufio.NewWriter(w)
		fmt.Fprintf(bw, "# total=%d parsed=%d stamped_WarnUnsupported=%d verdict_moves=%d\n",
			total, parsed, stamped, len(lines))
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
	t.Logf("RESCAN PROBE total=%d parsed=%d stamped=%d moves=%d", total, parsed, stamped, len(lines))
}
