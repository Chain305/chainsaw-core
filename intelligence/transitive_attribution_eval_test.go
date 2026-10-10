package intelligence

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// TestTransitiveVerdictAttribution answers one question about a sample of
// stored production reports: how many are non-allow ONLY because of the
// sc.transitive_* signals?
//
// For each row it evaluates the stored Input twice with the real engine —
// once as stored, once with every Transitive*Count zeroed — and counts the
// rows whose verdict moves to allow when the transitive counts are removed.
// Nothing else changes between the two evaluations.
//
//	CHAINSAW_TRANSITIVE_ATTRIBUTION_IN=/tmp/r300.jsonl go test ./intelligence/ \
//	  -run TestTransitiveVerdictAttribution -v
//
// Each input line is {"eco","pkg","ver","persisted_verdict","report"}.
// Unset, the test skips; a skip is not a pass.
func TestTransitiveVerdictAttribution(t *testing.T) {
	in := os.Getenv("CHAINSAW_TRANSITIVE_ATTRIBUTION_IN")
	if in == "" {
		t.Skip("CHAINSAW_TRANSITIVE_ATTRIBUTION_IN unset (DID NOT RUN)")
	}
	f, err := os.Open(in)
	if err != nil {
		t.Fatalf("DID NOT RUN: %v", err)
	}
	defer f.Close()

	type row struct {
		Eco       string          `json:"eco"`
		Pkg       string          `json:"pkg"`
		Ver       string          `json:"ver"`
		Persisted string          `json:"persisted_verdict"`
		Report    json.RawMessage `json:"report"`
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 64<<20)

	n, bad, persistedMismatch, pathDrift := 0, 0, 0, 0
	stored := map[string]int{}
	solelyTransitive := map[string]int{}
	var solelyRows []string
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r row
		var rep Report
		if json.Unmarshal([]byte(line), &r) != nil || json.Unmarshal(r.Report, &rep) != nil {
			bad++
			continue
		}
		n++
		with := ProjectToRiskInput(&rep)
		without := with
		without.TransitiveCriticalCount = 0
		without.TransitiveHighCount = 0
		without.TransitiveMediumCount = 0
		without.TransitiveLowCount = 0
		without.TransitiveMalwareCount = 0
		without.TransitiveBlockedCount = 0

		evWith := risk.EvaluatePackage(with, risk.Options{})
		evWithout := risk.EvaluatePackage(without, risk.Options{})
		if evWith == nil || evWithout == nil {
			bad++
			continue
		}
		vw, vwo := string(evWith.Verdict), string(evWithout.Verdict)
		stored[vw]++
		if r.Persisted != "" && r.Persisted != vw {
			persistedMismatch++
			// STALE when an older matcher or engine wrote the row; otherwise
			// the same facts project to a different verdict today. On the
			// 2026-10-09 sample all 11 are drift: persisted upgrade_available,
			// recomputed quarantine — the pre-2026-10-10 scan path gated
			// promotion on a DirectScore without sc.transitive_*. Fixed in
			// promoteToUpgradeAvailable; PATH DRIFT below must stay 0, and
			// these 11 clear when the rows are next scanned.
			kind := "PROJECTION DRIFT"
			if rep.Observation.MatcherEpoch != CurrentMatcherEpoch ||
				rep.Risk == nil || rep.Risk.EngineVersion != risk.EngineVersion {
				kind = "STALE"
			}
			t.Logf("MISMATCH %s %s@%s persisted=%s recomputed=%s epoch=%d collectedAt=%s",
				kind, r.Pkg, r.Ver, r.Persisted, vw, rep.Observation.MatcherEpoch,
				rep.Observation.CollectedAt.Format("2006-01-02T15:04Z"))
		}
		// The two production paths, on the same stored facts. The tree walk
		// cannot be redone here, so the scan path replays the overlay from
		// the stored tree outputs (severity counts, rolled-up score).
		if rep.Risk != nil {
			if sv, rv := scanReplayVerdict(rep, line), readReplayVerdict(line); sv != rv {
				pathDrift++
				t.Logf("PATH DRIFT %s@%s scan=%s read=%s persisted=%s", r.Pkg, r.Ver, sv, rv, r.Persisted)
			}
		}
		if vw != string(risk.VerdictAllow) && vwo == string(risk.VerdictAllow) {
			solelyTransitive[vw]++
			solelyRows = append(solelyRows, r.Pkg+"@"+r.Ver+" ("+vw+")")
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("DID NOT RUN: read: %v", err)
	}
	if n == 0 {
		t.Fatalf("DID NOT RUN: 0 rows parsed (%d unparseable)", bad)
	}

	keys := func(m map[string]int) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	t.Logf("rows=%d unparseable=%d recomputed-verdict-differs-from-persisted=%d", n, bad, persistedMismatch)
	t.Logf("scan-path-vs-read-path verdict disagreements=%d", pathDrift)
	for _, k := range keys(stored) {
		t.Logf("VERDICT %-18s %d", k, stored[k])
	}
	total := 0
	for _, k := range keys(solelyTransitive) {
		t.Logf("NON-ALLOW ONLY BECAUSE OF sc.transitive_*  %-18s %d", k, solelyTransitive[k])
		total += solelyTransitive[k]
	}
	t.Logf("SOLELY-TRANSITIVE TOTAL %d of %d (%.1f%%)", total, n, 100*float64(total)/float64(n))
	sort.Strings(solelyRows)
	for i, s := range solelyRows {
		if i == 20 {
			t.Logf("  ... and %d more", len(solelyRows)-20)
			break
		}
		t.Logf("  %s", s)
	}
}

// scanReplayVerdict replays Scan's sequence on a stored row: score with no
// transitive counts, overlay the stored tree outputs the way
// evaluateTransitiveRisk does, then ReapplyKnownFixAfterTransitive.
func scanReplayVerdict(stored Report, line string) risk.Verdict {
	var rep Report
	_ = json.Unmarshal([]byte(line), &struct {
		Report *Report `json:"report"`
	}{&rep})
	ts, rolled := stored.Risk.Resolution.TransitiveSeverity, stored.Risk.RolledUp
	rep.Risk = nil
	ComputeTrustScoreForOrg(&rep, "")
	in := ProjectToRiskInput(&rep)
	in.TransitiveCriticalCount, in.TransitiveHighCount = ts.CriticalCount, ts.HighCount
	in.TransitiveMediumCount, in.TransitiveLowCount = ts.MediumCount, ts.LowCount
	in.TransitiveMalwareCount, in.TransitiveBlockedCount = ts.MalwareCount, ts.BlockedCount
	if hasTransitiveSignal(ts) {
		if second := risk.EvaluatePackage(in, risk.Options{}); verdictRank(second.Verdict) >= verdictRank(rep.Risk.Verdict) {
			rep.Risk.Verdict, rep.Risk.Resolution = second.Verdict, second.Resolution
		}
	}
	rep.Risk.RolledUp = rolled
	rep.Risk.Resolution.TransitiveSeverity = ts
	ReapplyKnownFixAfterTransitive(&rep, "")
	return rep.Risk.Verdict
}

// readReplayVerdict replays personalize's re-score of the persisted row.
func readReplayVerdict(line string) risk.Verdict {
	var rep Report
	_ = json.Unmarshal([]byte(line), &struct {
		Report *Report `json:"report"`
	}{&rep})
	ts := rep.Risk.Resolution.TransitiveSeverity
	ComputeTrustScoreForOrg(&rep, "")
	rep.Risk.Resolution.TransitiveSeverity = ts
	ReapplyKnownFixAfterTransitive(&rep, "")
	return rep.Risk.Verdict
}
