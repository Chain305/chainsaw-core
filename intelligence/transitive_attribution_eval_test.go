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

	n, bad, persistedMismatch := 0, 0, 0
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
