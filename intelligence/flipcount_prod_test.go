package intelligence

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// TestProductionFlipCount measures how many real production coordinates the
// upgrade promotion would move, by evaluating each persisted report BOTH ways
// with the CURRENT code: once without the promotion (today's behaviour) and
// once with it. Comparing two runs of the same binary isolates the promotion
// and excludes any unrelated drift between the persisted verdict and HEAD.
//
// Opt-in: set CHAINSAW_FLIP_CORPUS=/path/to/vuln_reports.jsonl (one JSON
// object per line: {eco,pkg,ver,persisted_verdict,report}). Skipped otherwise
// so it never gates CI on a snapshot that is not in the repo.
func TestProductionFlipCount(t *testing.T) {
	path := os.Getenv("CHAINSAW_FLIP_CORPUS")
	if path == "" {
		t.Skip("set CHAINSAW_FLIP_CORPUS=<jsonl> to measure against a snapshot")
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

	flips := map[string]int{}
	var promoted []string
	total, parsed := 0, 0

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
			if total <= 2 {
				t.Logf("row unmarshal err: %v", err)
			}
			continue
		}
		var rep Report
		if err := json.Unmarshal(r.Report, &rep); err != nil {
			if total <= 2 {
				t.Logf("report unmarshal err: %v (raw %d bytes)", err, len(r.Report))
			}
			continue
		}
		parsed++

		input := ProjectToRiskInput(&rep)

		// Today: bare evaluation, display fields only, verdict untouched.
		before := risk.EvaluatePackage(input, risk.Options{})
		if before == nil {
			continue
		}
		// With the promotion gates applied.
		safe := MinimumSafeVersion(&rep)
		after := before
		if p := promoteToUpgradeAvailable(&rep, before, safe, nil, nil); p != nil {
			after = p
		}

		if before.Verdict != after.Verdict {
			flips[string(before.Verdict)+" -> "+string(after.Verdict)]++
			promoted = append(promoted, string(before.Verdict)+"  "+r.Eco+"/"+r.Pkg+"@"+r.Ver+"  safe="+safe)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scan corpus: %v", err)
	}

	t.Logf("corpus lines=%d parsed=%d", total, parsed)
	keys := make([]string, 0, len(flips))
	for k := range flips {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	n := 0
	for _, k := range keys {
		t.Logf("FLIP %-34s %d", k, flips[k])
		n += flips[k]
	}
	t.Logf("TOTAL FLIPS: %d of %d parsed (%.1f%%)", n, parsed, 100*float64(n)/float64(max(parsed, 1)))
	sort.Strings(promoted)
	for _, p := range promoted {
		t.Logf("  %s", p)
	}
}
