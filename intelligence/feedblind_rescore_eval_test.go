package intelligence

// feedblind_rescore_eval_test.go — re-scores stored corpus reports through
// the CURRENT risk engine with the malware feed removed, one JSON line per
// row. It is the iteration loop for scoring changes: scan once with the
// enterprise harness (TestBuildEnterpriseCorpus, which sees the premium
// codesmell providers that feed the install-path compounds), then re-score
// the stored reports here after every engine edit.
//
// Feed-blind means: MalwareStatus cleared and every MAL-* advisory dropped,
// because OSV re-publishes ossf/malicious-packages and would otherwise carry
// the feed in by a second lane (docs/REPORTS.md#feedless-ablation).
//
// CHAINSAW_RESCORE_BYTES_ONLY=1 is for reports from the harness's bytes-only
// mode, which never fetches registry metadata. The licence is then marked
// unavailable rather than absent; otherwise lic.missing fires on every row of
// both corpora and the comparison measures the instrument.
//
//	CHAINSAW_RESCORE_IN=a.jsonl,b.jsonl CHAINSAW_RESCORE_OUT=out.jsonl \
//	  go test ./core/intelligence/ -run TestFeedBlindRescore -count=1
//
// CHAINSAW_RESCORE_NO_EXEMPTION=1 is the counterfactual for the popular
// exemption on warn-ceiling compounds: every rule's DampEstablished is cleared
// for the run. "damped" lists the fired IDs the damper softened.

import (
	"bufio"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

func TestFeedBlindRescore(t *testing.T) {
	in, outPath := os.Getenv("CHAINSAW_RESCORE_IN"), os.Getenv("CHAINSAW_RESCORE_OUT")
	if in == "" || outPath == "" {
		t.Skip("set CHAINSAW_RESCORE_IN and CHAINSAW_RESCORE_OUT")
	}
	out, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	w := bufio.NewWriter(out)
	defer w.Flush()
	bytesOnly := os.Getenv("CHAINSAW_RESCORE_BYTES_ONLY") != ""
	if os.Getenv("CHAINSAW_RESCORE_NO_EXEMPTION") != "" {
		saved := append([]risk.CompoundRule(nil), risk.CompoundRules...)
		defer func() { risk.CompoundRules = saved }()
		for i := range risk.CompoundRules {
			risk.CompoundRules[i].DampEstablished = false
		}
	}
	n := 0
	for _, path := range strings.Split(in, ",") {
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		for sc.Scan() {
			var row struct {
				Eco, Pkg, Ver string
				Report        Report `json:"report"`
			}
			if json.Unmarshal(sc.Bytes(), &row) != nil {
				continue
			}
			r := &row.Report
			r.SupplyChain.MalwareStatus, r.SupplyChain.MalwareID, r.SupplyChain.MalwareSummary = "", "", ""
			kept := r.Vulnerabilities.CVEs[:0]
			for _, id := range r.Vulnerabilities.CVEs {
				if !strings.HasPrefix(id, "MAL-") {
					kept = append(kept, id)
				}
			}
			r.Vulnerabilities.CVEs = kept
			if len(kept) == 0 {
				r.Vulnerabilities.IsVulnerable = false
			}
			if bytesOnly {
				r.Observation.Warnings = append(r.Observation.Warnings,
					Warning{Provider: "registrymetadata", Code: WarnLicenseUnavailable})
			}
			ev := risk.EvaluatePackage(ProjectToRiskInput(r), risk.Options{})
			var fired, damped []string
			for _, cs := range ev.DirectScore.Categories {
				for _, f := range cs.FiredSignals {
					fired = append(fired, f.ID)
					if f.Evidence["damped"] == true {
						damped = append(damped, f.ID)
					}
				}
			}
			sort.Strings(fired)
			sort.Strings(damped)
			line, _ := json.Marshal(map[string]any{
				"eco": row.Eco, "pkg": row.Pkg, "ver": row.Ver,
				"verdict": ev.Verdict, "overall": ev.DirectScore.Overall,
				"sc":      ev.DirectScore.Categories[risk.CategorySupplyChain].Score,
				"ceiling": ev.DirectScore.CeilingSignal, "fired": fired, "damped": damped,
			})
			w.Write(append(line, '\n'))
			n++
		}
		f.Close()
	}
	t.Logf("re-scored %d rows -> %s", n, outPath)
}
