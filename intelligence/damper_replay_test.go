package intelligence

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/risk"
)

// TestEstablishedDamperReplay is the acceptance gate for the
// established-package damper (docs/PLANS_INTELLIGENCE.md#plan-established-damper).
// It scores every exported production report twice through the same code,
// damper off and on, and reports each verdict the damper moved.
//
// It FAILS on any flip of a known-malicious row or of a row where a
// takeover indicator or compound rule fired: those are the cases the damper
// must never soften.
//
// Export (read-only) one JSON object per line with keys eco, pkg, ver,
// verdict, mal and report, gzipped, then:
//
//	CHAINSAW_DAMPER_REPLAY=/path/replay.jsonl.gz go test ./intelligence/ -run TestEstablishedDamperReplay -v
func TestEstablishedDamperReplay(t *testing.T) {
	path := os.Getenv("CHAINSAW_DAMPER_REPLAY")
	if path == "" {
		t.Skip("CHAINSAW_DAMPER_REPLAY not set")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 0, 1<<20), 256<<20)

	now := time.Now()
	type row struct {
		Eco, Pkg, Ver, Verdict string
		Mal                    bool
		Report                 json.RawMessage
	}
	var (
		rows, unparsed, established, dampedRows int
		flips                                   = map[string]int{}
		flipSignals                             = map[string]int{}
		examples                                []string
		violations                              []string
	)
	for sc.Scan() {
		var r row
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			unparsed++
			continue
		}
		var rep Report
		if err := json.Unmarshal(r.Report, &rep); err != nil {
			unparsed++
			continue
		}
		rows++
		in := ProjectToRiskInput(&rep)
		if in.Ecosystem == "" {
			in.Ecosystem, in.Package, in.Version = r.Eco, r.Pkg, r.Ver
		}
		fixed := func() time.Time { return now }
		off := risk.EvaluatePackage(in, risk.Options{Now: fixed, NoEstablishedDamper: true})
		on := risk.EvaluatePackage(in, risk.Options{Now: fixed})
		if risk.EstablishedReason(in.Downloads, in.DownloadsWindow, in.WeeklyDownloads, in.VersionCount, in.FirstPublishedAt, now) != "" {
			established++
		}
		var damped []string
		takeover := false
		for _, cs := range on.DirectScore.Categories {
			for _, fs := range cs.FiredSignals {
				if fs.Evidence["damped"] == true {
					damped = append(damped, fs.ID)
				}
				if fs.Compound {
					takeover = true
				}
				if s, ok := risk.Registry[fs.ID]; ok && s.TakeoverIndicator {
					takeover = true
				}
			}
		}
		if len(damped) > 0 {
			dampedRows++
		}
		if off.Verdict == on.Verdict {
			continue
		}
		key := fmt.Sprintf("%s -> %s", off.Verdict, on.Verdict)
		flips[key]++
		sort.Strings(damped)
		flipSignals[strings.Join(damped, "+")]++
		line := fmt.Sprintf("%s %s@%s %s (%d -> %d) damped=%v", r.Eco, r.Pkg, r.Ver, key,
			off.DirectScore.Overall, on.DirectScore.Overall, damped)
		if len(examples) < 40 {
			examples = append(examples, line)
		}
		if r.Mal || takeover {
			violations = append(violations, line)
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("rows=%d unparsed=%d established=%d rows-with-damped-signal=%d", rows, unparsed, established, dampedRows)
	for k, n := range flips {
		t.Logf("FLIP %s: %d", k, n)
	}
	for k, n := range flipSignals {
		t.Logf("BY %s: %d", k, n)
	}
	for _, e := range examples {
		t.Logf("EX %s", e)
	}
	if rows == 0 {
		t.Fatal("replay read zero rows: did not run")
	}
	for _, v := range violations {
		t.Errorf("damper moved a malicious or takeover row: %s", v)
	}
}
