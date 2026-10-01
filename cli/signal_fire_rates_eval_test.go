package cli

// TestSignalFireRates — every fired signal, INCLUDING weight-0 and unknown.
//
// WHY. The other harnesses grade verdicts, so a signal that cannot move a
// verdict is invisible to them however wrong it is. On 2026-09-30 lodash's
// public page carried cap.shell on RegExp `.exec(`, cap.filesystem_write on a
// JSDoc comment, and "Download count unavailable" on a package with 195M
// weekly downloads. All three were weight 0 or unknown severity; the corpus
// had them firing on 123, 29 and 673 rows respectively, and no report ever
// printed those numbers as something to check.
//
// This prints the rate per signal split by corpus label, and writes a
// fixed-seed SAMPLE of hits with their evidence so a person can label each one
// real or false. The sample is the deliverable: a fire rate says how often a
// signal speaks, not whether it is right.
//
//	CHAINSAW_LABELLED_CORPUS=<reports.jsonl> \
//	CHAINSAW_LABELLED_SEED=<corpus.tsv> \
//	CHAINSAW_SIGNAL_RATES_OUT=<dir> \
//	CHAINSAW_SIGNAL_RATES_DEFAULT_LABEL=popular \  # label for rows not in the seed
//	  go test ./core/cli/ -run TestSignalFireRates -v -count=1

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

type firedForRates struct {
	ID       string         `json:"id"`
	Severity string         `json:"severity"`
	Weight   float64        `json:"weight"`
	Evidence map[string]any `json:"evidence"`
}

// signalSamplesPerSignal bounds the precision sample. Ten per signal is what a
// person can label in one sitting across the registry.
const signalSamplesPerSignal = 10

func TestSignalFireRates(t *testing.T) {
	corpusPath := os.Getenv("CHAINSAW_LABELLED_CORPUS")
	if corpusPath == "" {
		t.Skip("set CHAINSAW_LABELLED_CORPUS (and optionally CHAINSAW_LABELLED_SEED, CHAINSAW_SIGNAL_RATES_OUT)")
	}
	rows, err := readServerRiskCorpus(corpusPath)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	labels := map[string]labelledRow{}
	if p := os.Getenv("CHAINSAW_LABELLED_SEED"); p != "" {
		if labels, err = readLabelledSeed(p); err != nil {
			t.Fatalf("read seed: %v", err)
		}
	}

	type hit struct {
		coord, label, where string
	}
	type stat struct {
		weight   float64
		severity string
		byLabel  map[string]int
		unknown  int
		hits     []hit
	}
	stats := map[string]*stat{}
	labelTotals := map[string]int{}
	defaultLabel := os.Getenv("CHAINSAW_SIGNAL_RATES_DEFAULT_LABEL")
	if defaultLabel == "" {
		defaultLabel = "unlabelled"
	}
	verdicts := map[string]map[string]int{}
	var flagged []string

	for _, r := range rows {
		label := defaultLabel
		if l, ok := labels[labelKey(r.Eco, r.Pkg, r.Ver)]; ok && l.Label != "" {
			label = l.Label
		}
		labelTotals[label]++
		var rep struct {
			Risk struct {
				Verdict  string `json:"verdict"`
				RolledUp struct {
					Overall       int    `json:"overall"`
					CeilingSignal string `json:"ceilingSignal"`
					Categories    map[string]struct {
						FiredSignals []firedForRates `json:"firedSignals"`
					} `json:"categories"`
				} `json:"rolledUp"`
			} `json:"risk"`
		}
		if json.Unmarshal(r.Report, &rep) != nil {
			continue
		}
		coord := r.Eco + "/" + r.Pkg + "@" + r.Ver
		if verdicts[label] == nil {
			verdicts[label] = map[string]int{}
		}
		verdicts[label][rep.Risk.Verdict]++
		if rep.Risk.Verdict != "allow" && rep.Risk.Verdict != "" {
			flagged = append(flagged, fmt.Sprintf("%-10s %-50s %-11s %3d  ceiling=%s",
				label, coord, rep.Risk.Verdict, rep.Risk.RolledUp.Overall, rep.Risk.RolledUp.CeilingSignal))
		}
		for _, cat := range rep.Risk.RolledUp.Categories {
			for _, s := range cat.FiredSignals {
				st := stats[s.ID]
				if st == nil {
					st = &stat{weight: s.Weight, severity: s.Severity, byLabel: map[string]int{}}
					stats[s.ID] = st
				}
				st.byLabel[label]++
				if s.Severity == "unknown" {
					st.unknown++
				}
				st.hits = append(st.hits, hit{coord: coord, label: label, where: firstEvidence(s.Evidence)})
			}
		}
	}

	var ids []string
	for id := range stats {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var labelNames []string
	for l := range labelTotals {
		labelNames = append(labelNames, l)
	}
	sort.Strings(labelNames)

	t.Logf("SIGNAL FIRE RATES over %d rows — weight-0 and unknown included", len(rows))
	header := fmt.Sprintf("  %-38s %7s %-8s %7s", "signal", "weight", "severity", "unknown")
	for _, l := range labelNames {
		header += fmt.Sprintf(" %14s", fmt.Sprintf("%s/%d", l, labelTotals[l]))
	}
	t.Log(header)
	for _, id := range ids {
		st := stats[id]
		line := fmt.Sprintf("  %-38s %7.1f %-8s %7d", id, st.weight, st.severity, st.unknown)
		for _, l := range labelNames {
			line += fmt.Sprintf(" %14d", st.byLabel[l])
		}
		t.Log(line)
	}

	t.Log("")
	t.Log("VERDICTS by label")
	for _, l := range labelNames {
		t.Logf("  %-12s %v", l, verdicts[l])
	}
	// The full non-allow list is printed only for small runs (the popular
	// stratum): there, every flagged row is a candidate false positive a person
	// should read, and there are few enough to read.
	if len(rows) <= 600 {
		sort.Strings(flagged)
		t.Logf("NON-ALLOW rows (%d) — read each:", len(flagged))
		for _, f := range flagged {
			t.Log("  " + f)
		}
	}

	out := os.Getenv("CHAINSAW_SIGNAL_RATES_OUT")
	if out == "" {
		t.Log("set CHAINSAW_SIGNAL_RATES_OUT to write the precision sample")
		return
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	b.WriteString("signal\tweight\tlabel\tcoordinate\tevidence\tverdict_real_or_false\n")
	for _, id := range ids {
		st := stats[id]
		// Fixed-seed selection: order hits by a hash of (signal, coordinate) so
		// the same corpus yields the same sample on every run, and a relabel
		// session can be resumed.
		sort.Slice(st.hits, func(i, j int) bool {
			return sampleKey(id, st.hits[i].coord) < sampleKey(id, st.hits[j].coord)
		})
		for i, h := range st.hits {
			if i == signalSamplesPerSignal {
				break
			}
			fmt.Fprintf(&b, "%s\t%.1f\t%s\t%s\t%s\t\n", id, st.weight, h.label, h.coord, h.where)
		}
	}
	path := filepath.Join(out, "signal-precision-sample.tsv")
	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %s — the last column is blank ON PURPOSE: a person labels each row", path)
}

func sampleKey(id, coord string) string {
	sum := sha256.Sum256([]byte(id + "\x00" + coord))
	return fmt.Sprintf("%x", sum[:8])
}

// firstEvidence renders the first evidence location, or the evidence map, as
// one tab-free line.
func firstEvidence(ev map[string]any) string {
	if locs, ok := ev["locations"].([]any); ok && len(locs) > 0 {
		if l, ok := locs[0].(map[string]any); ok {
			s := fmt.Sprintf("%v:%v %v", l["file"], l["line"], l["snippet"])
			return strings.NewReplacer("\t", " ", "\n", " ").Replace(s)
		}
	}
	if len(ev) == 0 {
		return ""
	}
	b, _ := json.Marshal(ev)
	s := strings.NewReplacer("\t", " ", "\n", " ").Replace(string(b))
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
