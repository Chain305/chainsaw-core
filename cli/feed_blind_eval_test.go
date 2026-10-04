package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/risk"
)

// TestFeedBlindVerdicts re-evaluates a corpus with the malware feed removed,
// for the parity scorer (scripts/parity-score.sh).
//
// Two routes carry OSSF's verdict into a report: the malware index
// (SupplyChain.Malware*) and OSV, which ships the same MAL-* records as
// advisories that fire vuln.known_vulnerable. Clearing only the first leaves
// recall at 100% and measures nothing (docs/REPORTS.md#feedless-ablation).
//
// It does NOT undo the scan-time short-circuit: a malware hit cancels
// registrymetadata, so a feed-hit row re-evaluated here reads `unknown`. Rows
// that matter must be RE-SCANNED with no malware index first; the scorer does
// that for malicious rows that still have bytes.
//
//	CHAINSAW_LABELLED_CORPUS=<reports.jsonl> CHAINSAW_FEED_BLIND_OUT=<out.tsv>
//
// Output columns: eco, pkg, ver, verdict as scanned, feed-blind verdict, the
// non-zero-weight signals that fired feed-blind (id:weight).
func TestFeedBlindVerdicts(t *testing.T) {
	in, out := os.Getenv("CHAINSAW_LABELLED_CORPUS"), os.Getenv("CHAINSAW_FEED_BLIND_OUT")
	if in == "" || out == "" {
		t.Skip("set CHAINSAW_LABELLED_CORPUS and CHAINSAW_FEED_BLIND_OUT")
	}
	rows, err := readServerRiskCorpus(in)
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create %s: %v", out, err)
	}
	w := bufio.NewWriter(f)
	n := 0
	for _, r := range rows {
		var rep intelligence.Report
		if err := json.Unmarshal(r.Report, &rep); err != nil {
			t.Fatalf("%s %s@%s: %v", r.Eco, r.Pkg, r.Ver, err)
		}
		asIs, _ := feedBlindEval(&rep)
		stripMalwareFeed(&rep)
		blind, sigs := feedBlindEval(&rep)
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", r.Eco, r.Pkg, r.Ver, asIs, blind, sigs)
		n++
	}
	if err := w.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	f.Close()
	if n == 0 {
		t.Fatalf("0 rows read from %s", in)
	}
	t.Logf("wrote %d feed-blind verdicts -> %s", n, out)
}

// stripMalwareFeed removes both routes the OSSF feed reaches a report by.
func stripMalwareFeed(rep *intelligence.Report) {
	rep.SupplyChain.MalwareStatus = "clean"
	rep.SupplyChain.MalwareID = ""
	rep.SupplyChain.MalwareSummary = ""
	var cves []string
	for _, c := range rep.Vulnerabilities.CVEs {
		if !strings.HasPrefix(c, "MAL-") {
			cves = append(cves, c)
		}
	}
	var det []intelligence.CVEDetail
	for _, d := range rep.Vulnerabilities.CVEDetails {
		if !strings.HasPrefix(d.CVE, "MAL-") {
			det = append(det, d)
		}
	}
	rep.Vulnerabilities.CVEs, rep.Vulnerabilities.CVEDetails = cves, det
	rep.Vulnerabilities.IsVulnerable = len(cves) > 0
}

func feedBlindEval(rep *intelligence.Report) (verdict, signals string) {
	ev := risk.EvaluatePackage(intelligence.ProjectToRiskInput(rep), risk.Options{})
	if ev == nil {
		return "nil", ""
	}
	var ids []string
	for _, c := range ev.DirectScore.Categories {
		for _, s := range c.FiredSignals {
			if s.Weight != 0 {
				ids = append(ids, fmt.Sprintf("%s:%g", s.ID, s.Weight))
			}
		}
	}
	sort.Strings(ids)
	return string(ev.Verdict), strings.Join(ids, ",")
}

// A report whose only malicious evidence is a MAL-* advisory must not stay
// adverse once the feed is stripped; a real CVE beside it must survive.
func TestStripMalwareFeedRemovesBothRoutes(t *testing.T) {
	rep := intelligence.Report{}
	rep.SupplyChain.MalwareStatus = "malicious"
	rep.Vulnerabilities = intelligence.VulnSection{IsVulnerable: true,
		CVEs:       []string{"MAL-2026-1", "GHSA-xxxx"},
		CVEDetails: []intelligence.CVEDetail{{CVE: "MAL-2026-1"}, {CVE: "GHSA-xxxx"}}}
	stripMalwareFeed(&rep)
	if rep.SupplyChain.MalwareStatus == "malicious" {
		t.Fatal("malware index route survived")
	}
	if got := rep.Vulnerabilities.CVEs; len(got) != 1 || got[0] != "GHSA-xxxx" || !rep.Vulnerabilities.IsVulnerable {
		t.Fatalf("CVEs after strip = %v (vulnerable=%v); want only GHSA-xxxx, still vulnerable", got, rep.Vulnerabilities.IsVulnerable)
	}
	for _, d := range rep.Vulnerabilities.CVEDetails {
		if strings.HasPrefix(d.CVE, "MAL-") {
			t.Fatal("MAL-* survived in CVEDetails: vuln.known_vulnerable still carries the feed")
		}
	}
}
