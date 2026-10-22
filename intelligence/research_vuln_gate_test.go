package intelligence

// Research vulnerability-gate runner: would CHAINSAW's own vulnerability data
// refuse the dependency versions the impact report counts as refusable?
//
// The impact report's severity-gate numbers were computed from the
// organisation's scanner labels (Trivy) plus osv.dev publish dates. This
// runner asks the product instead: it drives the real OSV provider
// (newOSVProvider + Run, the code the intelligence scan runs) over every fix
// action in analysis/cost_model_actions.csv and applies the proxy block rule
// an operator would write — conditions {isVulnerable: true, cvssMin: 7} — with
// the evaluator's own semantics (core/policy/evaluator.go: isVulnerable must
// equal ctx.IsVulnerable; the package is dropped when ctx.CVSSScore <
// cvssMin). Report.Vulnerabilities is projected onto the policy context
// unchanged by hydrateIntelPolicyContext (internal/server/artifact_scan.go).
//
// Two answers per fix action:
//   - today:    provider.Run as shipped (every advisory in the bundle)
//   - at intro: the same matched advisories restricted to those published on
//     or before the version's introduction date — the no-hindsight
//     counterfactual the report needs.
//
// Skipped unless both RESEARCH_DIR and CHAINSAW_OSV_BUNDLE_PATH are set
// (build the bundle with core/tools/osv-bundle-gen, which runs the same
// refresher prod runs):
//
//	CHAINSAW_OSV_BUNDLE_PATH=/path/osv-bundle.json.gz \
//	RESEARCH_DIR="$HOME/research-dataset" \
//	  go test ./core/intelligence/ -run TestResearchVulnGateOverDataset -count=1 -v
//
// Output: analysis/chainsaw_vuln_gate.csv (one row per fix action) and a
// summary in the test log.

import (
	"context"
	"encoding/csv"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// dataset ecosystem -> the ecosystem string the provider is keyed by.
var researchVulnEco = map[string]string{
	"npm": "npm", "pypi": "pypi", "maven": "maven", "golang": "go",
	"composer": "composer", "gem": "rubygems", "cargo": "cargo", "pub": "pub",
}

// researchCVSSMinDefault matches the portal recipe "Block packages with
// critical CVEs" at sensitivity "conservative" (policy-wizard/recipes.ts:
// conservative 7.0, balanced 8.0, aggressive 9.0). Override with
// CHAINSAW_RESEARCH_CVSS_MIN; a non-default floor writes its own output file.
const researchCVSSMinDefault = 7.0

func TestResearchVulnGateOverDataset(t *testing.T) {
	root := os.Getenv("RESEARCH_DIR")
	if root == "" || os.Getenv(OSVBundleEnvVar) == "" {
		t.Skip("RESEARCH_DIR and " + OSVBundleEnvVar + " must both be set")
	}
	p := newOSVProvider(nil, nil)
	if p.idx == nil {
		t.Fatalf("OSV bundle did not load from %s — a dormant provider would read as 'no vulnerabilities'", os.Getenv(OSVBundleEnvVar))
	}
	t.Logf("bundle: %d advisories, loaded %s", p.idx.Total(), p.idx.LoadedAt().Format("2006-01-02T15:04Z"))
	researchCVSSMin, outName := researchCVSSMinDefault, "chainsaw_vuln_gate.csv"
	if v := strings.TrimSpace(os.Getenv("CHAINSAW_RESEARCH_CVSS_MIN")); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f <= 0 || f > 10 {
			t.Fatalf("CHAINSAW_RESEARCH_CVSS_MIN=%q: want a CVSS floor in (0, 10]", v)
		}
		researchCVSSMin = f
		if f != researchCVSSMinDefault {
			outName = "chainsaw_vuln_gate_cvss" + strconv.FormatFloat(f, 'f', -1, 64) + ".csv"
		}
	}
	t.Logf("block rule: {isVulnerable: true, cvssMin: %.1f} -> analysis/%s", researchCVSSMin, outName)

	in, err := os.Open(filepath.Join(root, "analysis", "cost_model_actions.csv"))
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	r := csv.NewReader(in)
	header, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	for _, need := range []string{"repo", "package", "version", "eco", "intro", "backlog", "refusable", "gate_findings"} {
		if _, ok := col[need]; !ok {
			t.Fatalf("cost_model_actions.csv lacks column %q", need)
		}
	}

	outF, err := os.Create(filepath.Join(root, "analysis", outName))
	if err != nil {
		t.Fatal(err)
	}
	defer outF.Close()
	w := csv.NewWriter(outF)
	defer w.Flush()
	_ = w.Write([]string{"repo", "package", "version", "eco", "intro", "refusable_by_report",
		"ecosystem_covered", "today_vulnerable", "today_max_cvss", "today_blocks",
		"intro_hits", "intro_max_cvss", "intro_blocks", "intro_hits_without_cvss", "intro_label_high"})

	type tally struct{ rows, covered, todayVuln, todayBlock, introVuln, introBlock, introNoCVSSOnly, introLabelHighOnly int }
	var ref, all tally
	ctx := context.Background()
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if row[col["gate_findings"]] == "0" {
			continue
		}
		eco, ok := researchVulnEco[row[col["eco"]]]
		refusable := row[col["refusable"]] == "True"
		pkg, ver, intro := row[col["package"]], row[col["version"]], row[col["intro"]]
		tl := []*tally{&all}
		if refusable {
			tl = append(tl, &ref)
		}
		for _, x := range tl {
			x.rows++
		}
		if !ok || !p.idx.HasEcosystem(eco) {
			_ = w.Write([]string{row[col["repo"]], pkg, ver, row[col["eco"]], intro, strconv.FormatBool(refusable),
				"false", "", "", "false", "", "", "false", "", ""})
			continue
		}
		// today: the shipped provider path, unchanged.
		part, err := p.Run(ctx, Request{Key: Key{Ecosystem: eco, Package: pkg, Version: ver}}, nil)
		if err != nil {
			t.Fatalf("Run %s %s@%s: %v", eco, pkg, ver, err)
		}
		var todayVuln bool
		var todayCVSS float64
		if part.Vulns != nil {
			todayVuln, todayCVSS = part.Vulns.IsVulnerable, part.Vulns.CVSSScore
		}
		todayBlock := todayVuln && todayCVSS >= researchCVSSMin
		// at intro: the same matcher, advisories published on/before intro.
		hits, _, _ := p.idx.LookupEx(eco, pkg, ver)
		introHits, noCVSS, labelHigh := 0, 0, 0
		var introCVSS float64
		for _, a := range hits {
			if a.Published == "" || a.Published[:min(10, len(a.Published))] > intro {
				continue
			}
			introHits++
			if a.CVSSScore > introCVSS {
				introCVSS = a.CVSSScore
			}
			if a.CVSSScore == 0 {
				noCVSS++
				if s := strings.ToUpper(a.Severity); s == "HIGH" || s == "CRITICAL" {
					labelHigh++
				}
			}
		}
		introBlock := introHits > 0 && introCVSS >= researchCVSSMin
		for _, x := range tl {
			x.covered++
			if todayVuln {
				x.todayVuln++
			}
			if todayBlock {
				x.todayBlock++
			}
			if introHits > 0 {
				x.introVuln++
			}
			if introBlock {
				x.introBlock++
			}
			if introHits > 0 && !introBlock && noCVSS > 0 {
				x.introNoCVSSOnly++
				if labelHigh > 0 {
					x.introLabelHighOnly++
				}
			}
		}
		_ = w.Write([]string{row[col["repo"]], pkg, ver, row[col["eco"]], intro, strconv.FormatBool(refusable),
			"true", strconv.FormatBool(todayVuln), strconv.FormatFloat(todayCVSS, 'f', 1, 64), strconv.FormatBool(todayBlock),
			strconv.Itoa(introHits), strconv.FormatFloat(introCVSS, 'f', 1, 64), strconv.FormatBool(introBlock),
			strconv.Itoa(noCVSS), strconv.Itoa(labelHigh)})
	}
	for name, x := range map[string]tally{"refusable-by-report": ref, "all-gate-fix-actions": all} {
		t.Logf("%s: rows %d, ecosystem covered %d, today vulnerable %d, today block(cvss>=%.0f) %d, at-intro vulnerable %d, at-intro block %d, at-intro matched but no CVSS>=7 because CVSS missing %d (of which labelled HIGH/CRITICAL %d)",
			name, x.rows, x.covered, x.todayVuln, researchCVSSMin, x.todayBlock, x.introVuln, x.introBlock, x.introNoCVSSOnly, x.introLabelHighOnly)
	}
}

// TestResearchVulnGateOverCoords is the benchmark-v2 lane B runner: the same
// provider path and block rule, over a plain coordinate list (columns eco,
// package, version; eco is the provider key: npm, pypi, maven, go, composer,
// rubygems). Ground truth lives in the input file and is never read here.
//
//	CHAINSAW_OSV_BUNDLE_PATH=/path/osv-bundle.json.gz \
//	RESEARCH_COORDS=/path/coords.csv RESEARCH_COORDS_OUT=/path/chainsaw.csv \
//	  go test ./intelligence/ -run TestResearchVulnGateOverCoords -count=1 -v
func TestResearchVulnGateOverCoords(t *testing.T) {
	inPath, outPath := os.Getenv("RESEARCH_COORDS"), os.Getenv("RESEARCH_COORDS_OUT")
	if inPath == "" || outPath == "" || os.Getenv(OSVBundleEnvVar) == "" {
		t.Skip("RESEARCH_COORDS, RESEARCH_COORDS_OUT and " + OSVBundleEnvVar + " must all be set")
	}
	p := newOSVProvider(nil, nil)
	if p.idx == nil {
		t.Fatalf("OSV bundle did not load from %s", os.Getenv(OSVBundleEnvVar))
	}
	in, err := os.Open(inPath)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	r := csv.NewReader(in)
	header, err := r.Read()
	if err != nil {
		t.Fatal(err)
	}
	col := map[string]int{}
	for i, h := range header {
		col[h] = i
	}
	for _, need := range []string{"eco", "package", "version"} {
		if _, ok := col[need]; !ok {
			t.Fatalf("%s lacks column %q", inPath, need)
		}
	}
	outF, err := os.Create(outPath)
	if err != nil {
		t.Fatal(err)
	}
	defer outF.Close()
	w := csv.NewWriter(outF)
	defer w.Flush()
	_ = w.Write([]string{"eco", "package", "version", "covered", "vulnerable", "max_cvss", "blocks", "advisories"})
	var rows, blocks int
	for {
		row, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		eco, pkg, ver := row[col["eco"]], row[col["package"]], row[col["version"]]
		rows++
		if !p.idx.HasEcosystem(eco) {
			_ = w.Write([]string{eco, pkg, ver, "false", "", "", "false", ""})
			continue
		}
		part, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: eco, Package: pkg, Version: ver}}, nil)
		if err != nil {
			t.Fatalf("Run %s %s@%s: %v", eco, pkg, ver, err)
		}
		var vuln bool
		var cvss float64
		if part.Vulns != nil {
			vuln, cvss = part.Vulns.IsVulnerable, part.Vulns.CVSSScore
		}
		hits, _, _ := p.idx.LookupEx(eco, pkg, ver)
		ids := make([]string, 0, len(hits))
		for _, a := range hits {
			ids = append(ids, a.AdvisoryID)
		}
		block := vuln && cvss >= researchCVSSMinDefault
		if block {
			blocks++
		}
		_ = w.Write([]string{eco, pkg, ver, "true", strconv.FormatBool(vuln), strconv.FormatFloat(cvss, 'f', 1, 64),
			strconv.FormatBool(block), strings.Join(ids, ";")})
	}
	t.Logf("coords %d, block(cvss>=%.0f) %d -> %s", rows, researchCVSSMinDefault, blocks, outPath)
}
