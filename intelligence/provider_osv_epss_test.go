package intelligence

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/chain305/chainsaw-core/intelligence/osv"
	"github.com/chain305/chainsaw-core/risk"
)

// stubEPSS is the narrow epssReader the provider takes.
type stubEPSS struct {
	scores map[string]float64
	err    error
	calls  [][]string
}

func (s *stubEPSS) MaxEPSSForCVEs(cves []string) (float64, error) {
	s.calls = append(s.calls, append([]string(nil), cves...))
	if s.err != nil {
		return 0, s.err
	}
	var max float64
	for _, c := range cves {
		if v := s.scores[c]; v > max {
			max = v
		}
	}
	return max, nil
}

func epssFixture(t *testing.T) func() {
	t.Helper()
	return withStubbedBundle(t, []osv.Advisory{
		{
			Ecosystem:          "npm",
			Package:            "vulnerable-pkg",
			VulnerableVersions: []string{"1.0.0"},
			AdvisoryID:         "GHSA-epss-low",
			Aliases:            []string{"CVE-2026-00001"},
			CVSSScore:          4.0,
		},
		{
			Ecosystem:          "npm",
			Package:            "vulnerable-pkg",
			VulnerableVersions: []string{"1.0.0"},
			AdvisoryID:         "GHSA-epss-high",
			Aliases:            []string{"CVE-2026-00002"},
			CVSSScore:          5.0,
		},
	})
}

// TestOSVProvider_CarriesEPSS is the regression this wave exists for.
//
// EPSS reached a Report only through cveProvider.Run, which the L-02
// federation fix gated on ecosystemHasScannerAdvisorySource — "docker"
// only. osvProvider took over everywhere else and referenced EPSS
// nowhere, so prod held 245 scored rows (16 over the signal threshold)
// and zero of 14,948 stored reports carried an epssScore.
func TestOSVProvider_CarriesEPSS(t *testing.T) {
	defer epssFixture(t)()

	epss := &stubEPSS{scores: map[string]float64{
		"CVE-2026-00001": 0.21,
		"CVE-2026-00002": 0.87,
	}}
	p := newOSVProvider(slog.Default(), epss)

	got, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "vulnerable-pkg", Version: "1.0.0"},
	}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got.Vulns == nil {
		t.Fatalf("expected a VulnSection")
	}
	// Max-wins across the matched CVEs, same rule as the package rollup
	// and as mergeVulns.
	if got.Vulns.EPSSScore != 0.87 {
		t.Errorf("EPSSScore = %v, want 0.87", got.Vulns.EPSSScore)
	}
	if len(epss.calls) != 1 {
		t.Fatalf("expected exactly one EPSS lookup per scan, got %d", len(epss.calls))
	}
	if len(epss.calls[0]) != 2 {
		t.Errorf("EPSS lookup got %d CVEs, want the 2 matched ones: %v", len(epss.calls[0]), epss.calls[0])
	}
}

// TestOSVProvider_EPSSReachesTheSignal closes the loop the plan demands:
// a stored epssScore is worthless unless vuln.epss_high fires off it.
func TestOSVProvider_EPSSReachesTheSignal(t *testing.T) {
	defer epssFixture(t)()

	p := newOSVProvider(slog.Default(), &stubEPSS{scores: map[string]float64{
		"CVE-2026-00002": 0.87, // above the signal's 0.5 threshold
	}})
	got, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "vulnerable-pkg", Version: "1.0.0"},
	}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	rep := &Report{
		Identity:        IdentitySection{Ecosystem: "npm", Package: "vulnerable-pkg", Version: "1.0.0"},
		Vulnerabilities: *got.Vulns,
	}
	in := ProjectToRiskInput(rep)
	if in.EPSSScore != 0.87 {
		t.Fatalf("risk.Input.EPSSScore = %v, want 0.87 — the projection dropped it", in.EPSSScore)
	}

	ev := risk.EvaluatePackage(in, risk.Options{})
	var fired bool
	for _, cat := range ev.RolledUp.Categories {
		for _, f := range cat.FiredSignals {
			if f.ID == risk.SignalVulnEPSSHigh {
				fired = true
			}
		}
	}
	if !fired {
		t.Errorf("%s did not fire on an EPSS of 0.87; the wire is still cut somewhere downstream", risk.SignalVulnEPSSHigh)
	}
}

// TestOSVProvider_EPSSBelowThresholdStaysSilent — the score is carried
// either way, but the signal must not fire under 0.5.
func TestOSVProvider_EPSSBelowThresholdStaysSilent(t *testing.T) {
	defer epssFixture(t)()

	p := newOSVProvider(slog.Default(), &stubEPSS{scores: map[string]float64{
		"CVE-2026-00001": 0.21,
		"CVE-2026-00002": 0.30,
	}})
	got, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "vulnerable-pkg", Version: "1.0.0"},
	}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got.Vulns.EPSSScore != 0.30 {
		t.Errorf("EPSSScore = %v, want 0.30 carried through", got.Vulns.EPSSScore)
	}
}

// TestOSVProvider_EPSSOutageDoesNotFailTheScan — enrichment, not a
// dependency. A store error costs the report its epssScore and nothing
// else; the CVEs must still be there.
func TestOSVProvider_EPSSOutageDoesNotFailTheScan(t *testing.T) {
	defer epssFixture(t)()

	p := newOSVProvider(slog.Default(), &stubEPSS{err: errors.New("db down")})
	got, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "vulnerable-pkg", Version: "1.0.0"},
	}, nil)
	if err != nil {
		t.Fatalf("an EPSS outage must not fail the scan: %v", err)
	}
	if got.Vulns == nil || len(got.Vulns.CVEs) != 2 {
		t.Fatalf("CVEs must survive an EPSS outage, got %+v", got.Vulns)
	}
	if got.Vulns.EPSSScore != 0 {
		t.Errorf("EPSSScore = %v, want 0 when the lookup failed", got.Vulns.EPSSScore)
	}
}

// TestOSVProvider_NoEPSSReaderIsNotAZeroScore — a nil reader must not be
// confused with a measured zero, and must not panic.
func TestOSVProvider_NoEPSSReaderIsNotAZeroScore(t *testing.T) {
	defer epssFixture(t)()

	p := newOSVProvider(slog.Default(), nil)
	got, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "vulnerable-pkg", Version: "1.0.0"},
	}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got.Vulns.EPSSScore != 0 {
		t.Errorf("EPSSScore = %v, want 0 with no reader wired", got.Vulns.EPSSScore)
	}
	// omitempty on the field means a 0 is absent from the JSON rather
	// than published as a measured score — that is the property that
	// makes the zero honest.
}

// TestOSVProvider_CleanPackageHasNoEPSSLookup — shape 2′ stamps a clean
// section with no CVEs. Doing a DB round-trip there would be per-scan
// work for a guaranteed empty answer.
func TestOSVProvider_CleanPackageHasNoEPSSLookup(t *testing.T) {
	defer epssFixture(t)()

	epss := &stubEPSS{scores: map[string]float64{"CVE-2026-00002": 0.87}}
	p := newOSVProvider(slog.Default(), epss)
	if _, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "not-in-the-bundle", Version: "1.0.0"},
	}, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(epss.calls) != 0 {
		t.Errorf("uncovered package triggered %d EPSS lookups, want 0", len(epss.calls))
	}
}
