package intelligence

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/risk"
)

// TestAttack2026_19_AxiosProvenanceDowngrade: axios releases before the
// 2026-03-31 takeover were published by trusted publishing (provenance
// attested); 1.14.1 was published from the npm CLI with a stolen session and
// carries none. The npm registry reader turns that into
// sc.provenance_downgrade, which caps the verdict at warn — DETECTED, and a
// warn verdict doubles the release hold (96h). It never refuses alone.
func TestAttack2026_19_AxiosProvenanceDowngrade(t *testing.T) {
	now := time.Now()
	ts := func(d time.Duration) string { return now.Add(-d).UTC().Format(time.RFC3339) }
	attested := `{"dist":{"tarball":"https://registry.npmjs.org/axios/-/axios-X.tgz","attestations":{"url":"https://registry.npmjs.org/-/npm/v1/attestations/axios@X","provenance":{"predicateType":"https://slsa.dev/provenance/v1"}}}}`
	bare := `{"dist":{"tarball":"https://registry.npmjs.org/axios/-/axios-X.tgz"}}`
	var versions map[string]npmVersionMeta
	if err := json.Unmarshal([]byte(`{"1.13.5":`+attested+`,"1.13.6":`+attested+`,"1.14.0":`+attested+`,"1.14.1":`+bare+`}`), &versions); err != nil {
		t.Fatal(err)
	}
	stamps := map[string]string{"1.13.5": ts(40 * 24 * time.Hour), "1.13.6": ts(25 * 24 * time.Hour), "1.14.0": ts(12 * 24 * time.Hour), "1.14.1": ts(40 * time.Minute)}

	d := npmProvenanceDowngrade(versions, stamps, "1.14.1")
	if d == nil || d.LastAttestedVersion != "1.14.0" || d.PriorAttestedCount < risk.ProvenanceDowngradeMinPrior {
		t.Fatalf("axios@1.14.1 downgrade evidence = %+v", d)
	}
	if npmProvenanceDowngrade(versions, stamps, "1.14.0") != nil {
		t.Fatal("negative control: attested 1.14.0 reported as a downgrade")
	}

	report := &Report{}
	report.Identity = IdentitySection{Ecosystem: "npm", Package: "axios", Version: "1.14.1"}
	report.Metadata.LicenseExpression = "MIT"
	report.SupplyChain.ProvenanceDowngrade = d
	ev := risk.EvaluatePackage(ProjectToRiskInput(report), risk.Options{})
	fired := false
	for _, c := range ev.DirectScore.Categories {
		for _, f := range c.FiredSignals {
			fired = fired || f.ID == risk.SignalSCProvenanceDowngrade
		}
	}
	if !fired || ev.Verdict != risk.VerdictWarn {
		t.Fatalf("axios@1.14.1: provenance_downgrade fired=%v verdict=%s overall=%d, want fired + warn", fired, ev.Verdict, ev.DirectScore.Overall)
	}

	report.SupplyChain.ProvenanceDowngrade = nil
	if ev := risk.EvaluatePackage(ProjectToRiskInput(report), risk.Options{}); ev.Verdict == risk.VerdictWarn && ev.DirectScore.CeilingSignal == risk.SignalSCProvenanceDowngrade {
		t.Fatal("negative control: warn ceiling without a downgrade")
	}
}
