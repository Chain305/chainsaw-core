package intelligence

import (
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// TestAttack2026_11_BittensorWallet replays the metadata half of the
// bittensor-wallet 4.0.2 compromise (PyPI, 2026-03-15). The backdoor was
// compiled into the Rust extension, so no byte detector sees it; what the
// attacker could not fake was the trusted-publisher attestation — the
// release workflow's attest-build-provenance step was deleted, so 4.0.2
// shipped with no PEP 740 provenance after attested releases.
//
// Drives the real PyPI simple-index rule (pypiProvenanceDowngrade), the
// report projection (ProjectToRiskInput) and the risk engine, and asserts
// sc.provenance_downgrade fires and the verdict is warn (the signal is
// warn-capped; it never quarantines alone). Control: the same release WITH
// provenance on every file does not fire.
func TestAttack2026_11_BittensorWallet(t *testing.T) {
	files := func(attested402 bool) []pypiSimpleFile {
		return []pypiSimpleFile{
			pf("bittensor_wallet-3.1.0.tar.gz", "01-10", true),
			pf("bittensor_wallet-3.1.0-cp312-cp312-manylinux_2_17_x86_64.whl", "01-10", true),
			pf("bittensor_wallet-4.0.0.tar.gz", "02-01", true),
			pf("bittensor_wallet-4.0.0-cp312-cp312-manylinux_2_17_x86_64.whl", "02-01", true),
			pf("bittensor_wallet-4.0.1.tar.gz", "03-01", true),
			pf("bittensor_wallet-4.0.1-cp312-cp312-manylinux_2_17_x86_64.whl", "03-01", true),
			// 4.0.2: uploaded straight to PyPI, attestation step removed.
			pf("bittensor_wallet-4.0.2.tar.gz", "03-15", attested402),
			pf("bittensor_wallet-4.0.2-cp312-cp312-manylinux_2_17_x86_64.whl", "03-15", attested402),
		}
	}
	eval := func(attested402 bool) (*ProvenanceDowngrade, *risk.Evaluation) {
		d := pypiProvenanceDowngrade(files(attested402), "4.0.2")
		r := &Report{Identity: IdentitySection{Ecosystem: "pypi", Package: "bittensor-wallet", Version: "4.0.2"}}
		r.SupplyChain.MalwareStatus = "clean"
		r.SupplyChain.ProvenanceDowngrade = d
		return d, risk.EvaluatePackage(ProjectToRiskInput(r), risk.Options{})
	}
	fired := func(ev *risk.Evaluation) bool {
		for _, cs := range ev.DirectScore.Categories {
			for _, f := range cs.FiredSignals {
				if f.ID == risk.SignalSCProvenanceDowngrade {
					return true
				}
			}
		}
		return false
	}

	d, ev := eval(false)
	if d == nil || d.LastAttestedVersion != "4.0.1" || d.PriorAttestedCount < 3 {
		t.Fatalf("4.0.2 without provenance after three attested releases: downgrade=%+v, want last attested 4.0.1", d)
	}
	if !fired(ev) {
		t.Fatalf("sc.provenance_downgrade did not fire on bittensor-wallet 4.0.2 (verdict %q)", ev.Verdict)
	}
	if ev.Verdict != risk.VerdictWarn {
		t.Fatalf("bittensor-wallet 4.0.2 verdict %q (overall %d), want warn", ev.Verdict, ev.DirectScore.Overall)
	}

	// Negative control: the same release carrying provenance is not a downgrade.
	d, ev = eval(true)
	if d != nil || fired(ev) {
		t.Fatalf("attested 4.0.2 flagged as a provenance downgrade: %+v", d)
	}
}
