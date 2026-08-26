package risk

// license_tiering_test.go — P8-06.
//
// TWO defects, and the second is the reason the first cannot be fixed on
// its own:
//
//	(1) license.non_permissive is BY ITS OWN DEFINITION the superset of
//	    license.copyleft, and both were -20, so every copyleft package paid
//	    -40. MPL-2.0 cost exactly twice what BUSL-1.1 cost.
//
//	(2) UpgradePromotionEligible's dominance test is `d >= vuln` — a TIE
//	    ALSO REFUSES. So deleting the duplicate and stopping there would
//	    have left licence at 20 against vuln.cvss_high's 20 and changed
//	    NOTHING. The certifi case the plan cites does not flip on the
//	    de-duplication alone. The weights had to move too.
//
// These tests assert on the OUTPUT OF THE REAL EvaluatePackage and on the
// real UpgradePromotionEligible, not on registry constants: a test that
// reads Registry[id].Weight would pass against a registry whose signal
// never fires.

import "testing"

// licenceInput builds an Input carrying nothing but a licence, so the
// deficit under test is the only one in play.
func licenceInput(spdx string) Input {
	return Input{
		Ecosystem:   "pypi",
		Package:     "fixture",
		Version:     "1.0.0",
		LicenseSPDX: spdx,
		LicenseTags: Classify(spdx),
	}
}

// licenceDeficit sums the negative licence-category weights the evaluator
// actually filed — the same walk UpgradePromotionEligible does.
func licenceDeficit(ev *Evaluation) float64 {
	total := 0.0
	for _, cs := range ev.DirectScore.Categories {
		for _, f := range cs.FiredSignals {
			if f.Category == CategoryLicense && f.Weight < 0 {
				total += -f.Weight
			}
		}
	}
	return total
}

// TestLicenceStrengthBandsArePriced is the tiering scheme, asserted end to
// end. The ordering is the claim: weak copyleft costs LESS than
// source-available, which costs less than strong copyleft. Before this
// change all three were -40 / -20 / -40, i.e. not an ordering at all.
func TestLicenceStrengthBandsArePriced(t *testing.T) {
	cases := []struct {
		spdx string
		want float64
		band string
	}{
		// Weak copyleft — reciprocity confined to the dependency's own
		// files (MPL/EPL/CDDL) or to linkage (LGPL). -10.
		{"MPL-2.0", 10, "weak copyleft"},
		{"EPL-2.0", 10, "weak copyleft"},
		{"CDDL-1.0", 10, "weak copyleft"},
		{"LGPL-3.0-only", 10, "weak copyleft"},

		// Source-available — not OSI-free; forbids competing use. -20,
		// exactly what it cost before: it was never the over-called case.
		{"BUSL-1.1", 20, "source-available"},
		{"Elastic-2.0", 20, "source-available"},

		// Strong copyleft — whole-work reciprocity. -10 copyleft plus
		// -20 non-permissive = -30.
		{"GPL-3.0-only", 30, "strong copyleft"},
		{"AGPL-3.0-only", 30, "strong copyleft"},
		{"OSL-3.0", 30, "strong copyleft"},

		// Permissive — nothing at all.
		{"MIT", 0, "permissive"},
		{"Apache-2.0", 0, "permissive"},
	}
	for _, tc := range cases {
		t.Run(tc.spdx, func(t *testing.T) {
			ev := EvaluatePackage(licenceInput(tc.spdx), Options{})
			if got := licenceDeficit(ev); got != tc.want {
				t.Errorf("%s (%s): licence deficit %.0f, want %.0f",
					tc.spdx, tc.band, got, tc.want)
			}
		})
	}

	// The ordering, stated as an invariant rather than inferred from the
	// table above, so a future edit that moves two numbers in step still
	// has to preserve the ranking that justified them.
	weak := licenceDeficit(EvaluatePackage(licenceInput("MPL-2.0"), Options{}))
	src := licenceDeficit(EvaluatePackage(licenceInput("BUSL-1.1"), Options{}))
	strong := licenceDeficit(EvaluatePackage(licenceInput("AGPL-3.0-only"), Options{}))
	if !(weak < src && src < strong) {
		t.Errorf("band ordering broken: weak=%.0f source-available=%.0f strong=%.0f "+
			"— the whole point of the tiering is that these three are not the same risk",
			weak, src, strong)
	}
}

// TestCopyleftIsNotDoubleCounted is the de-duplication, stated directly:
// no package may carry BOTH licence-strength signals for the WEAK case,
// because non_permissive is the superset and would be pricing the same
// fact twice.
func TestCopyleftIsNotDoubleCounted(t *testing.T) {
	ev := EvaluatePackage(licenceInput("MPL-2.0"), Options{})
	fired := map[string]bool{}
	for _, cs := range ev.DirectScore.Categories {
		for _, f := range cs.FiredSignals {
			fired[f.ID] = true
		}
	}
	if !fired[SignalLicCopyleft] {
		t.Error("MPL-2.0 must still fire license.copyleft — it IS copyleft")
	}
	if fired[SignalLicNonPermissive] {
		t.Error("MPL-2.0 fired BOTH license.copyleft and license.non_permissive. " +
			"The second is the superset of the first; charging both is the -40 " +
			"double count P8-06 exists to remove.")
	}
}

// TestNonPermissiveTagStillCarriesWeakCopyleft is the enforcement guard on
// the fix. The SIGNAL is suppressed for weak copyleft; the TAG must not be.
// core/policy's LicenseNonPermissive condition reads the tag, and narrowing
// a policy predicate would be an enforcement change smuggled in as a
// scoring fix — an operator who blocks non-permissive licences must keep
// blocking MPL.
func TestNonPermissiveTagStillCarriesWeakCopyleft(t *testing.T) {
	for _, spdx := range []string{"MPL-2.0", "EPL-2.0", "LGPL-3.0-only", "CDDL-1.0"} {
		tags := Classify(spdx)
		if !hasTag(tags, LicenseTagNonPermissive) {
			t.Errorf("Classify(%q) = %v — the license.non_permissive TAG must still "+
				"cover weak copyleft. Only the SIGNAL is suppressed; the tag is what "+
				"core/policy gates on.", spdx, tags)
		}
	}
}

// ─── THE CERTIFI CASE, END TO END ───────────────────────────────────────
//
// certifi 2023.7.22: MPL-2.0, and affected by CVE-2024-39689 (CVSS 7.5 —
// the vendor's "this is the fixed version" reading was itself wrong, see
// the plan's premises table). A safe version exists and the engine had
// already computed it: SafeVersion 2024.7.4 was stamped on the output.
//
// The user was nonetheless shown WARN "review before use" instead of
// UPGRADE, because licence deficit 40 >= vulnerability deficit 20 and
// UpgradePromotionEligible refused. That is a remediation regression for
// exactly the class where a patch exists.

func certifiInput() Input {
	return Input{
		Ecosystem:    "pypi",
		Package:      "certifi",
		Version:      "2023.7.22",
		LicenseSPDX:  "MPL-2.0",
		LicenseTags:  Classify("MPL-2.0"),
		IsVulnerable: true,
		MaxCVSS:      7.5,
		CVEs:         []string{"CVE-2024-39689"},
	}
}

func TestCertifiCopyleftPlusFixableCVEReachesUpgradeAvailable(t *testing.T) {
	in := certifiInput()

	// Step 1 — the deficits, which is where the old code lost.
	ev := EvaluatePackage(in, Options{})
	lic := licenceDeficit(ev)
	vuln := 0.0
	for _, cs := range ev.DirectScore.Categories {
		for _, f := range cs.FiredSignals {
			if f.Category == CategoryVulnerability && f.Weight < 0 {
				vuln += -f.Weight
			}
		}
	}
	if vuln <= 0 {
		t.Fatalf("no vulnerability deficit — the fixture stopped firing vuln.cvss_high")
	}
	if lic >= vuln {
		t.Fatalf("licence deficit %.0f >= vulnerability deficit %.0f. "+
			"UpgradePromotionEligible's test is `d >= vuln` — a TIE also refuses — "+
			"so this is still the pre-fix state: the licence is out-voting the CVE "+
			"and the upgrade recommendation is suppressed.", lic, vuln)
	}

	// Step 2 — the gate itself.
	if !UpgradePromotionEligible(ev) {
		t.Fatalf("UpgradePromotionEligible = false for certifi (verdict %q, overall %d)",
			ev.Verdict, ev.DirectScore.Overall)
	}

	// Step 3 — the promotion the caller performs once the gate opens, with
	// the SafeVersion the engine had computed all along.
	promoted := EvaluatePackage(in, Options{SafeUpgradeVersion: "2024.7.4"})
	if promoted.Verdict != VerdictUpgradeAvailable {
		t.Errorf("verdict = %q, want %q — the user is still being told "+
			"\"review before use\" while the engine holds a published fix",
			promoted.Verdict, VerdictUpgradeAvailable)
	}
	if promoted.Resolution.SafeVersion != "2024.7.4" {
		t.Errorf("SafeVersion = %q, want 2024.7.4", promoted.Resolution.SafeVersion)
	}
}

// TestStrongCopyleftStillOutVotesASingleCVE is the other side of the same
// gate, and it is why the fix is a tiering and not a blanket reduction.
// A package whose dominant problem really IS its licence must NOT be told
// "just upgrade" — a newer release of an AGPL package is still AGPL.
// Strong copyleft at -30 still exceeds vuln.cvss_high's -20, so the
// dominance test keeps refusing.
func TestStrongCopyleftStillOutVotesASingleCVE(t *testing.T) {
	in := certifiInput()
	in.LicenseSPDX = "AGPL-3.0-only"
	in.LicenseTags = Classify(in.LicenseSPDX)

	ev := EvaluatePackage(in, Options{})
	if UpgradePromotionEligible(ev) {
		t.Error("an AGPL package with one high CVE was promoted to upgrade_available. " +
			"Upgrading does not make it not-AGPL; the dominance test exists to " +
			"refuse exactly this.")
	}
}
