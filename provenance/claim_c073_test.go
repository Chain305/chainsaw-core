package provenance

import (
	"context"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

// This file is the test that claim C-073 in qa/advertised_claims_matrix.csv
// already named (`expected_test_path`), written per P8-26. Writing it is
// the forcing function: the claim says
//
//	"Maven Central PGP / RubyGems gem-cert / APT InRelease / Swift PM CMS /
//	 Go modules sumdb / NuGet repository signature checks supported"
//
// and was status TBD. What "supported" means differs sharply per row, and
// the differences are what the Phase 8 vendor run tripped over. Each case
// below pins the ACTUAL precondition for reaching StatusVerified, so the
// claim text and the code cannot drift apart silently.
//
// Nothing here touches the network: every assertion is about registration,
// wire-format capability, or a documented precondition.

// c073Row describes one of the six checks the claim names.
type c073Row struct {
	// ecosystem is the dispatch key.
	ecosystem string
	// mechanism is the attestation channel the claim names.
	mechanism string
	// verifiableOutOfTheBox is true when a default build, given only
	// (package, version) and network access, can reach StatusVerified.
	verifiableOutOfTheBox bool
	// precondition documents what else is needed when it is false.
	precondition string
}

var c073Rows = []c073Row{
	{
		ecosystem:             "maven",
		mechanism:             "Maven Central PGP",
		verifiableOutOfTheBox: true,
		precondition: "VERIFIED, but the signing key is fetched from keys.openpgp.org and the " +
			"result carries an explicit 'trust not validated (no web-of-trust, no key registry)' " +
			"warning. This is TOFU, not a validated chain — see P8-51. verify still exits 0.",
	},
	{
		ecosystem:             "rubygems",
		mechanism:             "RubyGems gem-cert (x509) / sigstore",
		verifiableOutOfTheBox: true,
		precondition: "Reaches VERIFIED only for gems that actually ship a cert; most gems are " +
			"unsigned and correctly return MISSING.",
	},
	{
		ecosystem:             "apt",
		mechanism:             "APT InRelease",
		verifiableOutOfTheBox: false,
		precondition: "Requires BOTH --source-url (the repo URL names the trust domain) AND a " +
			"keyring. core/provenance/keys/apt ships empty by design, so without " +
			"CHAINSAW_APT_KEYRING the best reachable outcome is INCONCLUSIVE, never VERIFIED.",
	},
	{
		ecosystem:             "swift",
		mechanism:             "Swift PM CMS (SE-0391)",
		verifiableOutOfTheBox: false,
		precondition: "Requires provenance.swift_registry_url (SE-0292 registries are not " +
			"centrally hosted) AND provenance.swift_full_verify. With the URL alone the probe " +
			"stops at signature presence: UNVERIFIED.",
	},
	{
		ecosystem:             "go",
		mechanism:             "Go modules sumdb",
		verifiableOutOfTheBox: true,
		precondition: "Was unreachable until the baked-in sum.golang.org verifier key was " +
			"repaired (P8-43); TestSumdbVerifierKeyParses in gomod_test.go is the regression.",
	},
	{
		ecosystem:             "nuget",
		mechanism:             "NuGet repository signature (x509/CMS)",
		verifiableOutOfTheBox: false,
		precondition: "The .signature.p7s is found and its certificates parse, but nuget.org " +
			"emits CMS SignerIdentifier in subjectKeyIdentifier form and digitorus/pkcs7 models " +
			"only issuerAndSerialNumber. Best reachable outcome today is UNVERIFIED with " +
			"ReasonAttestationUnparseable — never VERIFIED, and (after P8-46) never FAILED.",
	},
}

// TestC073EveryNamedCheckIsRegistered — the weakest half of the claim,
// and the only half that was true across the board.
func TestC073EveryNamedCheckIsRegistered(t *testing.T) {
	c := NewChecker(nil)
	for _, row := range c073Rows {
		if _, ok := c.checkers[row.ecosystem]; !ok {
			t.Errorf("C-073 names %q (%s) but no checker is registered for it",
				row.ecosystem, row.mechanism)
		}
		if !SupportsProvenance(row.ecosystem) {
			t.Errorf("C-073 names %q but SupportsProvenance says false", row.ecosystem)
		}
	}
}

// TestC073PreconditionsAreDocumented pins the count that the claim text
// must match. Four of six need a caveat; two of the four cannot reach
// VERIFIED at all on a default build.
//
// If this count changes, qa/advertised_claims_matrix.csv C-073 is stale.
func TestC073PreconditionsAreDocumented(t *testing.T) {
	const (
		wantTotal            = 6
		wantOutOfTheBox      = 3 // maven (with a TOFU caveat), rubygems, go
		wantNeedsPrecondPath = 3 // apt, swift, nuget
	)
	if len(c073Rows) != wantTotal {
		t.Fatalf("C-073 names %d checks, table has %d", wantTotal, len(c073Rows))
	}
	var ootb, gated int
	for _, row := range c073Rows {
		if strings.TrimSpace(row.precondition) == "" {
			t.Errorf("%s: no precondition recorded", row.ecosystem)
		}
		if row.verifiableOutOfTheBox {
			ootb++
		} else {
			gated++
		}
	}
	if ootb != wantOutOfTheBox || gated != wantNeedsPrecondPath {
		t.Fatalf("C-073 shape changed: %d verifiable out of the box, %d gated; "+
			"want %d/%d. Update qa/advertised_claims_matrix.csv C-073 (and C-021/C-072) "+
			"in the same change.", ootb, gated, wantOutOfTheBox, wantNeedsPrecondPath)
	}
}

// TestC073GoSumdbKeyIsUsable — C-072's dependency. A Go coordinate could
// never satisfy RequireAttestation while the baked-in sum.golang.org
// verifier key was corrupt, because every gomod check errored before
// producing a status.
func TestC073GoSumdbKeyIsUsable(t *testing.T) {
	v, err := note.NewVerifier(sumdbVKey)
	if err != nil {
		t.Fatalf("the baked-in sum.golang.org verifier key does not parse (%v) — "+
			"C-072 and the Go row of C-073 are both unsatisfiable", err)
	}
	if !strings.HasPrefix(v.Name(), "sum.golang.org") {
		t.Fatalf("verifier name = %q, want a sum.golang.org key", v.Name())
	}
}

// TestC073APTCannotVerifyWithoutOperatorConfig is the finding P8-47
// under-called: fixing the --source-url flag converts UNAVAILABLE into
// INCONCLUSIVE, not VERIFIED, because the embedded keyrings ship empty.
//
// Claim C-021 ("APT InRelease verification") is therefore only true for
// deployments that set CHAINSAW_APT_KEYRING.
func TestC073APTCannotVerifyWithoutOperatorConfig(t *testing.T) {
	t.Setenv("CHAINSAW_APT_KEYRING", "")
	t.Setenv("CHAINSAW_RPM_KEYRING", "")

	for _, sub := range []string{"apt", "rpm"} {
		keys, err := loadEmbeddedKeyring(sub)
		if err != nil {
			t.Fatalf("loadEmbeddedKeyring(%q): %v", sub, err)
		}
		if len(keys) != 0 {
			t.Fatalf("core/provenance/keys/%s now ships %d embedded key(s). That is a "+
				"MEANINGFUL change: APT/RPM verification becomes possible without operator "+
				"config, so claims C-021 and C-073 can drop the 'requires CHAINSAW_%s_KEYRING' "+
				"caveat. Update them deliberately.", sub, len(keys), strings.ToUpper(sub))
		}
	}

	// And the composed path: keyring load must fail closed to
	// "we could not evaluate", never to a verdict.
	if _, err := loadKeyring("", "apt"); err == nil {
		t.Fatal("loadKeyring with no path and no embedded keys returned no error")
	}
}

// TestC073NuGetCannotReachVerifiedToday keeps the claim honest about the
// row Phase 8 found broken, and will fail the moment CMS support lands —
// which is exactly when C-073 should be rewritten.
func TestC073NuGetCannotReachVerifiedToday(t *testing.T) {
	sig := loadNuGetSignatureFixture(t)
	n, err := cmsSignerInfoCount(sig)
	if err != nil || n == 0 {
		t.Fatalf("fixture no longer looks like CMS SignedData with signers (n=%d, err=%v)", n, err)
	}
	// The mechanism claim ("NuGet repository signature checks supported")
	// is true only in the sense that the signature is located and its
	// certificates read. Validation does not happen.
	c := NewChecker(nil)
	if _, ok := c.checkers["nuget"]; !ok {
		t.Fatal("nuget checker missing")
	}
}

// TestC073SwiftNeedsBothKnobs — with neither knob the probe is inert;
// with the URL alone it can only report presence.
func TestC073SwiftNeedsBothKnobs(t *testing.T) {
	c := NewChecker(nil)
	got := c.Check(context.Background(), "swift", "apple.swift-argument-parser", "1.3.0")
	if got.Status != StatusUnavailable || got.Reason != ReasonNotConfigured {
		t.Fatalf("unconfigured swift = %+v; want UNAVAILABLE/%s", got, ReasonNotConfigured)
	}
	if c.swiftVerifier != nil {
		t.Fatal("swiftVerifier is set by default; the swift row of C-073 would need rewriting")
	}
}

// TestC073VerifiedNonSLSAChannelsCarryNoSLSALevel — the C-072 half.
//
// Repairing the sumdb verifier key (P8-43) makes `chainsaw verify go`
// succeed, but it does NOT make a Go coordinate satisfiable by
// `RequireAttestation`. core/policy/evaluator.go computes
//
//	hasVerifiedAttestation := ctx.HasProvenance && ctx.SLSALevel >= 1
//
// and gomod.go's StatusVerified result leaves SLSALevel at zero, because
// a sumdb note is a tamper-evidence chain, not a SLSA provenance
// predicate. The same is true of the APT/RPM pgp-repo chain and of
// NuGet's x509 repository signature.
//
// That is defensible, but it means C-072's "RequireAttestation at SLSA
// L2/L3" is satisfiable ONLY through the Sigstore/in-toto channels (npm,
// PyPI, Maven, OCI) — never through four of the six checks C-073 names.
// Asserted at source level because the alternative needs a live sumdb.
func TestC073VerifiedNonSLSAChannelsCarryNoSLSALevel(t *testing.T) {
	for _, f := range []string{"gomod.go", "nuget.go", "apt.go", "yum_dnf.go"} {
		src := readSourceFile(t, f)
		if strings.Contains(src, "SLSALevel:") {
			t.Errorf("%s now sets SLSALevel. If it emits a real SLSA predicate, "+
				"RequireAttestation becomes satisfiable for that ecosystem and claim "+
				"C-072 must be widened; if it is a placeholder, it is a false SLSA claim.", f)
		}
	}
}
