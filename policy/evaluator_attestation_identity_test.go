package policy

import (
	"os"
	"strings"
	"testing"
)

// The attestation IDENTITY matchers — RequireBuilderID, RequireBuilderIssuer,
// RequireSourceRepo, RequireTransparencyLog — read four fields that producers
// fill in best-effort from material nothing validated. See the block comment
// in matchesConditions for the full provenance of each. These tests pin the
// gate that makes them inadmissible unless ProvenanceStatus == "verified".
//
// Each case is written so that DELETING the gate flips it. The proof is
// recorded in the commit notes: with the four-line zeroing removed,
// TestUnverifiedIdentityCannotSatisfyAllowRule and
// TestUnverifiedTransparencyLogFailsClosed both fail.

// unverifiedForgedCtx is the attacker's coordinate: a bundle that FAILED
// verification, whose cert extensions nonetheless carried a builder, an
// issuer, a source repo inside the victim org's namespace, and a
// transparency-log URL read straight out of TLogEntries[0].
func unverifiedForgedCtx(status string) EvaluationContext {
	return EvaluationContext{
		Repository:       "npmjs",
		RepositoryFormat: "npm",
		PackageName:      "evil-pkg",
		PackageVersion:   "1.0.0",
		// The whole point: verification did NOT succeed.
		HasProvenance:              false,
		ProvenanceStatus:           status,
		SLSALevel:                  0,
		AttestationBuilderID:       "https://github.com/acme/ci/.github/workflows/release.yml@refs/heads/main",
		AttestationIssuer:          "https://token.actions.githubusercontent.com",
		AttestationSourceRepo:      "https://github.com/acme/widgets",
		AttestationTransparencyLog: "https://search.sigstore.dev/?logIndex=99999",
	}
}

// TestUnverifiedIdentityCannotSatisfyAllowRule is the exploit, inverted.
//
// An org pins an ALLOW rule on its own source repo — "packages built from
// github.com/acme/ are exempt". A malicious package ships a Sigstore bundle
// that fails verification; npm.go's StatusFailed branch still extracted the
// cert's SourceRepositoryURI and the projection stored it. Before the gate,
// containsAnySubstring matched the attacker's string and the allow rule
// fired, exempting the package.
func TestUnverifiedIdentityCannotSatisfyAllowRule(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	allowTrustedRepo := basePolicy(Conditions{
		RequireSourceRepo: []string{"github.com/acme/"},
	})
	allowTrustedRepo.Mode = ModeAllow
	allowTrustedRepo.Precedence = 100

	// A lower-precedence block rule stands in for "the rest of the policy
	// set", so a failure to match the allow rule is visible as a block.
	blockEverything := basePolicy(Conditions{})
	blockEverything.ID = "block-all"
	blockEverything.Mode = ModeBlock
	blockEverything.Precedence = 1

	policies := []Policy{allowTrustedRepo, blockEverything}

	// Control: a genuinely verified package from that repo IS exempted.
	verified := baseAttestationCtx()
	verified.AttestationSourceRepo = "https://github.com/acme/widgets"
	if got := eval.EvaluateWithPolicies(verified, policies, 0); got.Action != ModeAllow {
		t.Fatalf("verified package from the trusted repo: got %s, want allow — "+
			"the gate must not break legitimate attestation-based exemptions", got.Action)
	}

	// The defect: every non-verified status must fail to satisfy the rule.
	for _, status := range []string{"failed", "unverified", "missing", "unavailable", ""} {
		ctx := unverifiedForgedCtx(status)
		got := eval.EvaluateWithPolicies(ctx, policies, 0)
		if got.Action == ModeAllow {
			t.Errorf("provenanceStatus=%q: got allow — a bundle that did not verify "+
				"satisfied requireSourceRepo and exempted the package", status)
		}
	}
}

// TestUnverifiedTransparencyLogFailsClosed is the case that makes the
// DIRECTION of the gate load-bearing, and the reason it zeroes the field
// rather than returning false.
//
// `requireTransparencyLog: false` on a BLOCK rule means "block anything with
// no transparency-log entry" — the same negative polarity the seeded baseline
// uses via requireAttestation:false. A blanket "unverified provenance means
// this rule cannot match" would let a forged TLogEntries[0] ESCAPE that block:
// fail-open, and strictly worse than the bug being fixed. Zeroing makes
// hasTLog false, the block matches, the package is refused.
func TestUnverifiedTransparencyLogFailsClosed(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	blockNoTLog := basePolicy(Conditions{RequireTransparencyLog: boolPtr(false)})

	// Attacker supplies a transparency-log URL on an unverified bundle.
	ctx := unverifiedForgedCtx("failed")
	if got := eval.EvaluateWithPolicies(ctx, []Policy{blockNoTLog}, 0); got.Action != ModeBlock {
		t.Errorf("forged tlog on an unverified bundle: got %s, want block — "+
			"an unverified transparency-log URL must not satisfy the rule's "+
			"'has a tlog' branch and escape a no-tlog block", got.Action)
	}

	// And the positive polarity still behaves: a verified package WITH a
	// tlog does not match "block things with no tlog".
	verified := baseAttestationCtx()
	if got := eval.EvaluateWithPolicies(verified, []Policy{blockNoTLog}, 0); got.Action != ModeAllow {
		t.Errorf("verified package with a real tlog: got %s, want allow", got.Action)
	}
}

// TestUnverifiedIdentityBlocksBuilderAndIssuerMatchers covers the two
// remaining substring matchers on the same gate.
func TestUnverifiedIdentityBlocksBuilderAndIssuerMatchers(t *testing.T) {
	cases := []struct {
		name string
		cond Conditions
	}{
		{"builderID", Conditions{RequireBuilderID: []string{"github.com/acme/ci"}}},
		{"builderIssuer", Conditions{RequireBuilderIssuer: []string{"token.actions.githubusercontent.com"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Verified: the matcher works as designed.
			verified := baseAttestationCtx()
			verified.AttestationBuilderID = "https://github.com/acme/ci/.github/workflows/release.yml@refs/heads/main"
			if !matchesConditions(verified, tc.cond) {
				t.Fatalf("verified context did not satisfy %s — gate broke a working matcher", tc.name)
			}

			// Unverified: the same strings must not satisfy it.
			if matchesConditions(unverifiedForgedCtx("failed"), tc.cond) {
				t.Errorf("%s satisfied by an unverified bundle's cert extensions", tc.name)
			}
		})
	}
}

// TestProvenanceVerifiedIsCaseAndSpaceTolerant pins the comparison shape.
// internal/server/policy_simulate.go hydrates the same column with
// strings.EqualFold; a preview that disagreed with enforcement on casing
// would report a block the proxy does not deliver.
func TestProvenanceVerifiedIsCaseAndSpaceTolerant(t *testing.T) {
	for _, in := range []string{"verified", "Verified", "VERIFIED", " verified "} {
		if !provenanceVerified(in) {
			t.Errorf("provenanceVerified(%q) = false, want true", in)
		}
	}
	for _, in := range []string{"", "unverified", "failed", "missing", "unavailable", "verifie"} {
		if provenanceVerified(in) {
			t.Errorf("provenanceVerified(%q) = true, want false", in)
		}
	}
}

// TestProvenanceVerifiedMatchesProvenancePackage pins the duplicated literal.
//
// core/policy cannot import core/provenance (core/provenance imports
// core/policy), so "verified" is spelled out in provenanceVerified. If
// core/provenance.StatusVerified is ever renamed, this gate — and every
// Require* condition behind it — would silently stop matching ANY package,
// which reads as "policies just stopped firing" rather than as a break. The
// source scan is deliberate: an import would be a cycle.
func TestProvenanceVerifiedMatchesProvenancePackage(t *testing.T) {
	const src = "../provenance/provenance.go"
	b, err := os.ReadFile(src)
	if err != nil {
		t.Skipf("cannot read %s (core/provenance not vendored in this layout): %v", src, err)
	}
	const want = `StatusVerified Status = "verified"`
	if !strings.Contains(string(b), want) {
		t.Fatalf("%s no longer declares %s.\n"+
			"core/policy.provenanceVerified hard-codes the literal \"verified\" because it "+
			"cannot import core/provenance (import cycle). Update BOTH, or the attestation "+
			"identity gate silently rejects every package.", src, want)
	}
}
