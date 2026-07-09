package policy

import (
	"testing"
	"time"
)

// baseAttestationCtx returns an EvaluationContext that already represents
// "the package has a verified SLSA L3 attestation" — tests start here and
// flip individual fields to assert specific matchers.
func baseAttestationCtx() EvaluationContext {
	return EvaluationContext{
		Repository:                 "npmjs",
		RepositoryFormat:           "npm",
		PackageName:                "verified-pkg",
		PackageVersion:             "1.0.0",
		HasProvenance:              true,
		ProvenanceStatus:           "verified",
		SLSALevel:                  3,
		AttestationBuilderID:       "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v1",
		AttestationIssuer:          "https://token.actions.githubusercontent.com",
		AttestationSourceRepo:      "https://github.com/foo/bar",
		AttestationTransparencyLog: "https://search.sigstore.dev/?logIndex=12345",
	}
}

func basePolicy(cond Conditions) Policy {
	return Policy{
		ID:         "test-policy",
		Precedence: 1,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: cond,
	}
}

func TestRequireAttestationMatchesVerified(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)
	ctx := baseAttestationCtx()
	pol := basePolicy(Conditions{RequireAttestation: boolPtr(true)})
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeBlock {
		t.Errorf("expected block (rule matched), got %s", got.Action)
	}
	// Flip to unverified — rule should no longer match, falls through to allow.
	ctx.HasProvenance = false
	ctx.SLSALevel = 0
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeAllow {
		t.Errorf("unverified package: expected allow (rule skipped), got %s", got.Action)
	}
}

func TestRequireAttestationFalseFiresOnMissing(t *testing.T) {
	// The "block packages without verified attestation" baseline is
	// expressed as RequireAttestation=false on a block-mode policy.
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)
	ctx := baseAttestationCtx()
	ctx.HasProvenance = false
	ctx.SLSALevel = 0
	pol := basePolicy(Conditions{RequireAttestation: boolPtr(false)})
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeBlock {
		t.Errorf("missing attestation: expected block, got %s", got.Action)
	}
	// With verified attestation, rule should not fire.
	ctx = baseAttestationCtx()
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeAllow {
		t.Errorf("verified attestation: expected allow, got %s", got.Action)
	}
}

func TestRequireSLSALevel(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)
	pol := basePolicy(Conditions{RequireSLSALevel: intPtr(3)})

	cases := []struct {
		level int
		want  Mode
	}{
		{4, ModeBlock},
		{3, ModeBlock},
		{2, ModeAllow}, // below threshold → rule skips → fall through
		{1, ModeAllow},
		{0, ModeAllow},
	}
	for _, tc := range cases {
		ctx := baseAttestationCtx()
		ctx.SLSALevel = tc.level
		got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
		if got.Action != tc.want {
			t.Errorf("level=%d: got %s, want %s", tc.level, got.Action, tc.want)
		}
	}
}

func TestRequireBuilderIDSubstring(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)
	pol := basePolicy(Conditions{
		RequireBuilderID: []string{"slsa-framework/slsa-github-generator"},
	})
	ctx := baseAttestationCtx()
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeBlock {
		t.Errorf("matching builder: expected block (rule fired), got %s", got.Action)
	}

	ctx.AttestationBuilderID = "https://example.com/some-other-builder"
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeAllow {
		t.Errorf("non-matching builder: expected allow (rule skipped), got %s", got.Action)
	}

	// Empty builder ID never matches a non-empty allow-list.
	ctx.AttestationBuilderID = ""
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeAllow {
		t.Errorf("empty builder: expected allow, got %s", got.Action)
	}
}

func TestRequireSourceRepo(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)
	pol := basePolicy(Conditions{
		RequireSourceRepo: []string{"github.com/foo/bar", "github.com/foo/baz"},
	})
	ctx := baseAttestationCtx()
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeBlock {
		t.Errorf("matching repo: expected block, got %s", got.Action)
	}

	ctx.AttestationSourceRepo = "https://github.com/evil/typosquat"
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeAllow {
		t.Errorf("non-matching repo: expected allow, got %s", got.Action)
	}
}

func TestRequireTransparencyLog(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)
	pol := basePolicy(Conditions{RequireTransparencyLog: boolPtr(true)})
	ctx := baseAttestationCtx()
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeBlock {
		t.Errorf("with tlog: expected block, got %s", got.Action)
	}
	ctx.AttestationTransparencyLog = ""
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeAllow {
		t.Errorf("no tlog: expected allow, got %s", got.Action)
	}
}

func TestForbidCacheStale(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)
	pol := basePolicy(Conditions{ForbidCacheStale: boolPtr(true)})
	ctx := baseAttestationCtx()

	// Fresh verification: rule fires (operator wants to BLOCK packages
	// when cache is stale; with fresh data, the rule's "stale=false"
	// requirement is met, so the policy applies).
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeBlock {
		t.Errorf("fresh: expected block (rule fired), got %s", got.Action)
	}

	ctx.AttestationCacheStale = true
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeAllow {
		t.Errorf("stale: expected allow (rule skipped), got %s", got.Action)
	}
}

func TestEcosystemNarrowing(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)
	pol := basePolicy(Conditions{
		Ecosystems:         []string{"npm", "pypi", "maven", "gomod", "oci"},
		RequireAttestation: boolPtr(false), // block "no attestation"
	})

	cases := []struct {
		format string
		want   Mode
	}{
		// Tier-1 with no attestation → block
		{"npm", ModeBlock},
		{"pypi", ModeBlock},
		{"oci", ModeBlock},
		{"NPM", ModeBlock}, // case-insensitive
		// Non-Tier-1 → rule must skip → fall through to allow
		{"cargo", ModeAllow},
		{"rubygems", ModeAllow},
		{"composer", ModeAllow},
		// Empty format → defensively does not match
		{"", ModeAllow},
	}
	for _, tc := range cases {
		ctx := EvaluationContext{
			Repository:       "any",
			RepositoryFormat: tc.format,
			PackageName:      "no-attestation-pkg",
			PackageVersion:   "1.0.0",
			HasProvenance:    false,
			SLSALevel:        0,
		}
		got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
		if got.Action != tc.want {
			t.Errorf("format=%q: got %s, want %s", tc.format, got.Action, tc.want)
		}
	}
}

func TestEcosystemNarrowingEmptyListMatchesAny(t *testing.T) {
	// Empty Ecosystems list = unscoped: rule fires for every format
	// (existing semantics, drift guard).
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)
	pol := basePolicy(Conditions{
		RequireAttestation: boolPtr(false),
	})
	for _, fmt := range []string{"npm", "cargo", "rubygems"} {
		ctx := EvaluationContext{
			Repository:       "x",
			RepositoryFormat: fmt,
			PackageName:      "p",
			PackageVersion:   "1",
		}
		if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeBlock {
			t.Errorf("format=%q: got %s, want block (unscoped rule must fire)", fmt, got.Action)
		}
	}
}

func TestAttestationMatchersComposeAND(t *testing.T) {
	// The full SLSA-substrate matcher: "verified L3 from
	// slsa-github-generator built from github.com/foo/bar" composes
	// four matchers AND'd together. All must hit for the policy to
	// fire.
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)
	pol := basePolicy(Conditions{
		RequireAttestation: boolPtr(true),
		RequireSLSALevel:   intPtr(3),
		RequireBuilderID:   []string{"slsa-github-generator"},
		RequireSourceRepo:  []string{"github.com/foo/bar"},
	})
	ctx := baseAttestationCtx()
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeBlock {
		t.Errorf("all match: expected block, got %s", got.Action)
	}
	// Drop the level — single field flip should make the AND fail.
	ctx.SLSALevel = 1
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeAllow {
		t.Errorf("level<3: expected allow, got %s", got.Action)
	}
}
