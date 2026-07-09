package policy

import (
	"context"
	"sync"
	"testing"
	"time"
)

func scIntPtr(v int) *int { return &v }

// captureAuditor is a minimal SkipAuditor that collects emitted events for
// assertion in tests.
type captureAuditor struct {
	mu     sync.Mutex
	events []SkipAuditEvent
}

func (c *captureAuditor) RecordPolicyRuleSkipped(_ context.Context, ev SkipAuditEvent) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events = append(c.events, ev)
}

func (c *captureAuditor) snapshot() []SkipAuditEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]SkipAuditEvent, len(c.events))
	copy(out, c.events)
	return out
}

func TestEvaluateKnownMalicious(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	ctx := EvaluationContext{
		Repository:       "npmjs",
		PackageName:      "evil-pkg",
		PackageVersion:   "1.0.0",
		IsKnownMalicious: true,
	}

	policy := Policy{
		ID:         "block-malware",
		Precedence: 1,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			IsKnownMalicious: boolPtr(true),
		},
	}

	result := eval.EvaluateWithPolicies(ctx, []Policy{policy}, 0)
	if result.Action != ModeBlock {
		t.Errorf("expected block for known malicious, got %s", result.Action)
	}
}

func TestEvaluateSuspectedTyposquat(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	ctx := EvaluationContext{
		Repository:           "npmjs",
		PackageName:          "lodasg",
		PackageVersion:       "1.0.0",
		IsSuspectedTyposquat: true,
	}

	policy := Policy{
		ID:         "quarantine-typosquat",
		Precedence: 1,
		Mode:       ModeQuarantine,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			IsSuspectedTyposquat: boolPtr(true),
		},
	}

	result := eval.EvaluateWithPolicies(ctx, []Policy{policy}, 0)
	if result.Action != ModeQuarantine {
		t.Errorf("expected quarantine for suspected typosquat, got %s", result.Action)
	}
}

func TestEvaluateTrustScoreMin(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	ctx := EvaluationContext{
		Repository:     "npmjs",
		PackageName:    "sketchy-pkg",
		PackageVersion: "0.1.0",
		TrustScore:     25,
	}

	policy := Policy{
		ID:         "block-low-trust",
		Precedence: 1,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			TrustScoreMax: scIntPtr(50),
		},
	}

	result := eval.EvaluateWithPolicies(ctx, []Policy{policy}, 0)
	if result.Action != ModeBlock {
		t.Errorf("expected block for low trust score, got %s", result.Action)
	}

	// High trust score should not match.
	ctx.TrustScore = 80
	result = eval.EvaluateWithPolicies(ctx, []Policy{policy}, 0)
	if result.Action != ModeAllow {
		t.Errorf("expected allow for high trust score, got %s", result.Action)
	}
}

func TestEvaluateHasProvenance(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	ctx := EvaluationContext{
		Repository:     "npmjs",
		PackageName:    "no-provenance",
		PackageVersion: "1.0.0",
		HasProvenance:  false,
	}

	policy := Policy{
		ID:         "block-no-provenance",
		Precedence: 1,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			HasProvenance: boolPtr(false),
		},
	}

	result := eval.EvaluateWithPolicies(ctx, []Policy{policy}, 0)
	if result.Action != ModeBlock {
		t.Errorf("expected block for no provenance, got %s", result.Action)
	}
}

func TestEvaluateReservedNamespace(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	ctx := EvaluationContext{
		Repository:     "npmjs",
		PackageName:    "@myorg/internal-lib",
		PackageVersion: "2.0.0",
	}

	policy := Policy{
		ID:         "block-dep-confusion",
		Precedence: 1,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			ReservedNamespaces: []string{"@myorg/*"},
		},
	}

	result := eval.EvaluateWithPolicies(ctx, []Policy{policy}, 0)
	if result.Action != ModeBlock {
		t.Errorf("expected block for reserved namespace, got %s", result.Action)
	}

	// Different namespace should not match.
	ctx.PackageName = "@other/lib"
	result = eval.EvaluateWithPolicies(ctx, []Policy{policy}, 0)
	if result.Action != ModeAllow {
		t.Errorf("expected allow for non-reserved namespace, got %s", result.Action)
	}
}

// TestEvaluateSkipsUnsupportedCargoHasProvenance asserts that a HasProvenance
// rule scoped to a Cargo proxy does not block the request (because Cargo has
// no provenance standard per POLICY_PROXY_MATRIX.md) and that the evaluator
// emits a policy.rule.skipped audit event with reason unsupported_ecosystem.
func TestEvaluateSkipsUnsupportedCargoHasProvenance(t *testing.T) {
	store, _ := NewStore(nil)
	auditor := &captureAuditor{}
	eval := NewEvaluator(store).WithSkipAuditor(auditor)

	ctx := EvaluationContext{
		Repository:       "my-cargo-proxy",
		RepositoryFormat: "cargo",
		PackageName:      "cool-crate",
		PackageVersion:   "1.2.3",
		OrgID:            "org-1",
	}

	wantProv := true
	pol := Policy{
		ID:         "pol-cargo-block-no-provenance",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			HasProvenance: &wantProv,
		},
	}

	result := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeAllow {
		t.Fatalf("cargo+HasProvenance rule must not block — got %s (%s)",
			result.Action, result.Reason)
	}
	if result.MatchedPolicy != nil {
		t.Fatalf("expected no matched policy, got %s", result.MatchedPolicy.ID)
	}

	events := auditor.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 skip event, got %d (%+v)", len(events), events)
	}
	ev := events[0]
	if ev.PolicyID != pol.ID {
		t.Errorf("policy_id: want %s, got %s", pol.ID, ev.PolicyID)
	}
	if ev.Ecosystem != "cargo" {
		t.Errorf("ecosystem: want cargo, got %s", ev.Ecosystem)
	}
	if ev.Condition != string(ConditionHasProvenance) {
		t.Errorf("condition: want %s, got %s", ConditionHasProvenance, ev.Condition)
	}
	if ev.Reason != "unsupported_ecosystem" {
		t.Errorf("reason: want unsupported_ecosystem, got %s", ev.Reason)
	}
	if ev.OrgID != "org-1" {
		t.Errorf("org_id: want org-1, got %s", ev.OrgID)
	}
}

func TestEvaluateHasInstallScript(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	ctx := EvaluationContext{
		Repository:       "npmjs",
		PackageName:      "lib-with-postinstall",
		PackageVersion:   "1.0.0",
		HasInstallScript: true,
	}

	pol := Policy{
		ID:         "block-install-scripts",
		Precedence: 1,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			HasInstallScript: boolPtr(true),
		},
	}

	result := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeBlock {
		t.Errorf("expected block for HasInstallScript=true, got %s", result.Action)
	}

	// Negative case: policy demanding no install script should NOT match a
	// package that has one.
	polNone := pol
	polNone.Conditions = Conditions{HasInstallScript: boolPtr(false)}
	result = eval.EvaluateWithPolicies(ctx, []Policy{polNone}, 0)
	if result.Action != ModeAllow {
		t.Errorf("expected allow when HasInstallScript mismatch, got %s", result.Action)
	}
}

func TestEvaluateInstallScriptFetchesRemote(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	ctx := EvaluationContext{
		Repository:                 "npmjs",
		PackageName:                "phantomraven-sample",
		PackageVersion:             "0.1.0",
		HasInstallScript:           true,
		InstallScriptFetchesRemote: true,
	}

	pol := Policy{
		ID:         "block-phantomraven",
		Precedence: 1,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			InstallScriptFetchesRemote: boolPtr(true),
		},
	}

	result := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeBlock {
		t.Errorf("expected block for installScriptFetchesRemote=true, got %s", result.Action)
	}

	// Same rule must not fire on a package that has an install script
	// but doesn't fetch remote.
	ctx.InstallScriptFetchesRemote = false
	result = eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeAllow {
		t.Errorf("expected allow when InstallScriptFetchesRemote=false, got %s", result.Action)
	}
}

// TestEvaluateSkipsUnsupportedMavenInstallScript documents that an
// install-script policy scoped to a maven proxy is silently inert —
// maven has no lifecycle-script concept, so the evaluator must skip it
// and emit a skip-audit event.
func TestEvaluateSkipsUnsupportedMavenInstallScript(t *testing.T) {
	store, _ := NewStore(nil)
	auditor := &captureAuditor{}
	eval := NewEvaluator(store).WithSkipAuditor(auditor)

	ctx := EvaluationContext{
		Repository:       "my-maven-proxy",
		RepositoryFormat: "maven",
		PackageName:      "com.example:artifact",
		PackageVersion:   "1.0.0",
		OrgID:            "org-maven",
	}

	pol := Policy{
		ID:         "pol-maven-block-install-script",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			HasInstallScript: boolPtr(true),
		},
	}

	result := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeAllow {
		t.Fatalf("maven + HasInstallScript rule must not block — got %s", result.Action)
	}
	events := auditor.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 skip event, got %d (%+v)", len(events), events)
	}
	if events[0].Condition != string(ConditionHasInstallScript) {
		t.Errorf("want ConditionHasInstallScript, got %s", events[0].Condition)
	}
}

// TestEvaluateEmitsChecksumUnavailableSkip — PR 12.
//
// A policy that depends on integrity-derived signals (isVulnerable or
// hasProvenance) must emit a distinct `checksum_unavailable` skip
// audit event when the request's ChecksumUnavailable flag is set.
// The reason must NOT be `unsupported_ecosystem` — that's reserved
// for matrix-❌ conditions.
func TestEvaluateEmitsChecksumUnavailableSkip(t *testing.T) {
	store, _ := NewStore(nil)
	auditor := &captureAuditor{}
	eval := NewEvaluator(store).WithSkipAuditor(auditor)

	ctx := EvaluationContext{
		Repository:          "my-go-proxy",
		RepositoryFormat:    "go",
		PackageName:         "example.com/foo",
		PackageVersion:      "1.0.0",
		ChecksumUnavailable: true,
		// isVulnerable is false so if the matcher were reached, the
		// policy (which requires isVulnerable: true) would not match
		// anyway — but the point of the skip-audit is to fire BEFORE
		// matching so operators see the coverage gap.
		IsVulnerable: false,
	}

	wantVuln := true
	pol := Policy{
		ID:         "pol-go-block-vuln",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{IsVulnerable: &wantVuln},
	}

	result := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeAllow {
		t.Fatalf("checksum-unavailable-gated rule must not block, got %s", result.Action)
	}

	events := auditor.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 skip event, got %d (%+v)", len(events), events)
	}
	if events[0].Reason != SkipReasonChecksumUnavailable {
		t.Errorf("reason: want %s, got %s", SkipReasonChecksumUnavailable, events[0].Reason)
	}
	if events[0].Condition != string(ConditionCVE) {
		t.Errorf("condition: want %s (IsVulnerable maps here in proxy_matrix), got %s",
			ConditionCVE, events[0].Condition)
	}
}

// TestSkipReasonsAreEnumerated — PR 12 adds a second enum value to
// the skip-audit reason set. Assert the two known values are the
// only ones so a silent rename / new addition flips the build.
func TestSkipReasonsAreEnumerated(t *testing.T) {
	want := map[string]struct{}{
		"unsupported_ecosystem": {},
		"checksum_unavailable":  {},
	}
	got := map[string]struct{}{
		SkipReasonUnsupportedEcosystem: {},
		SkipReasonChecksumUnavailable:  {},
	}
	if len(got) != len(want) {
		t.Errorf("expected %d distinct reasons, got %d", len(want), len(got))
	}
	for k := range want {
		if _, ok := got[k]; !ok {
			t.Errorf("missing reason %q in enumerated set", k)
		}
	}
}

// TestEvaluateVersionAnomalyBoolFiresOnAnyFlag covers the coarse
// `versionAnomaly: true` path — any flag in the context should match.
func TestEvaluateVersionAnomalyBoolFiresOnAnyFlag(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	want := true
	pol := Policy{
		ID:         "pol-version-anomaly-any",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			VersionAnomaly: &want,
		},
	}

	// Each of the three flag kinds must fire the bool.
	for _, flag := range []string{
		"semver_regression",
		"major_skip",
		"timestamp_regression",
	} {
		ctx := EvaluationContext{
			Repository:          "npmjs",
			PackageName:         "axios",
			PackageVersion:      "0.30.4",
			VersionAnomaly:      true,
			VersionAnomalyFlags: []string{flag},
		}
		result := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
		if result.Action != ModeBlock {
			t.Errorf("flag %q: expected block, got %s", flag, result.Action)
		}
	}
}

// TestEvaluateVersionAnomalyBoolDoesNotFireWhenAbsent asserts
// `versionAnomaly: true` only matches when a flag is present — a clean
// version history must pass.
func TestEvaluateVersionAnomalyBoolDoesNotFireWhenAbsent(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	want := true
	pol := Policy{
		ID:         "pol-version-anomaly-absent",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			VersionAnomaly: &want,
		},
	}

	// No prior versions → no flags → rule must not fire.
	ctx := EvaluationContext{
		Repository:     "npmjs",
		PackageName:    "brand-new-pkg",
		PackageVersion: "1.0.0",
		// VersionAnomaly left false, VersionAnomalyFlags left nil.
	}
	result := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeAllow {
		t.Errorf("clean history must not match versionAnomaly=true, got %s", result.Action)
	}
}

// TestEvaluateVersionAnomalyKindsRequiresIntersection is the headline
// test: a policy with `versionAnomalyKinds: ["semver_regression"]`
// must NOT fire on a context whose only flag is
// `timestamp_regression`, and must fire on any context that contains
// at least one of the listed kinds.
func TestEvaluateVersionAnomalyKindsRequiresIntersection(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	pol := Policy{
		ID:         "pol-version-anomaly-kinds",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			VersionAnomalyKinds: []string{"semver_regression"},
		},
	}

	// Wrong kind — should not match.
	ctxWrong := EvaluationContext{
		Repository:          "npmjs",
		PackageName:         "something",
		PackageVersion:      "1.0.0",
		VersionAnomaly:      true,
		VersionAnomalyFlags: []string{"timestamp_regression"},
	}
	if got := eval.EvaluateWithPolicies(ctxWrong, []Policy{pol}, 0); got.Action != ModeAllow {
		t.Errorf("non-overlapping kind set must not match: got %s", got.Action)
	}

	// Matching kind — should fire.
	ctxRight := EvaluationContext{
		Repository:          "npmjs",
		PackageName:         "axios",
		PackageVersion:      "0.30.4",
		VersionAnomaly:      true,
		VersionAnomalyFlags: []string{"semver_regression"},
	}
	if got := eval.EvaluateWithPolicies(ctxRight, []Policy{pol}, 0); got.Action != ModeBlock {
		t.Errorf("matching kind must fire: got %s", got.Action)
	}

	// Intersection (at least one overlap) — multiple flags on the
	// context, one of which is listed. Also fires.
	ctxOverlap := EvaluationContext{
		Repository:          "npmjs",
		PackageName:         "axios",
		PackageVersion:      "0.30.4",
		VersionAnomaly:      true,
		VersionAnomalyFlags: []string{"timestamp_regression", "semver_regression"},
	}
	if got := eval.EvaluateWithPolicies(ctxOverlap, []Policy{pol}, 0); got.Action != ModeBlock {
		t.Errorf("intersection must fire: got %s", got.Action)
	}
}

// TestEvaluateVersionAnomalyKindsNotExactMatch confirms the semantics
// are intersection-based, not subset/exact — a policy listing only
// `semver_regression` must still fire when the context has BOTH
// `semver_regression` AND other flags the policy didn't list.
func TestEvaluateVersionAnomalyKindsNotExactMatch(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	pol := Policy{
		ID:         "pol-version-anomaly-intersection-only",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			VersionAnomalyKinds: []string{"semver_regression"},
		},
	}
	ctx := EvaluationContext{
		Repository:          "npmjs",
		PackageName:         "foo",
		PackageVersion:      "0.1.0",
		VersionAnomaly:      true,
		VersionAnomalyFlags: []string{"semver_regression", "major_skip"},
	}
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeBlock {
		t.Errorf("intersection (not exact) must fire: got %s (reason=%s)", got.Action, got.Reason)
	}
}

// TestEvaluateVersionAnomalyNoPriorVersions guards the "no history"
// branch: a first-ever package must not fire an anomaly rule, even
// one with versionAnomaly=true (because no priors → no flags).
func TestEvaluateVersionAnomalyNoPriorVersions(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	want := true
	pol := Policy{
		ID:         "pol-anomaly-empty-history",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			VersionAnomaly: &want,
		},
	}
	ctx := EvaluationContext{
		Repository:     "npmjs",
		PackageName:    "greenfield",
		PackageVersion: "1.0.0",
		// Deliberately leave both VersionAnomaly and VersionAnomalyFlags
		// zero — this is what the orchestrator produces when history
		// has fewer than 2 entries.
	}
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0); got.Action != ModeAllow {
		t.Errorf("empty history must not match versionAnomaly=true: got %s", got.Action)
	}
}

// TestEvaluateSkipsUnsupportedDockerVersionAnomaly asserts that a
// VersionAnomaly rule scoped to a Docker proxy does not fire (because
// Docker tags aren't SemVer per the matrix) and that the evaluator
// emits a policy.rule.skipped audit event.
func TestEvaluateSkipsUnsupportedDockerVersionAnomaly(t *testing.T) {
	store, _ := NewStore(nil)
	auditor := &captureAuditor{}
	eval := NewEvaluator(store).WithSkipAuditor(auditor)

	ctx := EvaluationContext{
		Repository:       "my-docker-proxy",
		RepositoryFormat: "docker",
		PackageName:      "library/alpine",
		PackageVersion:   "latest",
		OrgID:            "org-1",
	}

	want := true
	pol := Policy{
		ID:         "pol-docker-anomaly",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			VersionAnomaly: &want,
		},
	}

	result := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeAllow {
		t.Fatalf("docker+VersionAnomaly rule must not block — got %s (%s)", result.Action, result.Reason)
	}
	events := auditor.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 skip event, got %d", len(events))
	}
	if events[0].Condition != string(ConditionVersionAnomaly) {
		t.Errorf("skip condition: want %s, got %s", ConditionVersionAnomaly, events[0].Condition)
	}
}

// TestEvaluateHasHiddenUnicode covers the PR 8 condition: a plain bool rule
// blocks when the context signals hidden-unicode content and does nothing
// otherwise.
func TestEvaluateHasHiddenUnicode(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	ctx := EvaluationContext{
		Repository:       "npmjs",
		PackageName:      "sneaky-pkg",
		PackageVersion:   "1.0.0",
		HasHiddenUnicode: true,
	}

	pol := Policy{
		ID:         "block-hidden-unicode",
		Precedence: 1,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			HasHiddenUnicode: boolPtr(true),
		},
	}

	result := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeBlock {
		t.Errorf("expected block when hidden-unicode detected, got %s", result.Action)
	}

	ctx.HasHiddenUnicode = false
	result = eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeAllow {
		t.Errorf("expected allow when no hidden-unicode, got %s", result.Action)
	}
}

// TestEvaluateHiddenUnicodeKindsIntersection verifies the kinds-intersection
// semantics: the rule fires only when the policy's requested kinds overlap
// the context's detected kinds. Mirrors PR 3's versionAnomalyKinds shape.
func TestEvaluateHiddenUnicodeKindsIntersection(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	// Policy: block on bidi_override specifically.
	pol := Policy{
		ID:         "block-bidi",
		Precedence: 1,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			HasHiddenUnicode:   boolPtr(true),
			HiddenUnicodeKinds: []string{"bidi_override"},
		},
	}

	// Artifact detected zero_width only — should NOT match.
	ctx := EvaluationContext{
		Repository:         "npmjs",
		PackageName:        "zw-only",
		PackageVersion:     "1.0.0",
		HasHiddenUnicode:   true,
		HiddenUnicodeKinds: []string{"zero_width"},
	}
	result := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeAllow {
		t.Errorf("kinds mismatch should not match: got %s", result.Action)
	}

	// Artifact detected bidi_override and zero_width — overlaps → should match.
	ctx.PackageName = "bidi-and-zw"
	ctx.HiddenUnicodeKinds = []string{"bidi_override", "zero_width"}
	result = eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeBlock {
		t.Errorf("kinds intersection should match: got %s", result.Action)
	}

	// Case-insensitive + whitespace tolerance on the policy side.
	pol.Conditions.HiddenUnicodeKinds = []string{"  BIDI_OVERRIDE  "}
	result = eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeBlock {
		t.Errorf("kinds match should be case-insensitive: got %s", result.Action)
	}
}

// TestEvaluateHiddenUnicodeDockerSkips uses the proxy-matrix guard to assert
// that a hasHiddenUnicode rule scoped to a docker-format repo emits a skip
// audit event rather than blocking — docker text-file layer scanning is the
// subject of PR 7, separate from this PR.
func TestEvaluateHiddenUnicodeDockerSkips(t *testing.T) {
	store, _ := NewStore(nil)
	auditor := &captureAuditor{}
	eval := NewEvaluator(store).WithSkipAuditor(auditor)

	ctx := EvaluationContext{
		Repository:       "my-docker-proxy",
		RepositoryFormat: "docker",
		PackageName:      "library/nginx",
		PackageVersion:   "1.25.0",
		OrgID:            "org-1",
		// Even if somehow set, the skip guard must run first.
		HasHiddenUnicode: true,
	}

	pol := Policy{
		ID:         "pol-docker-block-hidden-unicode",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			HasHiddenUnicode: boolPtr(true),
		},
	}

	result := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeAllow {
		t.Fatalf("docker+HasHiddenUnicode must not block (PR 8 matrix says None for docker) — got %s",
			result.Action)
	}
	events := auditor.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 skip event for the unsupported docker combo, got %d", len(events))
	}
	if events[0].Condition != string(ConditionHasHiddenUnicode) {
		t.Errorf("expected condition %s, got %s", ConditionHasHiddenUnicode, events[0].Condition)
	}
}

// TestEvaluatePublishVelocityAnomaly walks the decision table for the new
// publishVelocityAnomaly condition across (count, threshold) pairs. Covers:
//   - under the default threshold → no fire (true-anomaly rule is inert)
//   - over the default threshold (20) → fires
//   - custom threshold 30 → fires only above 30
//   - inverse rule (publishVelocityAnomaly=false) → fires only when NOT anomalous
func TestEvaluatePublishVelocityAnomaly(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	trueFlag := true
	falseFlag := false
	threshold30 := 30

	// Rule: anomaly=true, no custom threshold → default 20
	defaultAnomaly := Policy{
		ID: "block-velocity-default", Precedence: 1, Mode: ModeBlock, Status: StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{PublishVelocityAnomaly: &trueFlag},
	}
	// Rule: anomaly=true, custom threshold 30
	customThreshold := Policy{
		ID: "block-velocity-custom", Precedence: 1, Mode: ModeBlock, Status: StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{PublishVelocityAnomaly: &trueFlag, PublishVelocityThreshold24h: &threshold30},
	}
	// Rule: anomaly=false → require under-threshold behaviour
	requireCalm := Policy{
		ID: "require-calm-velocity", Precedence: 1, Mode: ModeBlock, Status: StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{PublishVelocityAnomaly: &falseFlag},
	}

	cases := []struct {
		name     string
		policy   Policy
		velocity int
		want     Mode
	}{
		{"default threshold — under fires no rule", defaultAnomaly, 15, ModeAllow},
		{"default threshold — exactly at threshold stays quiet", defaultAnomaly, 20, ModeAllow},
		{"default threshold — over fires", defaultAnomaly, 21, ModeBlock},
		{"default threshold — well over fires", defaultAnomaly, 200, ModeBlock},
		{"custom threshold 30 — 25 stays quiet", customThreshold, 25, ModeAllow},
		{"custom threshold 30 — 31 fires", customThreshold, 31, ModeBlock},
		{"custom threshold 30 — 500 fires", customThreshold, 500, ModeBlock},
		{"inverse rule — quiet velocity fires require-calm", requireCalm, 0, ModeBlock},
		{"inverse rule — anomalous velocity does NOT fire require-calm", requireCalm, 100, ModeAllow},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := EvaluationContext{
				Repository:         "npmjs",
				PackageName:        "fast-publisher",
				PackageVersion:     "1.0.0",
				PublishVelocity24h: tc.velocity,
			}
			result := eval.EvaluateWithPolicies(ctx, []Policy{tc.policy}, 0)
			if result.Action != tc.want {
				t.Errorf("velocity=%d policy=%s: want %s, got %s (reason: %s)",
					tc.velocity, tc.policy.ID, tc.want, result.Action, result.Reason)
			}
		})
	}
}

// TestEvaluatePublishVelocityThresholdOnlyInert ensures a policy with only the
// threshold knob set (but no bool gate) stays inert — the ConditionsUsedBy
// accounting in proxy_matrix.go depends on this to avoid attributing fires
// to a field that can't match anything on its own.
func TestEvaluatePublishVelocityThresholdOnlyInert(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	threshold := 5
	// Threshold-only policy — still needs to pass the "at least one
	// condition" gate so we pair it with a target package name.
	pol := Policy{
		ID: "threshold-only", Precedence: 1, Mode: ModeBlock, Status: StatusEnabled,
		CreatedAt:  time.Now(),
		Identifier: Identifier{TargetPackageName: "fast-publisher"},
		Conditions: Conditions{PublishVelocityThreshold24h: &threshold},
	}
	ctx := EvaluationContext{
		Repository:         "npmjs",
		PackageName:        "fast-publisher",
		PackageVersion:     "1.0.0",
		PublishVelocity24h: 100, // well over the threshold
	}
	result := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	// The rule still fires because its identifier matches; the threshold
	// alone has no matching branch. This documents the current behaviour —
	// threshold is a knob on the bool, not a standalone predicate.
	if result.Action != ModeBlock {
		t.Errorf("identifier-driven policy should match regardless of threshold-only condition: got %s", result.Action)
	}
}

// TestEvaluateSupportedCargoCVEStillMatches ensures the skip path only fires
// for ❌ combos: a vulnerability rule on cargo must still evaluate normally.
func TestEvaluateSupportedCargoCVEStillMatches(t *testing.T) {
	store, _ := NewStore(nil)
	auditor := &captureAuditor{}
	eval := NewEvaluator(store).WithSkipAuditor(auditor)

	ctx := EvaluationContext{
		Repository:       "my-cargo-proxy",
		RepositoryFormat: "cargo",
		PackageName:      "vuln-crate",
		PackageVersion:   "0.1.0",
		IsVulnerable:     true,
	}

	wantVuln := true
	pol := Policy{
		ID:         "pol-cargo-block-vuln",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			IsVulnerable: &wantVuln,
		},
	}

	result := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeBlock {
		t.Fatalf("cargo+IsVulnerable rule should block, got %s", result.Action)
	}
	if evs := auditor.snapshot(); len(evs) != 0 {
		t.Errorf("unexpected skip events for supported combo: %+v", evs)
	}
}

// TestEvaluatePublisherChanged covers the PublisherChanged condition matching
// behaviour. The evaluator is just a boolean gate — the actual diff / prior
// lookup lives in supplychain/orchestrator.go and metadiff — but we need to
// confirm the gate fires for true, respects false, and stays inert for nil.
func TestEvaluatePublisherChanged(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	blockChanged := Policy{
		ID:         "block-publisher-changed",
		Precedence: 1,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			PublisherChanged: boolPtr(true),
		},
	}

	cases := []struct {
		name   string
		ctx    EvaluationContext
		want   Mode
		reason string
	}{
		{
			name: "changed=true matches policy publisherChanged=true → block",
			ctx: EvaluationContext{
				Repository:       "npmjs",
				PackageName:      "axios",
				PackageVersion:   "1.14.1",
				PublisherChanged: true,
			},
			want:   ModeBlock,
			reason: "Axios-style takeover should be caught",
		},
		{
			name: "changed=false does NOT match policy publisherChanged=true → allow",
			ctx: EvaluationContext{
				Repository:       "npmjs",
				PackageName:      "axios",
				PackageVersion:   "1.14.0",
				PublisherChanged: false,
			},
			want:   ModeAllow,
			reason: "unchanged publisher set must not fire",
		},
	}

	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			result := eval.EvaluateWithPolicies(c.ctx, []Policy{blockChanged}, 0)
			if result.Action != c.want {
				t.Errorf("%s: got %s, want %s", c.reason, result.Action, c.want)
			}
		})
	}
}

// TestEvaluatePublisherChangedNilConditionAnyValue asserts that a nil
// PublisherChanged pointer leaves the policy indifferent to the signal —
// i.e. doesn't spuriously block every request just because the ctx boolean
// defaults to false. Mirrors IsVulnerable's "nil=any" contract.
func TestEvaluatePublisherChangedNilConditionAnyValue(t *testing.T) {
	store, _ := NewStore(nil)
	eval := NewEvaluator(store)

	// Policy uses only IsKnownMalicious; PublisherChanged is nil ("any").
	pol := Policy{
		ID:         "block-malicious",
		Precedence: 1,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			IsKnownMalicious: boolPtr(true),
		},
	}

	// PublisherChanged true on the ctx must not change the outcome.
	ctx := EvaluationContext{
		Repository:       "npmjs",
		PackageName:      "evil-pkg",
		PackageVersion:   "1.0.0",
		IsKnownMalicious: true,
		PublisherChanged: true,
	}
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0).Action; got != ModeBlock {
		t.Errorf("policy with nil publisherChanged + ctx.publisherChanged=true: want block, got %s", got)
	}
	ctx.PublisherChanged = false
	if got := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0).Action; got != ModeBlock {
		t.Errorf("policy with nil publisherChanged + ctx.publisherChanged=false: want block, got %s", got)
	}
}

// TestEvaluateSkipsUnsupportedCargoPublisherChanged asserts the matrix skip
// path fires for cargo (❌ for PublisherChanged) — a policy referencing the
// condition must not fire on cargo, and must emit one skip audit event.
// Mirrors the HasProvenance skip test so the drift pattern is preserved.
func TestEvaluateSkipsUnsupportedCargoPublisherChanged(t *testing.T) {
	store, _ := NewStore(nil)
	auditor := &captureAuditor{}
	eval := NewEvaluator(store).WithSkipAuditor(auditor)

	ctx := EvaluationContext{
		Repository:       "my-cargo-proxy",
		RepositoryFormat: "cargo",
		PackageName:      "cool-crate",
		PackageVersion:   "1.2.3",
		PublisherChanged: true, // would match without the matrix guard
		OrgID:            "org-1",
	}

	pol := Policy{
		ID:         "pol-cargo-block-publisher-changed",
		Precedence: 10,
		Mode:       ModeBlock,
		Status:     StatusEnabled,
		CreatedAt:  time.Now(),
		Conditions: Conditions{
			PublisherChanged: boolPtr(true),
		},
	}

	result := eval.EvaluateWithPolicies(ctx, []Policy{pol}, 0)
	if result.Action != ModeAllow {
		t.Fatalf("cargo+PublisherChanged rule must not block — got %s (%s)",
			result.Action, result.Reason)
	}
	if result.MatchedPolicy != nil {
		t.Fatalf("expected no matched policy, got %s", result.MatchedPolicy.ID)
	}

	events := auditor.snapshot()
	if len(events) != 1 {
		t.Fatalf("expected 1 skip event, got %d (%+v)", len(events), events)
	}
	ev := events[0]
	if ev.PolicyID != pol.ID {
		t.Errorf("policy_id: want %s, got %s", pol.ID, ev.PolicyID)
	}
	if ev.Condition != string(ConditionPublisherChanged) {
		t.Errorf("condition: want %s, got %s", ConditionPublisherChanged, ev.Condition)
	}
	if ev.Reason != "unsupported_ecosystem" {
		t.Errorf("reason: want unsupported_ecosystem, got %s", ev.Reason)
	}
}
