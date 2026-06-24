package policyengine_test

// Pain 4 tests: the policyengine facade emits notify_owner side-effect
// verdicts populated with route metadata when an OwnerResolver is wired.

import (
	"context"
	"testing"

	"github.com/chain305/chainsaw-core/policy"
	"github.com/chain305/chainsaw-core/policy/dsl"
	"github.com/chain305/chainsaw-core/policyengine"
)

// fakeResolver is a stub OwnerResolver used to drive the routing path
// without touching the ownership store.
type fakeResolver struct {
	team, handle, contact string
	called                int
}

func (f *fakeResolver) ResolveOwners(_ context.Context, _, _, _ string) (string, string, string, bool) {
	f.called++
	if f.team == "" {
		return "", "", "", false
	}
	return f.team, f.handle, f.contact, true
}

// nativeBlockEvaluator is the smallest possible policy.Evaluator that
// returns a Block decision. We construct a policy store with one
// always-match block policy.
//
// We just construct an Engine with native = nil and rely on a custom
// path: easier — wire a fake DSL engine? Actually the simplest is to
// drive Engine.Decide with native nil + DSL nil but observe Action
// remains Allow → emitOwnerRouting won't fire. So we can't hit the
// routing path that easily without a real verdict.
//
// Instead, we wire a real native evaluator via policy.NewEvaluator
// against a minimal in-memory store. But that's a heavy fixture for
// what is conceptually a unit-level assertion. We instead use the
// public emission helper indirectly by constructing a Decision with a
// pre-populated notify_owner violation and verifying SetOwnerResolver
// + Decide back-fills the OwnerTeam field.
//
// The approach: enable the routing path by faking a non-allow native
// decision. We do that by constructing a tiny Evaluator with a single
// MatchAll policy in Block mode.

func TestNotifyOwnerEmittedWhenResolverWired(t *testing.T) {
	t.Parallel()

	// Use the same policies/ bundle the other tests load. The demo
	// rule fires Block when HasInstallScript && MaintainerAccountAgeDays<14.
	eng := policyengine.New(policyengine.Config{DSL: loadDSL(t)})
	resolver := &fakeResolver{
		team:    "payments",
		handle:  "@payments",
		contact: "https://example.com/payments",
	}
	eng.SetOwnerResolver(resolver)

	ec := policy.EvaluationContext{
		PackageName:              "evil-foo",
		PackageVersion:           "1.0.0",
		RepositoryFormat:         "npm",
		Repository:               "acme/payments",
		OrgID:                    "org-1",
		HasInstallScript:         true,
		MaintainerAccountAgeDays: 7,
	}
	dec, err := eng.Decide(context.Background(), policy.SurfaceProxy, ec)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Action != dsl.ActionBlock {
		t.Fatalf("expected Block from demo rule, got %s", dec.Action)
	}
	// emitOwnerRouting must have appended a notify_owner violation
	// with route metadata populated.
	found := false
	for _, v := range dec.Violations {
		if v.Action != dsl.ActionNotifyOwner {
			continue
		}
		found = true
		if v.OwnerTeam != "payments" {
			t.Errorf("OwnerTeam=%q, want payments", v.OwnerTeam)
		}
		if v.OwnerHandle != "@payments" {
			t.Errorf("OwnerHandle=%q, want @payments", v.OwnerHandle)
		}
		if v.OwnerContactURL != "https://example.com/payments" {
			t.Errorf("OwnerContactURL=%q, want https://example.com/payments", v.OwnerContactURL)
		}
	}
	if !found {
		t.Errorf("expected a notify_owner violation in the decision: %+v", dec.Violations)
	}
	if resolver.called == 0 {
		t.Errorf("resolver should have been called for an enforcement decision")
	}
}

func TestNotifyOwnerSkippedWhenAllow(t *testing.T) {
	t.Parallel()
	eng := policyengine.New(policyengine.Config{DSL: loadDSL(t)})
	resolver := &fakeResolver{team: "payments"}
	eng.SetOwnerResolver(resolver)

	// Build a context that doesn't trip the demo Block rule.
	ec := policy.EvaluationContext{
		PackageName:              "harmless",
		PackageVersion:           "1.0.0",
		RepositoryFormat:         "npm",
		Repository:               "acme/payments",
		OrgID:                    "org-1",
		HasInstallScript:         false,
		MaintainerAccountAgeDays: 365,
	}
	dec, err := eng.Decide(context.Background(), policy.SurfaceProxy, ec)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	if dec.Action != dsl.ActionAllow {
		t.Fatalf("expected Allow, got %s", dec.Action)
	}
	for _, v := range dec.Violations {
		if v.Action == dsl.ActionNotifyOwner {
			t.Errorf("notify_owner should not be emitted on Allow decisions")
		}
	}
}

func TestNotifyOwnerSkippedWhenNoResolver(t *testing.T) {
	t.Parallel()
	eng := policyengine.New(policyengine.Config{DSL: loadDSL(t)})
	// No SetOwnerResolver — routing path is a no-op.

	ec := policy.EvaluationContext{
		PackageName:              "evil-foo",
		PackageVersion:           "1.0.0",
		RepositoryFormat:         "npm",
		Repository:               "acme/payments",
		OrgID:                    "org-1",
		HasInstallScript:         true,
		MaintainerAccountAgeDays: 7,
	}
	dec, err := eng.Decide(context.Background(), policy.SurfaceProxy, ec)
	if err != nil {
		t.Fatalf("decide: %v", err)
	}
	for _, v := range dec.Violations {
		if v.Action == dsl.ActionNotifyOwner {
			t.Errorf("notify_owner should not be emitted when no resolver wired: %+v", v)
		}
	}
}
