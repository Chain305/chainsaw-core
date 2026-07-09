package policy

import (
	"context"
	"testing"

	"github.com/chain305/chainsaw-core/codeowners"
)

type captureDispatcher struct {
	calls []capturedDispatch
}

type capturedDispatch struct {
	violation RoutingViolation
	match     RoutingMatch
}

func (c *captureDispatcher) DispatchRouting(_ context.Context, v RoutingViolation, m RoutingMatch) error {
	c.calls = append(c.calls, capturedDispatch{violation: v, match: m})
	return nil
}

func TestEvaluateRouting_PathGlobMatch_DispatchesWithOwners(t *testing.T) {
	mappings, err := codeowners.Parse([]byte("/services/payments/ @acme/payments-team\n"))
	if err != nil {
		t.Fatalf("parse codeowners: %v", err)
	}
	index := NewMappingsIndex()
	index.Set("org-1", "github.com/acme/monorepo", mappings)

	policies := []Policy{{
		ID:     "pol-routing-1",
		Mode:   ModeMonitor,
		Status: StatusEnabled,
		Kind:   KindRouting,
		Routing: &RoutingRule{
			PathGlob: "/services/payments/**",
			Notify:   "codeowners",
		},
	}}

	disp := &captureDispatcher{}
	matches := EvaluateRouting(context.Background(), policies, RoutingViolation{
		OrgID:       "org-1",
		Repository:  "github.com/acme/monorepo",
		PackageName: "stripe",
		LogicalPath: "services/payments/checkout.go",
	}, index, disp)
	if len(matches) != 1 {
		t.Fatalf("want 1 match, got %d", len(matches))
	}
	if matches[0].PolicyID != "pol-routing-1" {
		t.Errorf("policy id mismatch: %q", matches[0].PolicyID)
	}
	if got := matches[0].Owners; len(got) != 1 || got[0] != "@acme/payments-team" {
		t.Errorf("owner resolution failed: %v", got)
	}
	if len(disp.calls) != 1 {
		t.Fatalf("dispatcher called %d times, want 1", len(disp.calls))
	}
	if disp.calls[0].match.Rule.PathGlob != "/services/payments/**" {
		t.Errorf("rule body not propagated through dispatcher: %+v", disp.calls[0].match.Rule)
	}
	if disp.calls[0].violation.PackageName != "stripe" {
		t.Errorf("violation package mismatch: %q", disp.calls[0].violation.PackageName)
	}
}

func TestEvaluateRouting_PackagePatternMatch_NoOwnersWhenPathEmpty(t *testing.T) {
	policies := []Policy{{
		ID:     "pol-routing-pkg",
		Mode:   ModeMonitor,
		Status: StatusEnabled,
		Kind:   KindRouting,
		Routing: &RoutingRule{
			PackagePattern: "lodash*",
			Notify:         "codeowners",
		},
	}}
	disp := &captureDispatcher{}
	matches := EvaluateRouting(context.Background(), policies, RoutingViolation{
		OrgID:       "org-1",
		Repository:  "npm-proxy",
		PackageName: "lodash-es",
		// No LogicalPath — package-only matches still fire, owners stay empty.
	}, nil, disp)
	if len(matches) != 1 {
		t.Fatalf("want 1 match, got %d", len(matches))
	}
	if len(matches[0].Owners) != 0 {
		t.Errorf("expected no owners when path absent and index nil, got %v", matches[0].Owners)
	}
}

func TestEvaluateRouting_DisabledRuleSkipped(t *testing.T) {
	policies := []Policy{{
		ID:     "pol-disabled",
		Mode:   ModeMonitor,
		Status: StatusDisabled,
		Kind:   KindRouting,
		Routing: &RoutingRule{
			PackagePattern: "*",
		},
	}}
	disp := &captureDispatcher{}
	matches := EvaluateRouting(context.Background(), policies, RoutingViolation{
		OrgID:       "org-1",
		PackageName: "anything",
	}, nil, disp)
	if len(matches) != 0 {
		t.Fatalf("disabled rule should not fire, got %d matches", len(matches))
	}
	if len(disp.calls) != 0 {
		t.Fatalf("disabled rule should not dispatch, got %d calls", len(disp.calls))
	}
}

func TestEvaluateRouting_EnforcementPoliciesIgnored(t *testing.T) {
	policies := []Policy{
		{
			ID:     "pol-enforce",
			Mode:   ModeBlock,
			Status: StatusEnabled,
			// Kind == KindEnforcement (empty) — must be skipped by the
			// routing evaluator regardless of any Routing body.
			Routing: &RoutingRule{PackagePattern: "*"},
			Conditions: Conditions{
				IsKnownMalicious: boolPtr(true),
			},
		},
	}
	disp := &captureDispatcher{}
	matches := EvaluateRouting(context.Background(), policies, RoutingViolation{
		OrgID:       "org-1",
		PackageName: "anything",
	}, nil, disp)
	if len(matches) != 0 {
		t.Fatalf("enforcement policy should not fire as routing, got %d matches", len(matches))
	}
}

func TestValidatePolicy_RoutingRequiresMatcher(t *testing.T) {
	pol := Policy{
		Mode:    ModeMonitor,
		Status:  StatusEnabled,
		Kind:    KindRouting,
		Routing: &RoutingRule{Notify: "codeowners"},
	}
	if err := validatePolicy(pol); err == nil {
		t.Fatal("validatePolicy should reject routing rule with no matcher")
	}
	pol.Routing.PathGlob = "/services/**"
	if err := validatePolicy(pol); err != nil {
		t.Fatalf("validatePolicy rejected legal routing rule: %v", err)
	}
}

func TestValidatePolicy_RoutingRejectsBogusNotify(t *testing.T) {
	pol := Policy{
		Mode:   ModeMonitor,
		Status: StatusEnabled,
		Kind:   KindRouting,
		Routing: &RoutingRule{
			PackagePattern: "*",
			Notify:         "slack",
		},
	}
	if err := validatePolicy(pol); err == nil {
		t.Fatal("validatePolicy should reject unknown notify channel")
	}
}
