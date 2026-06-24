package policy

import (
	"strings"
	"testing"
	"time"
)

func TestMatchesIPListSupportsExactAndCIDR(t *testing.T) {
	t.Parallel()

	if !matchesIPList("192.168.0.10", []string{"192.168.0.10"}) {
		t.Fatalf("expected exact IPv4 match")
	}
	if !matchesIPList("2001:db8::1", []string{"2001:db8::1"}) {
		t.Fatalf("expected exact IPv6 match")
	}
	if !matchesIPList("10.2.3.4", []string{"10.0.0.0/8"}) {
		t.Fatalf("expected CIDR match")
	}
	if matchesIPList("192.168.0.10", []string{"10.0.0.0/8"}) {
		t.Fatalf("did not expect non-matching CIDR to match")
	}
}

func TestMatchesScopeSupportsCountryAndLegacyWildcards(t *testing.T) {
	t.Parallel()

	if !matchesScope(EvaluationContext{}, Scope{TargetRequestingCountry: []string{"all"}}) {
		t.Fatalf("expected legacy country wildcard to behave as unrestricted")
	}
	if !matchesScope(EvaluationContext{}, Scope{TargetRequestingIP: []string{"*"}}) {
		t.Fatalf("expected legacy IP wildcard to behave as unrestricted")
	}
	if !matchesScope(EvaluationContext{RequestingCountry: "gb"}, Scope{TargetRequestingCountry: []string{"GB"}}) {
		t.Fatalf("expected case-insensitive country match")
	}
}

func TestMatchesLicenseConditionSupportsSPDXExpressions(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		policy   []string
		resolved string
		want     bool
	}{
		{
			name:     "exact single license",
			policy:   []string{"MIT"},
			resolved: "MIT",
			want:     true,
		},
		{
			name:     "or expression matches token",
			policy:   []string{"Apache-2.0"},
			resolved: "(MIT OR Apache-2.0)",
			want:     true,
		},
		{
			name:     "and expression matches token",
			policy:   []string{"GPL-3.0-only"},
			resolved: "MIT AND GPL-3.0-only",
			want:     true,
		},
		{
			name:     "with exception still matches base license",
			policy:   []string{"GPL-2.0-or-later"},
			resolved: "GPL-2.0-or-later WITH Classpath-exception-2.0",
			want:     true,
		},
		{
			name:     "empty resolved license does not match",
			policy:   []string{"MIT"},
			resolved: "",
			want:     false,
		},
		{
			name:     "non matching token stays false",
			policy:   []string{"BSD-3-Clause"},
			resolved: "(MIT OR Apache-2.0)",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := matchesLicenseCondition(tt.policy, tt.resolved); got != tt.want {
				t.Fatalf("matchesLicenseCondition(%v, %q) = %v, want %v", tt.policy, tt.resolved, got, tt.want)
			}
		})
	}
}

func boolPtr(v bool) *bool           { return &v }
func floatPtr(v float64) *float64    { return &v }
func timePtr(v time.Time) *time.Time { return &v }

func TestIsExpiredException(t *testing.T) {
	t.Parallel()
	now := time.Now()

	tests := []struct {
		name    string
		policy  Policy
		ageDays int
		want    bool
	}{
		{
			name: "expired exception",
			policy: Policy{
				Mode:       ModeAllow,
				Conditions: Conditions{IsVulnerable: boolPtr(true)},
				CreatedAt:  now.Add(-100 * 24 * time.Hour),
			},
			ageDays: 90,
			want:    true,
		},
		{
			name: "active exception",
			policy: Policy{
				Mode:       ModeAllow,
				Conditions: Conditions{IsVulnerable: boolPtr(true)},
				CreatedAt:  now.Add(-50 * 24 * time.Hour),
			},
			ageDays: 90,
			want:    false,
		},
		{
			name: "block policy not subject to expiry",
			policy: Policy{
				Mode:       ModeBlock,
				Conditions: Conditions{IsVulnerable: boolPtr(true)},
				CreatedAt:  now.Add(-100 * 24 * time.Hour),
			},
			ageDays: 90,
			want:    false,
		},
		{
			name: "allow without isVulnerable not subject to expiry",
			policy: Policy{
				Mode:       ModeAllow,
				Conditions: Conditions{},
				CreatedAt:  now.Add(-100 * 24 * time.Hour),
			},
			ageDays: 90,
			want:    false,
		},
		{
			name: "expiry disabled when ageDays is zero",
			policy: Policy{
				Mode:       ModeAllow,
				Conditions: Conditions{IsVulnerable: boolPtr(true)},
				CreatedAt:  now.Add(-100 * 24 * time.Hour),
			},
			ageDays: 0,
			want:    false,
		},
		{
			name: "boundary: exactly at age limit is expired",
			policy: Policy{
				Mode:       ModeAllow,
				Conditions: Conditions{IsVulnerable: boolPtr(true)},
				CreatedAt:  now.Add(-90*24*time.Hour - time.Second),
			},
			ageDays: 90,
			want:    true,
		},
		// KindException paths — post-fix exceptions don't carry the
		// legacy IsVulnerable=true sentinel. Without the Kind branch
		// added in the malware-bypass fix, these would all return
		// false (never expire), which would silently mean exceptions
		// created via the new code path never aged out.
		{
			name: "kind=exception expires under ageDays",
			policy: Policy{
				Mode:      ModeAllow,
				Kind:      KindException,
				CreatedAt: now.Add(-100 * 24 * time.Hour),
			},
			ageDays: 90,
			want:    true,
		},
		{
			name: "kind=exception still active inside window",
			policy: Policy{
				Mode:      ModeAllow,
				Kind:      KindException,
				CreatedAt: now.Add(-30 * 24 * time.Hour),
			},
			ageDays: 90,
			want:    false,
		},
		// Per-row ExpiresAt override — wins over ageDays entirely.
		{
			name: "per-row ExpiresAt in the past => expired",
			policy: Policy{
				Mode:      ModeAllow,
				Kind:      KindException,
				CreatedAt: now,
				ExpiresAt: timePtr(now.Add(-1 * time.Hour)),
			},
			ageDays: 999, // would say active under legacy, but override wins
			want:    true,
		},
		{
			name: "per-row ExpiresAt in the future => active",
			policy: Policy{
				Mode:      ModeAllow,
				Kind:      KindException,
				CreatedAt: now.Add(-1000 * 24 * time.Hour),
				ExpiresAt: timePtr(now.Add(48 * time.Hour)),
			},
			ageDays: 90, // would say expired under legacy, but override wins
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := IsExpiredException(tt.policy, tt.ageDays, now); got != tt.want {
				t.Fatalf("IsExpiredException() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestEvaluatePoliciesKindException_BypassesMalwareBlock is the
// unit-level guarantee for the malware-bypass fix. A KindException
// allow-rule at the lowest precedence MUST win against a later
// IsKnownMalicious-driven block — regardless of whether the context
// carries IsVulnerable=true. Pre-fix the exception was created with
// Conditions.IsVulnerable=true (and no Kind), so it required
// ctx.IsVulnerable=true to match — silently letting malware blocks
// (which fire on IsKnownMalicious) sail through. See
// internal/server/exception_bypass_e2e_test.go for the E2E
// counterpart that exercises the full HTTP path.
func TestEvaluatePoliciesKindException_BypassesMalwareBlock(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)
	isMaliciousTrue := true
	policies := []Policy{
		{
			ID:         "exception-evil-1.0",
			Precedence: -1, // exceptions sort before user-defined policies
			Mode:       ModeAllow,
			Kind:       KindException,
			Status:     StatusEnabled,
			Identifier: Identifier{
				TargetPackageRepo:    "npmjs",
				TargetPackageName:    "evil-pkg",
				TargetPackageVersion: "1.0.0",
			},
			// Crucially: NO IsVulnerable=true here. Pre-fix this
			// condition was required and is what silently broke
			// malware-feed bypasses.
			Conditions: Conditions{},
		},
		{
			ID:         "block-known-malware",
			Precedence: 100,
			Mode:       ModeBlock,
			Status:     StatusEnabled,
			Identifier: Identifier{
				TargetPackageRepo:    "*",
				TargetPackageName:    "*",
				TargetPackageVersion: "*",
			},
			Conditions: Conditions{IsKnownMalicious: &isMaliciousTrue},
		},
	}

	ctx := EvaluationContext{
		Repository:       "npmjs",
		PackageName:      "evil-pkg",
		PackageVersion:   "1.0.0",
		IsKnownMalicious: true,
		IsVulnerable:     false, // the legacy sentinel is OFF
	}
	result := evaluator.EvaluateWithPolicies(ctx, policies, 0)
	if result.Action != ModeAllow {
		t.Fatalf("expected exception to bypass malware block (ModeAllow), got %s matched=%+v",
			result.Action, result.MatchedPolicy)
	}
	if result.MatchedPolicy == nil || result.MatchedPolicy.ID != "exception-evil-1.0" {
		t.Fatalf("expected the KindException rule to match, got %+v", result.MatchedPolicy)
	}

	// Different coordinate: the exception is identifier-scoped, so
	// the malware block must still fire.
	other := ctx
	other.PackageName = "other-pkg"
	res2 := evaluator.EvaluateWithPolicies(other, policies, 0)
	if res2.Action != ModeBlock {
		t.Fatalf("expected non-excepted package to be blocked, got %s", res2.Action)
	}
}

func TestEvaluatePoliciesMonitorMatch(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)

	policies := []Policy{
		{
			ID:         "monitor-high-cvss",
			Precedence: 10,
			Mode:       ModeMonitor,
			Status:     StatusEnabled,
			Conditions: Conditions{CVSSMin: floatPtr(7.0)},
		},
	}

	ctx := EvaluationContext{
		PackageName:    "leftpad",
		PackageVersion: "1.0.0",
		IsVulnerable:   true,
		CVSSScore:      8.5,
	}

	result := evaluator.EvaluateWithPolicies(ctx, policies, 0)
	if result.Action != ModeMonitor {
		t.Fatalf("expected monitor action, got %s", result.Action)
	}
	if result.MatchedPolicy == nil || result.MatchedPolicy.ID != "monitor-high-cvss" {
		t.Fatalf("expected monitor-high-cvss to match, got %#v", result.MatchedPolicy)
	}
	if !strings.Contains(result.Reason, "monitor-high-cvss") {
		t.Fatalf("expected reason to reference matched policy id, got %q", result.Reason)
	}
	if !strings.HasPrefix(result.Reason, "monitored by policy") {
		t.Fatalf("expected reason to start with 'monitored by policy', got %q", result.Reason)
	}
}

func TestEvaluatePoliciesFirstMatchWinsAcrossModes(t *testing.T) {
	t.Parallel()

	evaluator := NewEvaluator(nil)

	// Monitor at precedence 10 should win over Block at precedence 100
	// because policies are evaluated first-match-wins by ascending
	// precedence. This encodes the contract that Monitor does NOT
	// automatically yield to Block — precedence is the only tiebreaker.
	policies := []Policy{
		{
			ID:         "monitor-all-vulnerable",
			Precedence: 10,
			Mode:       ModeMonitor,
			Status:     StatusEnabled,
			Conditions: Conditions{IsVulnerable: boolPtr(true)},
		},
		{
			ID:         "block-all-vulnerable",
			Precedence: 100,
			Mode:       ModeBlock,
			Status:     StatusEnabled,
			Conditions: Conditions{IsVulnerable: boolPtr(true)},
		},
	}

	ctx := EvaluationContext{
		PackageName:    "axios",
		PackageVersion: "1.1.2",
		IsVulnerable:   true,
	}

	result := evaluator.EvaluateWithPolicies(ctx, policies, 0)
	if result.Action != ModeMonitor {
		t.Fatalf("expected monitor to win (lower precedence), got %s", result.Action)
	}
	if result.MatchedPolicy == nil || result.MatchedPolicy.ID != "monitor-all-vulnerable" {
		t.Fatalf("expected monitor-all-vulnerable to win, got %#v", result.MatchedPolicy)
	}

	// Reorder: Block first (precedence 10), Monitor last (precedence 100).
	// The evaluator requires a pre-sorted precedence-ascending slice, mirroring
	// Store.List ordering. Now Block should win under first-match-wins.
	swapped := []Policy{
		{
			ID:         "block-all-vulnerable",
			Precedence: 10,
			Mode:       ModeBlock,
			Status:     StatusEnabled,
			Conditions: Conditions{IsVulnerable: boolPtr(true)},
		},
		{
			ID:         "monitor-all-vulnerable",
			Precedence: 100,
			Mode:       ModeMonitor,
			Status:     StatusEnabled,
			Conditions: Conditions{IsVulnerable: boolPtr(true)},
		},
	}
	result = evaluator.EvaluateWithPolicies(ctx, swapped, 0)
	if result.Action != ModeBlock {
		t.Fatalf("expected block to win after precedence swap, got %s", result.Action)
	}
	if result.MatchedPolicy == nil || result.MatchedPolicy.ID != "block-all-vulnerable" {
		t.Fatalf("expected block-all-vulnerable to win, got %#v", result.MatchedPolicy)
	}
}

func TestEvaluatePoliciesSkipsExpiredExceptions(t *testing.T) {
	t.Parallel()
	now := time.Now()

	evaluator := NewEvaluator(nil)

	// Expired exception (precedence 0) should be skipped, so block policy (precedence 1) fires.
	policies := []Policy{
		{
			ID:         "expired-exception",
			Precedence: 0,
			Mode:       ModeAllow,
			Status:     StatusEnabled,
			CreatedAt:  now.Add(-100 * 24 * time.Hour),
			Conditions: Conditions{IsVulnerable: boolPtr(true)},
			Identifier: Identifier{TargetPackageName: "hoek", TargetPackageVersion: "4.1.0"},
		},
		{
			ID:         "block-vulnerable",
			Precedence: 1,
			Mode:       ModeBlock,
			Status:     StatusEnabled,
			Conditions: Conditions{IsVulnerable: boolPtr(true)},
		},
	}

	ctx := EvaluationContext{
		PackageName:    "hoek",
		PackageVersion: "4.1.0",
		IsVulnerable:   true,
	}

	result := evaluator.EvaluateWithPolicies(ctx, policies, 90)
	if result.Action != ModeBlock {
		t.Fatalf("expected block (expired exception skipped), got %s", result.Action)
	}
	if result.MatchedPolicy == nil || result.MatchedPolicy.ID != "block-vulnerable" {
		t.Fatalf("expected block-vulnerable policy to match")
	}

	// Same scenario but with expiry disabled: exception should match.
	result = evaluator.EvaluateWithPolicies(ctx, policies, 0)
	if result.Action != ModeAllow {
		t.Fatalf("expected allow (expiry disabled), got %s", result.Action)
	}

	// Active exception should match normally.
	policies[0].CreatedAt = now.Add(-50 * 24 * time.Hour)
	result = evaluator.EvaluateWithPolicies(ctx, policies, 90)
	if result.Action != ModeAllow {
		t.Fatalf("expected allow (active exception), got %s", result.Action)
	}
}
