package policy

import (
	"testing"
	"time"
)

// BenchmarkEvaluateWithPolicies measures the in-memory policy evaluation
// hot path. The store-backed Evaluate variant is dominated by a SQL round
// trip which we exclude here so the benchmark reflects what production
// callers reuse via the cached-store fast path.
//
// p99 target: <5ms — measure with: go test -bench=. -benchtime=10s -count=5
func BenchmarkEvaluateWithPolicies(b *testing.B) {
	evaluator := NewEvaluator(nil)

	// A representative policy bundle: a few exceptions, two
	// supply-chain guards, and a default block with realistic field
	// shapes. ~10 policies is the common production case.
	releasedAge := 30
	cvssMin := 7.0
	trustMin := 50
	provTrue := true
	maliciousTrue := true
	typosquatTrue := true
	vulnerableTrue := true

	policies := []Policy{
		{
			ID: "exception-axios-cve", Precedence: 1, Mode: ModeAllow, Status: StatusEnabled,
			CreatedAt:  time.Now().Add(-15 * 24 * time.Hour),
			Identifier: Identifier{TargetPackageName: "axios", TargetPackageVersion: ">=1.0.0"},
			Conditions: Conditions{IsVulnerable: &vulnerableTrue},
		},
		{
			ID: "block-known-malicious", Precedence: 5, Mode: ModeBlock, Status: StatusEnabled,
			Conditions: Conditions{IsKnownMalicious: &maliciousTrue},
		},
		{
			ID: "block-typosquat", Precedence: 6, Mode: ModeBlock, Status: StatusEnabled,
			Conditions: Conditions{IsSuspectedTyposquat: &typosquatTrue},
		},
		{
			ID: "quarantine-young-pkgs", Precedence: 10, Mode: ModeQuarantine, Status: StatusEnabled,
			Conditions: Conditions{PackageAge: &releasedAge},
		},
		{
			ID: "block-high-cvss", Precedence: 20, Mode: ModeBlock, Status: StatusEnabled,
			Conditions: Conditions{CVSSMin: &cvssMin},
		},
		{
			ID: "monitor-low-trust", Precedence: 25, Mode: ModeMonitor, Status: StatusEnabled,
			Conditions: Conditions{TrustScoreMax: &trustMin},
		},
		{
			ID: "block-no-provenance", Precedence: 30, Mode: ModeBlock, Status: StatusEnabled,
			Conditions: Conditions{HasProvenance: &provTrue},
		},
		{
			ID: "block-restricted-scope", Precedence: 40, Mode: ModeBlock, Status: StatusEnabled,
			Conditions: Conditions{ReservedNamespaces: []string{"@internal/*", "com.acme."}},
		},
		{
			ID: "license-allowlist", Precedence: 50, Mode: ModeAllow, Status: StatusEnabled,
			Conditions: Conditions{PackageLicense: []string{"MIT", "Apache-2.0", "BSD-3-Clause"}},
		},
		{
			ID: "default-allow", Precedence: 100, Mode: ModeAllow, Status: StatusEnabled,
		},
	}

	released := time.Now().Add(-180 * 24 * time.Hour)
	ctx := EvaluationContext{
		Repository:         "npm-proxy",
		RepositoryFormat:   "npm",
		PackageName:        "lodash",
		PackageVersion:     "4.17.21",
		ClientID:           "ci-runner-7",
		ClientGroups:       []string{"developers", "ci"},
		RequestingIP:       "10.0.4.22",
		RequestingCountry:  "US",
		PackageReleaseDate: &released,
		LicenseSPDX:        "MIT",
		HasProvenance:      true,
		TrustScore:         82,
		CVSSScore:          3.1,
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = evaluator.EvaluateWithPolicies(ctx, policies, 90)
	}
}
