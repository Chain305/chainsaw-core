package provenance

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// readSourceFile reads a file from this package's directory (or a
// sibling package via a relative path) for source-level guards.
func readSourceFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Clean(rel))
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	return string(b)
}

// This file guards the defect CLASS behind P8-48's swift half, which is
// not "the swift checker is wrong" — the swift checker is correct — but
// "a correct function whose dependency nobody supplies."
//
// This repo has been bitten by that shape repeatedly: SafeUpgradeVersion
// documented as wired for months while never written, backfillRepositoryGuides
// with no caller, ReapplyKnownFixAfterTransitive needing a source guard.
// A test that iterates the checker table proves the function works and
// says nothing about whether anything ever calls WithSwiftRegistryURL.
// So: assert the composition root at source level, AND assert a
// production-shaped Checker actually reaches a registry once configured.

var (
	// The bootstrap must construct the checker and then hand it the
	// configured registry URL. Both halves matter: a NewChecker with no
	// following WithSwiftRegistryURL is exactly the dead-config bug.
	reBootstrapNewChecker = regexp.MustCompile(`provChecker\s*:=\s*provenance\.NewChecker\(`)
	reBootstrapSwiftURL   = regexp.MustCompile(`provChecker\.WithSwiftRegistryURL\(cfg\.SwiftRegistryURL\)`)
	reBootstrapSwiftVfy   = regexp.MustCompile(`provChecker\.WithSwiftFullVerify\(cfg\.SwiftTrustRoots\)`)
)

// TestSupplyChainBootstrapWiresSwiftRegistryURL is the composition-root
// guard. It fails if someone deletes the call, reorders it before
// construction, or renames the config field without rewiring.
func TestSupplyChainBootstrapWiresSwiftRegistryURL(t *testing.T) {
	const rel = "../supplychain/bootstrap.go"
	src := readSourceFile(t, rel)

	newIdx := reBootstrapNewChecker.FindStringIndex(src)
	if newIdx == nil {
		t.Fatalf("%s: provenance.NewChecker(...) assignment to provChecker not found — "+
			"the guard can no longer see the composition root; update this test deliberately", rel)
	}
	urlIdx := reBootstrapSwiftURL.FindStringIndex(src)
	if urlIdx == nil {
		t.Fatalf("%s: nothing calls provChecker.WithSwiftRegistryURL(cfg.SwiftRegistryURL). "+
			"The swift checker is registered and correct but closes over an empty URL, so "+
			"every swift coordinate returns UNAVAILABLE while SupportsProvenance(\"swift\") "+
			"is true and claim C-073 advertises Swift PM CMS.", rel)
	}
	if urlIdx[0] < newIdx[0] {
		t.Fatalf("%s: WithSwiftRegistryURL is called before the Checker is constructed", rel)
	}
	if reBootstrapSwiftVfy.FindStringIndex(src) == nil {
		t.Errorf("%s: nothing calls provChecker.WithSwiftFullVerify(cfg.SwiftTrustRoots) — "+
			"swift can then only ever reach StatusUnverified", rel)
	}
}

// TestCLIVerifyWiresSwiftRegistryURL — the CLI is the second composition
// root, and it has no config file to read swift_registry_url from. If it
// does not thread --source-url into WithSwiftRegistryURL, `chainsaw
// verify swift ...` can never do anything at all.
func TestCLIVerifyWiresSwiftRegistryURL(t *testing.T) {
	const rel = "../cli/verify.go"
	src := readSourceFile(t, rel)
	if !strings.Contains(src, "checker.WithSwiftRegistryURL(sourceURL)") {
		t.Fatalf("%s: the CLI never configures the Swift registry, so "+
			"`chainsaw verify swift <pkg> <ver>` can never reach a registry", rel)
	}
	if !strings.Contains(src, "requireSourceURL(ecosystem, sourceURL)") {
		t.Fatalf("%s: runVerify no longer refuses a source-aware ecosystem "+
			"invoked without --source-url", rel)
	}
}

// TestProductionBuiltCheckerReportsSwiftConfigured is the behavioural
// half: a Checker built the way production builds one reports swift as
// configured once the URL is supplied, and reaches the registry.
//
// Without this, the source guard above could pass against a
// WithSwiftRegistryURL that no longer feeds the closure.
func TestProductionBuiltCheckerReportsSwiftConfigured(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"resources": []map[string]any{{
				"name": "source-archive",
				"signing": map[string]any{
					"signatureFormat": "cms-1.0.0",
					"signature":       "",
				},
			}},
			"metadata": map[string]any{
				"repositoryURLs": []string{"https://github.com/apple/swift-argument-parser"},
			},
		})
	}))
	defer srv.Close()

	// Unconfigured: inert, and it says why.
	bare := NewChecker(nil)
	if got := bare.Check(context.Background(), "swift", "apple.swift-argument-parser", "1.3.0"); got.Reason != ReasonNotConfigured {
		t.Fatalf("unconfigured swift: Reason = %q, want %q", got.Reason, ReasonNotConfigured)
	}
	if hits != 0 {
		t.Fatalf("unconfigured swift dialled something (%d requests)", hits)
	}

	// Configured the way bootstrap.go configures it.
	c := NewChecker(nil)
	c.WithSwiftRegistryURL(srv.URL)

	got := c.Check(context.Background(), "swift", "apple.swift-argument-parser", "1.3.0")
	if hits == 0 {
		t.Fatalf("configured swift never reached the registry — WithSwiftRegistryURL "+
			"no longer feeds the checker's closure (%+v)", got)
	}
	if got.Status == StatusUnavailable {
		t.Fatalf("configured swift still reports UNAVAILABLE: %+v", got)
	}
	if got.Status != StatusUnverified {
		t.Fatalf("Status = %q, want %q (presence recorded, full CMS verify off)",
			got.Status, StatusUnverified)
	}
	if got.Reason != ReasonPresenceOnly {
		t.Errorf("Reason = %q, want %q", got.Reason, ReasonPresenceOnly)
	}
	if got.AttestationType != "cms-se0391" {
		t.Errorf("AttestationType = %q, want %q", got.AttestationType, "cms-se0391")
	}
}
