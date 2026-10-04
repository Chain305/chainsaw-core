package intelligence

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/risk"
	"github.com/chain305/chainsaw-core/supplychain"
)

// A repo check that was attempted and failed must say so. Before, it wrote
// nothing, and the row looked exactly like a package with no repo URL while
// sc.repo_archived / sc.repo_missing silently did not run.
func TestRepolinkUnknownIsVisibleAndNotMissing(t *testing.T) {
	t.Parallel()
	prior := func() *Report {
		return &Report{
			Identity: IdentitySection{Ecosystem: "npm", Package: "chalk", Version: "5.3.0"},
			URLs:     URLSection{SourceRepoURL: "https://github.com/chalk/chalk"},
		}
	}

	// Through the real checker: GitHub's budget answer, 403 with
	// X-RateLimit-Remaining: 0.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "0")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
	}))
	defer srv.Close()
	checker := supplychain.NewRepoLivenessChecker(&http.Client{Timeout: 5 * time.Second}, nil,
		supplychain.WithAPIBaseOverride("github", srv.URL))
	pr, err := newRepolinkProvider(checker, 0).Run(context.Background(), Request{}, prior())
	if err != nil {
		t.Fatal(err)
	}
	if pr.SupplyChain != nil {
		t.Errorf("a failed check wrote SupplyChain %+v; unknown is not a status to persist", *pr.SupplyChain)
	}
	if len(pr.Warnings) != 1 || pr.Warnings[0].Provider != "repolink" || pr.Warnings[0].Code != WarnRepoCheckRateLimited {
		t.Fatalf("warnings = %+v, want one repolink %s", pr.Warnings, WarnRepoCheckRateLimited)
	}

	// The report carrying that warning fires neither repo signal.
	r := prior()
	r.Observation.Warnings = pr.Warnings
	fired := map[string]bool{}
	for _, c := range risk.EvaluatePackage(ProjectToRiskInput(r), risk.Options{}).DirectScore.Categories {
		for _, f := range c.FiredSignals {
			fired[f.ID] = true
		}
	}
	for _, id := range []string{"sc.repo_missing", "sc.repo_missing_established", "sc.repo_archived"} {
		if fired[id] {
			t.Errorf("%s fired on a check that never completed", id)
		}
	}

	for _, tc := range []struct {
		reason, want string
	}{
		{supplychain.UnknownTransport, WarnRepoCheckUnavailable},
		{supplychain.UnknownHTTP, WarnRepoCheckUnavailable},
		{"", ""}, // an unrecognised host was never probed: silent, like no repo
	} {
		fake := &fakeRepoLivenessChecker{result: supplychain.RepoLivenessResult{
			Status: supplychain.RepoLinkStatusUnknown, CheckedAt: time.Now(), UnknownReason: tc.reason}}
		pr, _ := newRepolinkProvider(fake, 0).Run(context.Background(), Request{}, prior())
		got := ""
		if len(pr.Warnings) == 1 {
			got = pr.Warnings[0].Code
		}
		if got != tc.want || len(pr.Warnings) > 1 {
			t.Errorf("reason %q: warnings %+v, want code %q", tc.reason, pr.Warnings, tc.want)
		}
	}
}

// A transient failure must not erase the stored answer: the provider emits
// no status, so the sticky merge keeps a stored "archived".
func TestRepolinkUnknownKeepsTheStoredStatus(t *testing.T) {
	t.Parallel()
	next := &Report{Observation: ObservationSection{Warnings: []Warning{{Provider: "repolink", Code: WarnRepoCheckRateLimited}}}}
	stored := &Report{SupplyChain: SupplyChainSection{RepoLinkStatus: supplychain.RepoLinkStatusArchived}}
	applyStickySupplyChain(next, stored)
	if next.SupplyChain.RepoLinkStatus != supplychain.RepoLinkStatusArchived {
		t.Errorf("stored archived lost on a rate-limited recheck: %q", next.SupplyChain.RepoLinkStatus)
	}
}
