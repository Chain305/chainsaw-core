package intelligence

import (
	"context"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/supplychain"
)

// fakeRepoLivenessChecker records every Classify call and returns a
// caller-supplied result. The struct is intentionally tiny — no concurrency
// guards because all repolink-provider tests are single-threaded.
type fakeRepoLivenessChecker struct {
	result supplychain.RepoLivenessResult
	calls  []fakeClassifyCall
}

type fakeClassifyCall struct {
	repoURL      string
	publisherIDs []string
}

func (f *fakeRepoLivenessChecker) Classify(_ context.Context, repoURL string, publisherIDs []string) supplychain.RepoLivenessResult {
	f.calls = append(f.calls, fakeClassifyCall{repoURL: repoURL, publisherIDs: append([]string(nil), publisherIDs...)})
	return f.result
}

// TestRepolinkProvider_Tier locks in Tier-3 placement. The maintenance
// enricher (Tier-4) reads this provider's SupplyChain output, so a
// drift to Tier-4 here would silently break that handoff.
func TestRepolinkProvider_Tier(t *testing.T) {
	t.Parallel()
	if got := newRepolinkProvider(nil).Tier(); got != 3 {
		t.Fatalf("Tier() = %d, want 3 (Tier-3 probe whose output Tier-4 maintenance reads)", got)
	}
}

// TestRepolinkProvider_WiresFields locks in the canonical "wire-up the
// previously-orphaned RepoLivenessChecker" assertion: when a non-nil
// checker is supplied and prior carries a SourceRepoURL, the provider
// Classify()s once and projects all three fields onto SupplyChain.
func TestRepolinkProvider_WiresFields(t *testing.T) {
	t.Parallel()
	when := time.Date(2025, 6, 1, 12, 0, 0, 0, time.UTC)
	tru := true
	fake := &fakeRepoLivenessChecker{
		result: supplychain.RepoLivenessResult{
			Status:       supplychain.RepoLinkStatusOK,
			CheckedAt:    time.Now().UTC(),
			LastCommitAt: &when,
			Archived:     &tru,
		},
	}
	prior := &Report{
		Identity: IdentitySection{Package: "left-pad", Version: "1.0.0"},
		URLs:     URLSection{SourceRepoURL: "https://github.com/foo/bar"},
		People:   PeopleSection{PublisherIDs: []string{"alice@example.com"}},
	}
	p := newRepolinkProvider(fake)
	patch, err := p.Run(context.Background(), Request{}, prior)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.calls) != 1 {
		t.Fatalf("Classify call count: got %d, want 1", len(fake.calls))
	}
	if fake.calls[0].repoURL != "https://github.com/foo/bar" {
		t.Errorf("Classify repoURL: got %q, want %q", fake.calls[0].repoURL, "https://github.com/foo/bar")
	}
	if len(fake.calls[0].publisherIDs) != 1 || fake.calls[0].publisherIDs[0] != "alice@example.com" {
		t.Errorf("Classify publisherIDs: got %v, want [alice@example.com]", fake.calls[0].publisherIDs)
	}
	if patch.SupplyChain == nil {
		t.Fatal("SupplyChain patch: got nil, want populated")
	}
	if patch.SupplyChain.RepoLinkStatus != supplychain.RepoLinkStatusOK {
		t.Errorf("RepoLinkStatus: got %q, want %q", patch.SupplyChain.RepoLinkStatus, supplychain.RepoLinkStatusOK)
	}
	if patch.SupplyChain.RepoArchived == nil || *patch.SupplyChain.RepoArchived != true {
		t.Errorf("SupplyChain.RepoArchived: got %v, want &true", patch.SupplyChain.RepoArchived)
	}
	if patch.SupplyChain.RepoLastCommitAt == nil || !patch.SupplyChain.RepoLastCommitAt.Equal(when) {
		t.Errorf("SupplyChain.RepoLastCommitAt: got %v, want %v", patch.SupplyChain.RepoLastCommitAt, when)
	}
	// The Tier-3 repolink provider does NOT touch MaintenanceSection —
	// projection onto MaintenanceSection is the Tier-4 maintenance
	// enricher's job. Verify the boundary is clean.
	if patch.Maintenance != nil {
		t.Errorf("Maintenance patch: got %+v, want nil (Tier-4 maintenance owns this)", patch.Maintenance)
	}
}

// TestRepolinkProvider_SkippedWhenNoURL — the probe is gated on
// prior.URLs.SourceRepoURL (with HomepageURL fallback). When neither
// is set, the checker MUST NOT be called: a 404 against an empty URL
// would burn an outbound request and surface a misleading "missing"
// status.
func TestRepolinkProvider_SkippedWhenNoURL(t *testing.T) {
	t.Parallel()
	fake := &fakeRepoLivenessChecker{
		result: supplychain.RepoLivenessResult{Status: supplychain.RepoLinkStatusOK},
	}
	prior := &Report{
		Identity: IdentitySection{Package: "left-pad", Version: "1.0.0"},
		People:   PeopleSection{Maintainers: []string{"alice"}},
		// URLs intentionally empty.
	}
	p := newRepolinkProvider(fake)
	patch, err := p.Run(context.Background(), Request{}, prior)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("Classify should not be called when no repo URL is present, got %d calls", len(fake.calls))
	}
	if patch.SupplyChain != nil {
		t.Errorf("SupplyChain patch: got %+v, want nil (no probe → nothing to mirror)", patch.SupplyChain)
	}
}

// TestRepolinkProvider_NilCheckerNoPanic — a nil checker is the
// production fallback when the operator disabled liveness. The
// provider must degrade to a no-op cleanly.
func TestRepolinkProvider_NilCheckerNoPanic(t *testing.T) {
	t.Parallel()
	prior := &Report{
		Identity: IdentitySection{Package: "left-pad", Version: "1.0.0"},
		URLs:     URLSection{SourceRepoURL: "https://github.com/foo/bar"},
		People:   PeopleSection{Maintainers: []string{"alice", "bob"}},
	}
	p := newRepolinkProvider(nil)
	patch, err := p.Run(context.Background(), Request{}, prior)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if patch.SupplyChain != nil {
		t.Errorf("SupplyChain patch: got %+v, want nil (no checker)", patch.SupplyChain)
	}
}

// TestRepolinkProvider_HomepageURLFallback — when SourceRepoURL is
// empty but HomepageURL is set, the provider falls through to it
// (some ecosystems blend the two in the manifest).
func TestRepolinkProvider_HomepageURLFallback(t *testing.T) {
	t.Parallel()
	fake := &fakeRepoLivenessChecker{
		result: supplychain.RepoLivenessResult{
			Status:    supplychain.RepoLinkStatusOK,
			CheckedAt: time.Now().UTC(),
		},
	}
	prior := &Report{
		Identity: IdentitySection{Package: "left-pad", Version: "1.0.0"},
		URLs:     URLSection{HomepageURL: "https://github.com/foo/bar"},
	}
	p := newRepolinkProvider(fake)
	if _, err := p.Run(context.Background(), Request{}, prior); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(fake.calls) != 1 || fake.calls[0].repoURL != "https://github.com/foo/bar" {
		t.Fatalf("Classify call: got %+v, want one call with HomepageURL", fake.calls)
	}
}
