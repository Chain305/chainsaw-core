package intelligence

import (
	"context"
	"testing"
)

// tieredFakeProvider is a synthetic provider that lets the tier-ordering
// tests assert "Tier-N saw what Tier-(N-1) wrote". It captures the
// `prior` argument passed to Run so the test can verify what was
// merged into the Report by the time this provider executed.
type tieredFakeProvider struct {
	name    string
	signal  SignalMask
	tier    int
	partial PartialReport
	// observed is set during Run — the test reads it after Scan returns.
	observed func(prior *Report)
}

func (p *tieredFakeProvider) Name() string           { return p.name }
func (p *tieredFakeProvider) Signal() SignalMask     { return p.signal }
func (p *tieredFakeProvider) Tier() int              { return p.tier }
func (p *tieredFakeProvider) NeedsArtifact() bool    { return false }
func (p *tieredFakeProvider) Supports(_ string) bool { return true }
func (p *tieredFakeProvider) Run(_ context.Context, _ Request, prior *Report) (PartialReport, error) {
	if p.observed != nil {
		p.observed(prior)
	}
	return p.partial, nil
}

// TestScan_Tier4SeesTier3Output is the canonical lock-in for the
// fourth-tier dispatch. A synthetic Tier-3 provider writes a marker
// onto SupplyChain. A synthetic Tier-4 provider records the `prior`
// it observed at Run time. After Scan, the test asserts the marker is
// present in what Tier-4 saw — i.e. Tier-3 merged before Tier-4
// started. Without the post-Tier-3 merge step, Tier-4 would race
// alongside Tier-3 and observe an empty SupplyChain.
func TestScan_Tier4SeesTier3Output(t *testing.T) {
	t.Parallel()

	tier3 := &tieredFakeProvider{
		name:   "fake-tier3",
		signal: SignalMaintenance,
		tier:   3,
		partial: PartialReport{
			SupplyChain: &SupplyChainSection{RepoLinkStatus: "ok"},
		},
	}

	var observedStatus string
	tier4 := &tieredFakeProvider{
		name:   "fake-tier4",
		signal: SignalMaintenance,
		tier:   4,
		observed: func(prior *Report) {
			if prior != nil {
				observedStatus = prior.SupplyChain.RepoLinkStatus
			}
		},
	}

	svc := New(Config{Providers: []Provider{tier3, tier4}})
	if _, err := svc.Scan(context.Background(), Request{
		Key:   Key{Ecosystem: "npm", Package: "demo", Version: "1.0.0"},
		OrgID: "org-default",
	}); err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if observedStatus != "ok" {
		t.Fatalf("Tier-4 observed RepoLinkStatus = %q, want %q (Tier-3 output must be visible to Tier-4)", observedStatus, "ok")
	}
}

// TestScan_Tier3SiblingsDoNotSeeEachOther — preserve the existing
// contract: within a single tier, providers fan out in parallel and
// MUST NOT see each other's writes. Without this, the prior-batch
// "collapse repolink into maintenance" workaround wouldn't have been
// necessary, and the Tier-4 layer wouldn't be needed either.
func TestScan_Tier3SiblingsDoNotSeeEachOther(t *testing.T) {
	t.Parallel()

	writer := &tieredFakeProvider{
		name:   "fake-tier3-writer",
		signal: SignalMaintenance,
		tier:   3,
		partial: PartialReport{
			SupplyChain: &SupplyChainSection{RepoLinkStatus: "ok"},
		},
	}
	var observedStatus string
	reader := &tieredFakeProvider{
		name:   "fake-tier3-reader",
		signal: SignalMaintenance,
		tier:   3,
		observed: func(prior *Report) {
			if prior != nil {
				observedStatus = prior.SupplyChain.RepoLinkStatus
			}
		},
	}

	svc := New(Config{Providers: []Provider{writer, reader}})
	if _, err := svc.Scan(context.Background(), Request{
		Key:   Key{Ecosystem: "npm", Package: "demo", Version: "1.0.0"},
		OrgID: "org-default",
	}); err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if observedStatus != "" {
		t.Fatalf("sibling Tier-3 reader observed RepoLinkStatus = %q, want empty (intra-tier providers must not see each other)", observedStatus)
	}
}
