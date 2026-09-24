package intelligence

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
)

// callerRecordingProvider emits one pinned dependency (so a Scan triggers the
// cache-warm) and records the egress caller every run arrived with.
type callerRecordingProvider struct {
	mu      sync.Mutex
	callers []string
}

func (p *callerRecordingProvider) Name() string         { return "caller-recorder" }
func (p *callerRecordingProvider) Signal() SignalMask   { return SignalMalware }
func (p *callerRecordingProvider) Tier() int            { return 1 }
func (p *callerRecordingProvider) NeedsArtifact() bool  { return false }
func (p *callerRecordingProvider) Supports(string) bool { return true }
func (p *callerRecordingProvider) Run(ctx context.Context, req Request, _ *Report) (PartialReport, error) {
	p.mu.Lock()
	p.callers = append(p.callers, httpclient.EgressCallerFrom(ctx))
	p.mu.Unlock()
	if req.Key.Package != "parent" {
		return PartialReport{}, nil
	}
	return PartialReport{Dependencies: &DependenciesSection{
		Direct: []DependencyRef{{Name: "lodash", Constraint: "4.17.21"}},
	}}, nil
}

func (p *callerRecordingProvider) snapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.callers...)
}

// declared_inventory D-2 divides refresh egress by refreshed coordinates. The
// cache-warm runs on the service's own background context, so without carrying
// the tag across, every request a refresher-triggered warm makes would be
// counted as customer traffic and the per-coordinate cost understated.
func TestCacheWarmKeepsTheEgressCaller(t *testing.T) {
	prov := &callerRecordingProvider{}
	svc := New(Config{Providers: []Provider{prov}})
	defer svc.Close()

	ctx := httpclient.WithEgressCaller(context.Background(), httpclient.EgressCallerRefresh)
	if _, err := svc.Scan(ctx, Request{Key: Key{Ecosystem: "npm", Package: "parent", Version: "1.0.0"}}); err != nil {
		t.Fatalf("scan: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && len(prov.snapshot()) < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	got := prov.snapshot()
	if len(got) < 2 {
		t.Fatalf("the warm never ran: provider saw %d runs, want 2 (parent + warmed dependency)", len(got))
	}
	for i, c := range got {
		if c != httpclient.EgressCallerRefresh {
			t.Errorf("run %d had egress caller %q, want %q — the warm dropped the tag", i, c, httpclient.EgressCallerRefresh)
		}
	}
}

// The refresher is the one caller that tags itself: every Scan a tick issues
// must arrive tagged, or none of its egress is attributed to refresh at all.
func TestRefresherTagsItsEgress(t *testing.T) {
	resetStaleReportMetrics()
	t.Cleanup(resetStaleReportMetrics)

	var mu sync.Mutex
	var callers []string
	svc := &fakeService{onScan: nil}
	src := &fakeStaleSource{rows: staleRows(3)}
	ref := NewRefresher(RefresherConfig{
		Service:                   svc,
		Metadata:                  &fakeMetadataSource{},
		MaxStaleness:              24 * time.Hour,
		Concurrency:               1,
		PageSize:                  50,
		StaleReportRefreshEnabled: true,
		StaleReportSource:         src,
		ArtifactEnabled:           true,
		EcosystemResolver:         func(string) string { return "go" },
		StaleReportArtifactFetcher: func(ctx context.Context, _, _, _ string) (*ArtifactHandle, error) {
			mu.Lock()
			callers = append(callers, httpclient.EgressCallerFrom(ctx))
			mu.Unlock()
			return nil, nil
		},
	})
	ref.RunOnce(context.Background())

	if len(callers) != 3 {
		t.Fatalf("artifact fetcher called %d times, want 3", len(callers))
	}
	for _, c := range callers {
		if c != httpclient.EgressCallerRefresh {
			t.Errorf("refresher egress tagged %q, want %q", c, httpclient.EgressCallerRefresh)
		}
	}
}
