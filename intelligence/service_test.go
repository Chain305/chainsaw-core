package intelligence

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeProvider records run count + returns a fixed PartialReport. Used
// to drive the Scan-pipeline tests without touching real upstreams.
type fakeProvider struct {
	name       string
	signal     SignalMask
	needsArt   bool
	ecosystems map[string]bool
	partial    PartialReport
	err        error
	runs       int64
	delay      time.Duration
}

func (f *fakeProvider) Name() string        { return f.name }
func (f *fakeProvider) Signal() SignalMask  { return f.signal }
func (f *fakeProvider) Tier() int           { return 1 }
func (f *fakeProvider) NeedsArtifact() bool { return f.needsArt }
func (f *fakeProvider) Supports(ecosystem string) bool {
	if f.ecosystems == nil {
		return true
	}
	return f.ecosystems[ecosystem]
}
func (f *fakeProvider) Run(ctx context.Context, req Request, _ *Report) (PartialReport, error) {
	atomic.AddInt64(&f.runs, 1)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return PartialReport{}, ctx.Err()
		}
	}
	return f.partial, f.err
}

func TestScan_MergesPartialReports(t *testing.T) {
	trueVal := true
	malware := &fakeProvider{
		name:   "fake-malware",
		signal: SignalMalware,
		partial: PartialReport{
			SupplyChain: &SupplyChainSection{MalwareStatus: "clean"},
		},
	}
	typosquat := &fakeProvider{
		name:   "fake-typosquat",
		signal: SignalTyposquat,
		partial: PartialReport{
			SupplyChain: &SupplyChainSection{TyposquatStatus: "suspected"},
			People:      &PeopleSection{TrustedPublisher: &trueVal},
		},
	}

	svc := New(Config{Providers: []Provider{malware, typosquat}})
	report, err := svc.Scan(context.Background(), Request{
		Key:   Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
		OrgID: "org-default",
	})
	if err != nil {
		t.Fatalf("Scan returned err: %v", err)
	}
	if got := report.SupplyChain.MalwareStatus; got != "clean" {
		t.Fatalf("MalwareStatus: got %q, want clean", got)
	}
	if got := report.SupplyChain.TyposquatStatus; got != "suspected" {
		t.Fatalf("TyposquatStatus: got %q, want suspected", got)
	}
	if report.People.TrustedPublisher == nil || !*report.People.TrustedPublisher {
		t.Fatalf("TrustedPublisher not merged")
	}
	if len(report.Observation.ProviderTimings) != 2 {
		t.Fatalf("ProviderTimings: got %d, want 2", len(report.Observation.ProviderTimings))
	}
}

func TestScan_SkipsProvidersForUnsupportedEcosystem(t *testing.T) {
	p := &fakeProvider{
		name:       "npm-only",
		signal:     SignalMalware,
		ecosystems: map[string]bool{"npm": true},
		partial:    PartialReport{SupplyChain: &SupplyChainSection{MalwareStatus: "clean"}},
	}
	svc := New(Config{Providers: []Provider{p}})
	report, err := svc.Scan(context.Background(), Request{
		Key:   Key{Ecosystem: "docker", Package: "nginx", Version: "1.27"},
		OrgID: "org-default",
	})
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if atomic.LoadInt64(&p.runs) != 0 {
		t.Fatalf("provider ran for unsupported ecosystem")
	}
	if report.SupplyChain.MalwareStatus != "" {
		t.Fatalf("MalwareStatus populated for unsupported ecosystem")
	}
}

func TestScan_EmitsWarningForArtifactProviderWithoutBytes(t *testing.T) {
	p := &fakeProvider{
		name:     "artifact-only",
		signal:   SignalHiddenUnicode,
		needsArt: true,
		partial:  PartialReport{Scan: &ArtifactScanSection{Performed: true}},
	}
	svc := New(Config{Providers: []Provider{p}})
	report, err := svc.Scan(context.Background(), Request{
		Key:   Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
		OrgID: "org-default",
	})
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if atomic.LoadInt64(&p.runs) != 0 {
		t.Fatalf("artifact-dependent provider ran without bytes")
	}
	found := false
	for _, w := range report.Observation.Warnings {
		if w.Provider == "artifact-only" && w.Code == WarnNeedsArtifact {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected needs_artifact warning, got warnings: %+v", report.Observation.Warnings)
	}
}

func TestScan_SurvivesProviderPanic(t *testing.T) {
	panicker := providerFunc{
		name:   "panicky",
		signal: SignalMalware,
		run: func(ctx context.Context, req Request, _ *Report) (PartialReport, error) {
			panic("boom")
		},
	}
	ok := &fakeProvider{
		name:    "ok",
		signal:  SignalTyposquat,
		partial: PartialReport{SupplyChain: &SupplyChainSection{TyposquatStatus: "clean"}},
	}
	svc := New(Config{Providers: []Provider{panicker, ok}})
	report, err := svc.Scan(context.Background(), Request{
		Key:   Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		OrgID: "org-default",
	})
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if report.SupplyChain.TyposquatStatus != "clean" {
		t.Fatalf("sibling provider output lost: %q", report.SupplyChain.TyposquatStatus)
	}
	sawPanic := false
	for _, w := range report.Observation.Warnings {
		if w.Provider == "panicky" && strings.Contains(w.Message, "panic") {
			sawPanic = true
			break
		}
	}
	if !sawPanic {
		t.Fatalf("expected panic warning, got: %+v", report.Observation.Warnings)
	}
}

// nameForPanicProvider panics on Name() AFTER Run returns. The inner
// recover only wraps p.Run; the post-Run code path (partialMsg
// construction, channel send) is guarded by the outer goroutine
// recover. If that outer recover is missing or scoped too narrowly,
// the panic from p.Name() at partialMsg-construction time crashes the
// whole Scan and the test panics.
type nameForPanicProvider struct {
	called atomic.Int32
}

func (p *nameForPanicProvider) Name() string {
	// First call is in the eligibility check (`p.Name()` for warnings)
	// — let that succeed so the provider gets dispatched. The second
	// call happens inside the goroutine after Run returned.
	if p.called.Add(1) >= 2 {
		panic("name() boom")
	}
	return "name-panicker"
}
func (p *nameForPanicProvider) Signal() SignalMask   { return SignalMalware }
func (p *nameForPanicProvider) Tier() int            { return 1 }
func (p *nameForPanicProvider) NeedsArtifact() bool  { return false }
func (p *nameForPanicProvider) Supports(string) bool { return true }
func (p *nameForPanicProvider) Run(context.Context, Request, *Report) (PartialReport, error) {
	return PartialReport{}, nil
}

// TestScan_SurvivesPostRunPanic exercises the outer goroutine recover
// added when the inner recover (around p.Run) was found to be too
// narrow. The post-Run panic — here from p.Name() during partialMsg
// construction — must not crash the test.
func TestScan_SurvivesPostRunPanic(t *testing.T) {
	panicker := &nameForPanicProvider{}
	ok := &fakeProvider{
		name:    "ok",
		signal:  SignalTyposquat,
		partial: PartialReport{SupplyChain: &SupplyChainSection{TyposquatStatus: "clean"}},
	}
	svc := New(Config{Providers: []Provider{panicker, ok}})
	report, err := svc.Scan(context.Background(), Request{
		Key:   Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		OrgID: "org-default",
	})
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	// The healthy sibling must still merge in even though the panicky
	// provider crashed mid-goroutine.
	if report == nil || report.SupplyChain.TyposquatStatus != "clean" {
		t.Fatalf("sibling provider output lost; report=%+v", report)
	}
}

func TestScan_SingleflightCoalescesParallelCalls(t *testing.T) {
	p := &fakeProvider{
		name:    "malware",
		signal:  SignalMalware,
		delay:   50 * time.Millisecond,
		partial: PartialReport{SupplyChain: &SupplyChainSection{MalwareStatus: "clean"}},
	}
	svc := New(Config{Providers: []Provider{p}})
	req := Request{
		Key:   Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
		OrgID: "org-default",
	}
	const N = 20
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = svc.Scan(context.Background(), req)
		}()
	}
	wg.Wait()
	// With store=nil the cache path misses every time. Singleflight
	// should still coalesce the 20 concurrent Scan calls into a single
	// Run of the underlying provider.
	if got := atomic.LoadInt64(&p.runs); got > 5 {
		t.Fatalf("singleflight did not coalesce: provider ran %d times, want <= 5", got)
	}
}

func TestScan_RejectsEmptyKey(t *testing.T) {
	svc := New(Config{})
	_, err := svc.Scan(context.Background(), Request{OrgID: "o"})
	if err == nil {
		t.Fatalf("expected error on empty key")
	}
}

func TestNoopService(t *testing.T) {
	var s Service = NoopService{}
	r, err := s.Scan(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
	})
	if err != nil {
		t.Fatalf("noop scan err: %v", err)
	}
	if len(r.Observation.Warnings) == 0 || r.Observation.Warnings[0].Code != WarnFeatureDisabled {
		t.Fatalf("expected feature_disabled warning, got: %+v", r.Observation.Warnings)
	}

	if _, err := s.Get(context.Background(), "o", Key{Ecosystem: "npm", Package: "p", Version: "1"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("noop Get: want ErrNotFound, got %v", err)
	}

	v, err := s.VerifyChecksum(context.Background(), ChecksumRequest{
		Declared: "abc", Actual: "abc",
	})
	if err != nil {
		t.Fatalf("noop VerifyChecksum err: %v", err)
	}
	if !v.Matched {
		t.Fatalf("expected matched verdict")
	}
}

// providerFunc is a small helper — lets tests express an ad-hoc
// provider without defining a whole struct. Only used inside the panic
// test above.
type providerFunc struct {
	name   string
	signal SignalMask
	run    func(ctx context.Context, req Request, prior *Report) (PartialReport, error)
}

func (p providerFunc) Name() string           { return p.name }
func (p providerFunc) Signal() SignalMask     { return p.signal }
func (p providerFunc) Tier() int              { return 1 }
func (p providerFunc) NeedsArtifact() bool    { return false }
func (p providerFunc) Supports(_ string) bool { return true }
func (p providerFunc) Run(ctx context.Context, req Request, r *Report) (PartialReport, error) {
	return p.run(ctx, req, r)
}
