package intelligence

// Regression tests for Options.MaxTier — the cap the dashboard uses to
// return a partial report inside a tight deadline while a background
// goroutine fills in the higher tiers.

import (
	"context"
	"sync/atomic"
	"testing"
)

// countingTierProvider exposes a configurable Tier() AND a run counter,
// so the MaxTier filter has providers across the whole 1..N range to act
// against and the test can assert which ones actually ran. (Distinct
// from scanner_tier4_test.go's tieredFakeProvider, which records `prior`
// instead of run count.)
type countingTierProvider struct {
	fakeProvider
	tier int
}

func (t *countingTierProvider) Tier() int { return t.tier }

func newTieredProvider(name string, tier int, sig SignalMask) *countingTierProvider {
	return &countingTierProvider{
		fakeProvider: fakeProvider{
			name:    name,
			signal:  sig,
			partial: PartialReport{},
		},
		tier: tier,
	}
}

// TestScan_MaxTierStopsAfterTier2 is the load-bearing assertion: a Scan
// with Options.MaxTier=2 runs every Tier-1 / Tier-2 provider and skips
// every higher-tier provider. The returned Report must be marked
// Partial=true and carry TierComplete=2 + TierTotal=4 so the UI can
// render "tier 2 of 4 — refining…" and poll for the rest.
func TestScan_MaxTierStopsAfterTier2(t *testing.T) {
	tier1 := newTieredProvider("p1", 1, SignalMalware)
	tier2 := newTieredProvider("p2", 2, SignalHiddenUnicode)
	tier3 := newTieredProvider("p3", 3, SignalTyposquat)
	tier4 := newTieredProvider("p4", 4, SignalKEV)

	svc := New(Config{Providers: []Provider{tier1, tier2, tier3, tier4}})
	report, err := svc.Scan(context.Background(), Request{
		Key:     Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
		OrgID:   "org-maxtier",
		Options: Options{MaxTier: 2},
	})
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}

	if atomic.LoadInt64(&tier1.runs) != 1 {
		t.Errorf("tier-1 provider ran %d times, want 1", tier1.runs)
	}
	if atomic.LoadInt64(&tier2.runs) != 1 {
		t.Errorf("tier-2 provider ran %d times, want 1", tier2.runs)
	}
	if got := atomic.LoadInt64(&tier3.runs); got != 0 {
		t.Errorf("tier-3 provider ran %d times under MaxTier=2, want 0", got)
	}
	if got := atomic.LoadInt64(&tier4.runs); got != 0 {
		t.Errorf("tier-4 provider ran %d times under MaxTier=2, want 0", got)
	}
	if !report.Observation.Partial {
		t.Errorf("Partial: got false, want true (MaxTier capped below TierTotal)")
	}
	if report.Observation.TierTotal != 4 {
		t.Errorf("TierTotal: got %d, want 4", report.Observation.TierTotal)
	}
	if report.Observation.TierComplete != 2 {
		t.Errorf("TierComplete: got %d, want 2", report.Observation.TierComplete)
	}
}

// TestScan_MaxTierZeroIsUnbounded pins the default — MaxTier=0 must run
// every registered tier and leave Partial=false.
func TestScan_MaxTierZeroIsUnbounded(t *testing.T) {
	tier1 := newTieredProvider("p1", 1, SignalMalware)
	tier3 := newTieredProvider("p3", 3, SignalTyposquat)

	svc := New(Config{Providers: []Provider{tier1, tier3}})
	report, err := svc.Scan(context.Background(), Request{
		Key:   Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
		OrgID: "org-maxtier",
	})
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if atomic.LoadInt64(&tier1.runs) != 1 || atomic.LoadInt64(&tier3.runs) != 1 {
		t.Errorf("MaxTier=0 must run every provider; got tier1=%d tier3=%d",
			tier1.runs, tier3.runs)
	}
	if report.Observation.Partial {
		t.Errorf("Partial: got true, want false on unbounded Scan")
	}
	if report.Observation.TierComplete != 3 {
		t.Errorf("TierComplete: got %d, want 3", report.Observation.TierComplete)
	}
	if report.Observation.TierTotal != 3 {
		t.Errorf("TierTotal: got %d, want 3", report.Observation.TierTotal)
	}
}
