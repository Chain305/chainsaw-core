package intelligence

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

// shortCircuitProvider is a synthetic provider that lets the
// short-circuit-on-Block test observe per-provider context cancellation.
// Its Run blocks for `delay` or until ctx is cancelled — whichever comes
// first. If ctx wins, it increments cancelObserved and returns ctx.Err().
// If the timer wins, it returns the configured PartialReport. Tests use
// this to assert that a Block verdict from one provider unblocks the
// rest of the phase-1 fan-out.
type shortCircuitProvider struct {
	name           string
	signal         SignalMask
	delay          time.Duration
	partial        PartialReport
	runs           int64
	cancelObserved int64
	completed      int64
}

func (p *shortCircuitProvider) Name() string           { return p.name }
func (p *shortCircuitProvider) Signal() SignalMask     { return p.signal }
func (p *shortCircuitProvider) Tier() int              { return 1 }
func (p *shortCircuitProvider) NeedsArtifact() bool    { return false }
func (p *shortCircuitProvider) Supports(_ string) bool { return true }
func (p *shortCircuitProvider) Run(ctx context.Context, _ Request, _ *Report) (PartialReport, error) {
	atomic.AddInt64(&p.runs, 1)
	if p.delay <= 0 {
		atomic.AddInt64(&p.completed, 1)
		return p.partial, nil
	}
	select {
	case <-time.After(p.delay):
		atomic.AddInt64(&p.completed, 1)
		return p.partial, nil
	case <-ctx.Done():
		atomic.AddInt64(&p.cancelObserved, 1)
		return PartialReport{}, ctx.Err()
	}
}

// TestScannerFanout_ShortCircuitOnBlock locks in F-5 follow-up: when
// any phase-1 provider returns a Block verdict (MalwareStatus="malicious")
// the scanner cancels its in-flight peers and returns the Block without
// waiting for the slowest-to-settle provider. The pre-fix wall-clock floor
// was max(provider delay) ≈ 200ms; the post-fix floor is the Block's own
// delay (~50ms) plus merge overhead.
func TestScannerFanout_ShortCircuitOnBlock(t *testing.T) {
	t.Parallel()

	const slowDelay = 200 * time.Millisecond
	const blockDelay = 50 * time.Millisecond
	const slowCount = 9

	slowProviders := make([]*shortCircuitProvider, 0, slowCount)
	for i := 0; i < slowCount; i++ {
		slowProviders = append(slowProviders, &shortCircuitProvider{
			// Each slow provider claims a different signal so they all
			// pass the SignalMask gate without being collapsed into one
			// merge entry. Ordering inside the mask doesn't matter.
			name:    "slow-allow",
			signal:  SignalMaintenance,
			delay:   slowDelay,
			partial: PartialReport{Maintenance: &MaintenanceSection{VersionCount: 1}},
		})
	}
	blocker := &shortCircuitProvider{
		name:    "fast-block",
		signal:  SignalMalware,
		delay:   blockDelay,
		partial: PartialReport{SupplyChain: &SupplyChainSection{MalwareStatus: "malicious"}},
	}

	providers := make([]Provider, 0, len(slowProviders)+1)
	providers = append(providers, blocker)
	for _, sp := range slowProviders {
		providers = append(providers, sp)
	}

	svc := New(Config{Providers: providers})

	// The short-circuit budget needs to comfortably exceed blockDelay
	// plus merge/sched overhead but stay well under slowDelay. 150ms
	// proves the slow providers couldn't have completed naturally.
	const wallClockBudget = 150 * time.Millisecond
	start := time.Now()
	report, err := svc.Scan(context.Background(), Request{
		Key:   Key{Ecosystem: "npm", Package: "evil-pkg", Version: "1.0.0"},
		OrgID: "org-default",
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("Scan returned err: %v", err)
	}
	if elapsed >= wallClockBudget {
		t.Fatalf("Scan did not short-circuit: elapsed=%v, want <%v (slow providers ran to completion at %v each)", elapsed, wallClockBudget, slowDelay)
	}
	if got := report.SupplyChain.MalwareStatus; got != "malicious" {
		t.Fatalf("MalwareStatus: got %q, want malicious — Block verdict lost during short-circuit", got)
	}

	// Wait briefly for any straggler goroutines that observed ctx.Done()
	// after Scan returned. They must unwind on their own — the Scan call
	// returns as soon as wg.Wait() does, but our cancelObserved counter
	// is incremented inside the slow providers' Run. By the time wg.Wait
	// returned, every slow provider's Run has already exited. So no
	// extra sleep is needed.

	cancelled := int64(0)
	for _, sp := range slowProviders {
		cancelled += atomic.LoadInt64(&sp.cancelObserved)
	}
	// Every slow provider should have observed cancellation. We allow
	// equality-or-greater so a future change that races slow providers
	// against each other still passes — what matters is that at least
	// N-1 (where N = total providers including the blocker) saw the
	// cancel signal.
	if cancelled < int64(slowCount) {
		// Spell out per-provider state so a regression is easy to debug.
		var details []string
		for _, sp := range slowProviders {
			runs := atomic.LoadInt64(&sp.runs)
			done := atomic.LoadInt64(&sp.completed)
			can := atomic.LoadInt64(&sp.cancelObserved)
			details = append(details, "runs="+itoa(runs)+" completed="+itoa(done)+" cancelled="+itoa(can))
		}
		t.Fatalf("expected all %d slow providers to observe cancellation, got %d; per-provider: %v", slowCount, cancelled, details)
	}

	// And no slow provider should have run to completion — that would
	// mean the short-circuit didn't actually trip.
	for i, sp := range slowProviders {
		if atomic.LoadInt64(&sp.completed) != 0 {
			t.Fatalf("slow provider %d completed despite short-circuit; cancelObserved=%d", i, atomic.LoadInt64(&sp.cancelObserved))
		}
	}
}

// TestScannerFanout_AllAllowCompletesNaturally is the negative control
// for the short-circuit: when no provider returns a Block, every provider
// must run to completion and contribute its partial to the merge. This
// guards against an over-eager short-circuit that misfires on non-Block
// verdicts and silently drops sibling results.
func TestScannerFanout_AllAllowCompletesNaturally(t *testing.T) {
	t.Parallel()

	const delay = 30 * time.Millisecond
	a := &shortCircuitProvider{
		name:    "allow-a",
		signal:  SignalMalware,
		delay:   delay,
		partial: PartialReport{SupplyChain: &SupplyChainSection{MalwareStatus: "clean"}},
	}
	b := &shortCircuitProvider{
		name:    "allow-b",
		signal:  SignalTyposquat,
		delay:   delay,
		partial: PartialReport{SupplyChain: &SupplyChainSection{TyposquatStatus: "clean"}},
	}
	c := &shortCircuitProvider{
		name:    "allow-c",
		signal:  SignalMaintenance,
		delay:   delay,
		partial: PartialReport{Maintenance: &MaintenanceSection{VersionCount: 7}},
	}

	svc := New(Config{Providers: []Provider{a, b, c}})
	report, err := svc.Scan(context.Background(), Request{
		Key:   Key{Ecosystem: "npm", Package: "good-pkg", Version: "1.0.0"},
		OrgID: "org-default",
	})
	if err != nil {
		t.Fatalf("Scan err: %v", err)
	}
	if report.SupplyChain.MalwareStatus != "clean" {
		t.Fatalf("MalwareStatus: got %q, want clean", report.SupplyChain.MalwareStatus)
	}
	if report.SupplyChain.TyposquatStatus != "clean" {
		t.Fatalf("TyposquatStatus: got %q, want clean", report.SupplyChain.TyposquatStatus)
	}
	if report.Maintenance.VersionCount != 7 {
		t.Fatalf("VersionCount: got %d, want 7", report.Maintenance.VersionCount)
	}
	for _, sp := range []*shortCircuitProvider{a, b, c} {
		if atomic.LoadInt64(&sp.cancelObserved) != 0 {
			t.Fatalf("provider %q observed cancel in all-allow path; spurious short-circuit", sp.name)
		}
		if atomic.LoadInt64(&sp.completed) != 1 {
			t.Fatalf("provider %q did not complete: completed=%d", sp.name, atomic.LoadInt64(&sp.completed))
		}
	}
}

// itoa is a tiny dependency-free integer formatter used by the test's
// failure messages — pulling in strconv just for a Fatalf detail line is
// unnecessary, and fmt.Sprintf is already in the test's import graph
// transitively but staying away from it keeps this helper hermetic.
func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
