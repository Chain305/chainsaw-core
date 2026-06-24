package intelligence

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/chain305/chainsaw-core/xreplicaflight"
	"golang.org/x/sync/singleflight"
)

// DefaultService is the production Service: cache-first, singleflight-
// coalesced, fan-out to Providers, partial-success merging.
type DefaultService struct {
	store     *Store
	providers []Provider
	logger    *slog.Logger
	now       func() time.Time

	// sf coalesces concurrent Scan calls for the same Key so N concurrent
	// proxy hits trigger one fan-out.
	sf singleflight.Group

	// flight is the cross-replica coordination layer. Default is the
	// zero-cost NoopFlight (every caller is leader — bit-identical to
	// the pre-xreplicaflight behaviour). A PGFlight is swapped in by
	// bootstrap when CHAINSAW_XREPLICA_SINGLEFLIGHT=true and a
	// shared *sql.DB is available. See internal/xreplicaflight.
	flight xreplicaflight.Flight

	// bg is the service-scoped context used by refreshAsync and any
	// background refresh. Cancelled by Close so shutdown reclaims leaked
	// goroutines.
	bg       context.Context
	bgCancel context.CancelFunc

	metrics MetricsRecorder

	// reportSink, if non-nil, is invoked after every successful
	// store.Upsert with the persisted Report. Bootstrap wires this to
	// the metadata-store denormaliser that projects the verified
	// ProvenanceSection (SLSA level, builder identity, source repo,
	// transparency log) onto package_metadata so the policy
	// evaluator's hot path reads SLSA-substrate fields without an
	// extra round-trip. Sinks must be cheap and non-blocking; errors
	// are swallowed because the canonical record (intelligence_reports
	// + attestations) is already on disk.
	reportSink ReportSink
}

// ReportSink is the callback signature for SetReportSink. orgID is the
// authoring tenant; report is non-nil and already persisted.
type ReportSink func(ctx context.Context, orgID string, report *Report)

// SetReportSink installs a post-Upsert hook. Pass nil to disable.
func (s *DefaultService) SetReportSink(sink ReportSink) {
	s.reportSink = sink
}

// MetricsRecorder is an optional observability seam. Implementations are
// expected to be cheap and non-blocking; default is the no-op.
type MetricsRecorder interface {
	RecordScan(duration time.Duration, cached bool)
	RecordCache(hit bool)
	RecordProviderError(provider string)
}

type noopMetricsRecorder struct{}

func (noopMetricsRecorder) RecordScan(time.Duration, bool) {}
func (noopMetricsRecorder) RecordCache(bool)               {}
func (noopMetricsRecorder) RecordProviderError(string)     {}

// SetMetricsRecorder installs a metrics recorder. Passing nil resets to
// the no-op. Safe to call once during bootstrap.
func (s *DefaultService) SetMetricsRecorder(r MetricsRecorder) {
	if r == nil {
		s.metrics = noopMetricsRecorder{}
		return
	}
	s.metrics = r
}

// Close cancels the service-scoped context so background refreshers
// unwind. Safe to call multiple times.
func (s *DefaultService) Close() error {
	if s.bgCancel != nil {
		s.bgCancel()
	}
	return nil
}

// New constructs a DefaultService. A nil Store (in-memory tests) is
// allowed — cache reads simply miss and writes no-op.
func New(cfg Config) *DefaultService {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	now := cfg.Now
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	bg, cancel := context.WithCancel(context.Background())
	return &DefaultService{
		store:     cfg.Store,
		providers: cfg.Providers,
		logger:    logger,
		now:       now,
		bg:        bg,
		bgCancel:  cancel,
		metrics:   noopMetricsRecorder{},
		// Default: cross-replica coordination OFF. bootstrap may swap
		// in a PGFlight via SetFlight when the feature flag is on.
		flight: xreplicaflight.NoopFlight{},
	}
}

// SetFlight installs a cross-replica coordination layer. Passing nil
// (or not calling SetFlight at all) leaves the NoopFlight default in
// place, which means every caller runs the full in-process Scan —
// bit-identical to the pre-xreplicaflight behaviour.
func (s *DefaultService) SetFlight(f xreplicaflight.Flight) {
	if f == nil {
		s.flight = xreplicaflight.NoopFlight{}
		return
	}
	s.flight = f
}

// Scan runs the tiered Scan pipeline with cache-first read, singleflight
// coalescing, and partial-success merging. Never returns an error except
// on context cancellation or empty Key.
func (s *DefaultService) Scan(ctx context.Context, req Request) (*Report, error) {
	if err := validateKey(req.Key); err != nil {
		return nil, err
	}
	deadline := req.Options.Deadline
	if deadline <= 0 {
		deadline = DefaultDeadline
	}
	maxStale := req.Options.MaxStaleness
	if maxStale <= 0 {
		maxStale = DefaultMaxStaleness
	}

	scanCtx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()

	scanStart := time.Now()

	// Cache-first read. Skipped entirely in Ephemeral mode: an artifact
	// upload must scan the bytes it carries, never return a coordinate-keyed
	// row authored by the proxy or another tenant (the read side of the
	// cache-poisoning threat).
	if s.store != nil && !req.Options.Ephemeral {
		if cached, err := s.store.Get(scanCtx, req.OrgID, req.Key); err == nil && cached != nil {
			age := s.now().Sub(cached.Observation.CollectedAt)
			if age < maxStale {
				cached.Observation.Cached = true
				s.metrics.RecordCache(true)
				s.metrics.RecordScan(time.Since(scanStart), true)
				return cached, nil
			}
			if req.Options.AllowStale {
				// Stale-while-revalidate: return cached, refresh async.
				go s.refreshAsync(req)
				cached.Observation.Cached = true
				s.metrics.RecordCache(true)
				s.metrics.RecordScan(time.Since(scanStart), true)
				return cached, nil
			}
		}
	}
	s.metrics.RecordCache(false)

	// Ephemeral (artifact-upload) path: run the fanout directly and return
	// the Report WITHOUT touching the shared store. We deliberately bypass
	// the singleflight + xreplicaflight leader machinery because that whole
	// apparatus exists to coordinate a SHARED cache write — there is no
	// shared write here, so coalescing under a coordinate-keyed lock would
	// be both pointless and a way to leak one upload's result to a concurrent
	// scan of the same client-asserted coordinate. No store.Upsert, no
	// reportSink: the client-asserted coordinate can never overwrite the
	// authoritative proxy/registry report. (Cache-warming of direct deps is
	// also skipped — it persists too.)
	if req.Options.Ephemeral {
		report := s.runFanout(scanCtx, req)
		s.metrics.RecordScan(time.Since(scanStart), false)
		return report, nil
	}

	// Cross-replica coordination: the inner closure holds the legacy
	// in-process singleflight PLUS the runFanout + store.Upsert chain,
	// so a follower replica that wakes up after the leader commits
	// reads the persisted Report via peek() below rather than refetching
	// upstream. NoopFlight (the default) collapses this to a direct
	// call of the inner closure — same cost path as before the feature.
	sfKey := singleflightKey(req.OrgID, req.Key)
	leader := func(innerCtx context.Context) (any, error) {
		v, err, _ := s.sf.Do(sfKey, func() (any, error) {
			report := s.runFanout(innerCtx, req)
			// Persist inside the leader closure so followers' peek()
			// sees the result as soon as the advisory lock releases.
			if s.store != nil {
				_ = s.store.Upsert(ctx, req.OrgID, report)
			}
			if s.reportSink != nil && report != nil {
				s.reportSink(ctx, req.OrgID, report)
			}
			return report, nil
		})
		return v, err
	}
	peek := func(innerCtx context.Context) (any, error) {
		if s.store == nil {
			// No store = no cache to read = no way to follow. The
			// xreplicaflight layer will surface this as a nil result
			// which the caller can retry.
			return nil, nil
		}
		cached, err := s.store.Get(innerCtx, req.OrgID, req.Key)
		if err != nil || cached == nil {
			return nil, nil
		}
		return cached, nil
	}
	v, err := s.flight.Do(scanCtx, sfKey, xreplicaflightLeaderTimeout, leader, peek)
	if err != nil {
		return nil, err
	}
	if v == nil {
		// Follower arrived after the leader released the lock but the
		// cache was empty (leader crashed mid-scan). Surface as an
		// error so the caller's next retry starts a fresh lock
		// attempt. DO NOT panic per the xreplicaflight contract.
		return nil, fmt.Errorf("intelligence: leader released lock without persisting report")
	}
	report := v.(*Report)
	s.metrics.RecordScan(time.Since(scanStart), false)
	// Fresh fan-out path: warm direct deps in the background so the next
	// Scan of this parent has full transitive coverage. Skips when there
	// are no direct deps; honours CHAINSAW_CACHE_WARM_DISABLED.
	if len(report.Dependencies.Direct) > 0 {
		go WarmDirectDeps(s.bg, report, s)
	}
	return report, nil
}

// xreplicaflightLeaderTimeout bounds how long a follower waits for a
// leader to finish its Scan. Set larger than DefaultDeadline so a
// leader that legitimately uses its full deadline isn't cut off by a
// follower timing out prematurely. Lower than the connection's
// idle-kill so pgbouncer / Postgres don't reap the follower's blocked
// query from under it.
var xreplicaflightLeaderTimeout = 45 * time.Second

// Get returns the cached Report or ErrNotFound.
func (s *DefaultService) Get(ctx context.Context, orgID string, key Key) (*Report, error) {
	if s.store == nil {
		return nil, ErrNotFound
	}
	return s.store.Get(ctx, orgID, key)
}

// Search delegates to the store.
func (s *DefaultService) Search(ctx context.Context, q SearchQuery) (*SearchResults, error) {
	if s.store == nil {
		return &SearchResults{}, nil
	}
	return s.store.Search(ctx, q)
}

// Facets delegates to the store.
func (s *DefaultService) Facets(ctx context.Context, orgID string) (*FacetCounts, error) {
	if s.store == nil {
		return &FacetCounts{}, nil
	}
	return s.store.Facets(ctx, orgID)
}

// VerifyChecksum runs only the checksum provider if one is registered.
// Falls back to the trivial declared==actual comparison otherwise so the
// proxy's enforcer behavior is preserved.
func (s *DefaultService) VerifyChecksum(ctx context.Context, req ChecksumRequest) (ChecksumVerdict, error) {
	if req.Declared == "" {
		return ChecksumVerdict{Status: "unavailable", Reason: "no declared hash"}, nil
	}
	if req.Actual == "" {
		return ChecksumVerdict{Status: "unavailable", Reason: "no actual hash"}, nil
	}
	if strings.EqualFold(req.Declared, req.Actual) {
		return ChecksumVerdict{Matched: true, Status: "matched"}, nil
	}
	return ChecksumVerdict{Status: "mismatch", Reason: "declared hash does not match actual"}, nil
}

// runFanout is the core Scan pipeline. Builds a fresh Report, fans out to
// every supported provider that the SignalMask selects, merges results,
// stamps observation metadata.
func (s *DefaultService) runFanout(ctx context.Context, req Request) *Report {
	now := s.now()
	report := &Report{
		Identity: IdentitySection{
			Ecosystem:       req.Key.Ecosystem,
			Package:         req.Key.Package,
			Version:         req.Key.Version,
			RegistryBase:    req.UpstreamURL,
			ArtifactSubtype: req.ArtifactSubtype,
		},
		Observation: ObservationSection{
			CollectedAt:   now,
			FreshUntil:    now.Add(DefaultMaxStaleness),
			RefreshReason: req.Options.RefreshReason,
		},
	}

	// Fan out providers in tiered phases:
	//   - Tier 1+2 run in parallel first (no `prior`),
	//   - the collector merges their output,
	//   - Tier 3 runs in parallel against the merged prior,
	//   - results merge,
	//   - Tier 4 runs in parallel against the now-tier-3-augmented prior.
	// By convention Tier-4 providers are projection / aggregation only —
	// they MUST NOT issue new HTTP / network calls; that constraint is
	// what justifies running them after the rest of the fanout has paid
	// its latency cost.
	// Every phase respects the shared Scan deadline.
	//
	// The post-Tier-1/2 phases are keyed on Tier() value rather than a
	// fixed slice so adding a Tier-5 (etc.) is one line, not a refactor.
	type partialMsg struct {
		name    string
		partial PartialReport
		elapsed time.Duration
		err     error
	}

	effectiveMask := req.Options.Signals
	skip := req.Options.SkipSignals
	// Compute the highest provider tier registered for this ecosystem so
	// we can stamp TierTotal on every Report. This is the ceiling
	// TierComplete will reach once a no-MaxTier Scan finishes — the UI
	// uses (TierComplete, TierTotal) to render the polling progress.
	tierTotal := 0
	for _, p := range s.providers {
		if !p.Supports(req.Key.Ecosystem) {
			continue
		}
		if t := p.Tier(); t > tierTotal {
			tierTotal = t
		}
	}
	report.Observation.TierTotal = tierTotal
	maxTier := req.Options.MaxTier // 0 = unbounded; >=1 caps the highest tier that runs

	var phase1 []Provider
	// postMergeTiers[N] holds providers whose Tier() == N+3 (so index 0
	// is Tier-3, index 1 is Tier-4, etc.). The slice grows on demand.
	var postMergeTiers [][]Provider
	for _, p := range s.providers {
		if !effectiveMask.Has(p.Signal()) {
			continue
		}
		if skip != 0 && p.Signal()&skip != 0 {
			continue
		}
		if !p.Supports(req.Key.Ecosystem) {
			continue
		}
		// Honor MaxTier: drop providers whose tier exceeds the cap.
		// MaxTier=1 keeps only Tier-1; MaxTier=2 keeps Tier-1+2 (the
		// full phase-1 pool); MaxTier=N>=3 also keeps post-merge
		// tiers up to and including N. MaxTier=0 keeps everything.
		if maxTier > 0 && p.Tier() > maxTier {
			continue
		}
		if p.NeedsArtifact() && req.Artifact == nil {
			report.Observation.Warnings = append(report.Observation.Warnings, Warning{
				Provider: p.Name(),
				Code:     WarnNeedsArtifact,
				Message:  "artifact bytes required but not provided",
				At:       now,
			})
			continue
		}
		if p.Tier() >= 3 {
			idx := p.Tier() - 3
			for len(postMergeTiers) <= idx {
				postMergeTiers = append(postMergeTiers, nil)
			}
			postMergeTiers[idx] = append(postMergeTiers[idx], p)
		} else {
			phase1 = append(phase1, p)
		}
	}
	eligible := phase1

	// Phase 1 workers don't read the shared `report` — they receive nil
	// as the `prior` argument so the main goroutine's merge can never
	// race with a concurrent provider read. Phase 3 providers, which
	// depend on merged output, run only after wg.Wait() returns.
	//
	// fanoutCtx is a child of ctx whose cancellation also short-circuits
	// the in-flight phase-1 providers. We trip it the instant any
	// provider returns a partial that, on its own, justifies a Block
	// verdict (malware "malicious", typosquat "confirmed"). The siblings
	// see fanoutCtx.Done() via their per-provider context (which we
	// derive from fanoutCtx, not the parent ctx) and unwind early — the
	// merge then proceeds with whatever results have already been
	// collected. The Block-bearing partial is preserved because the
	// goroutine sends to ch BEFORE tripping the cancel; siblings'
	// abandoned partials are dropped via the case <-fanoutCtx.Done()
	// branch on the send select. Per-provider deadlines
	// (DefaultProviderTimeout) and the merge-precedence rules are
	// untouched; this only collapses the wall-clock floor on cold
	// installs whose first-arriving verdict is decisive.
	fanoutCtx, fanoutCancel := context.WithCancel(ctx)
	defer fanoutCancel()
	ch := make(chan partialMsg, len(eligible))
	var wg sync.WaitGroup
	for _, p := range eligible {
		wg.Add(1)
		go func(p Provider) {
			defer wg.Done()
			// Outer recover guards the entire goroutine, including the
			// channel send. The select-on-fanoutCtx.Done() handles the
			// "ctx cancelled, no receivers" case but cannot help if
			// the channel is closed out from under us — a panic on a
			// closed channel would otherwise crash the process.
			defer func() {
				if r := recover(); r != nil {
					// We cannot reliably forward this to the merge
					// loop — the channel may be the very thing that
					// panicked. Fall back to direct logging via the
					// scanner's metrics hook so the panic is visible
					// in the same place a Run-error would be.
					s.metrics.RecordProviderError(p.Name())
				}
			}()
			// Derive the per-provider context from fanoutCtx (not the
			// parent ctx) so the short-circuit cancel propagates into
			// every running provider. Per-provider deadline math stays
			// the same — DefaultProviderTimeout is layered on top.
			providerCtx, cancel := context.WithTimeout(fanoutCtx, DefaultProviderTimeout)
			defer cancel()
			start := time.Now()
			var out PartialReport
			var runErr error
			func() {
				defer func() {
					if r := recover(); r != nil {
						runErr = fmt.Errorf("provider panic: %v", r)
					}
				}()
				out, runErr = p.Run(providerCtx, req, nil)
			}()
			msg := partialMsg{
				name:    p.Name(),
				partial: out,
				elapsed: time.Since(start),
				err:     runErr,
			}
			// Send first, THEN trip the short-circuit. If the order is
			// reversed, a fast-cancellation race could close the send
			// branch before the Block-bearing partial reaches the merge.
			select {
			case ch <- msg:
			case <-fanoutCtx.Done():
			}
			if runErr == nil && partialIsBlocking(out) {
				fanoutCancel()
			}
		}(p)
	}

	// Wait for all Phase-1 workers before closing the channel, so a
	// late-arriving send after ctx cancellation cannot panic on a
	// closed channel. The select inside each worker bounds how long
	// that can take to DefaultProviderTimeout — and short-circuit-on-
	// Block (fanoutCancel above) collapses it further when a decisive
	// verdict lands early.
	wg.Wait()
	close(ch)
	// Phase-1 mixes Tier-1 and Tier-2 providers. Once they all settle
	// the highest completed tier is the max of what was eligible —
	// either 1 (no Tier-2 was selected) or 2 (the common case).
	for _, p := range eligible {
		if t := p.Tier(); t > report.Observation.TierComplete {
			report.Observation.TierComplete = t
		}
	}

	// Merge partials.
	for msg := range ch {
		mergePartial(report, msg.partial)
		report.Observation.ProviderTimings = append(report.Observation.ProviderTimings, ProviderTiming{
			Provider: msg.name,
			Duration: msg.elapsed,
			Error:    errString(msg.err),
		})
		if msg.err != nil {
			s.metrics.RecordProviderError(msg.name)
			report.Observation.Warnings = append(report.Observation.Warnings, Warning{
				Provider: msg.name,
				Code:     warnCodeForError(msg.err),
				Message:  msg.err.Error(),
				At:       s.now(),
			})
		}
	}
	// Post-merge tiers (Tier 3, 4, ...). Each tier runs to completion
	// and merges before the next tier starts — that ordering is what
	// lets a Tier-N provider see Tier-(N-1) output. Within a tier the
	// providers fan out in parallel, so they still don't see each
	// other's writes (consistent with the pre-Tier-4 contract). Any
	// ctx cancellation during an earlier phase short-circuits here.
	for tierIdx, tierProviders := range postMergeTiers {
		if ctx.Err() != nil {
			break
		}
		if len(tierProviders) == 0 {
			continue
		}
		_ = tierIdx // tierIdx+3 is the Tier() value, kept implicit
		chN := make(chan partialMsg, len(tierProviders))
		var wgN sync.WaitGroup
		for _, p := range tierProviders {
			wgN.Add(1)
			go func(p Provider) {
				defer wgN.Done()
				providerCtx, cancel := context.WithTimeout(ctx, DefaultProviderTimeout)
				defer cancel()
				start := time.Now()
				var out PartialReport
				var runErr error
				func() {
					defer func() {
						if r := recover(); r != nil {
							runErr = fmt.Errorf("provider panic: %v", r)
						}
					}()
					out, runErr = p.Run(providerCtx, req, report)
				}()
				msg := partialMsg{name: p.Name(), partial: out, elapsed: time.Since(start), err: runErr}
				select {
				case chN <- msg:
				case <-ctx.Done():
				}
			}(p)
		}
		wgN.Wait()
		close(chN)
		for msg := range chN {
			mergePartial(report, msg.partial)
			report.Observation.ProviderTimings = append(report.Observation.ProviderTimings, ProviderTiming{
				Provider: msg.name,
				Duration: msg.elapsed,
				Error:    errString(msg.err),
			})
			if msg.err != nil {
				s.metrics.RecordProviderError(msg.name)
				report.Observation.Warnings = append(report.Observation.Warnings, Warning{
					Provider: msg.name,
					Code:     warnCodeForError(msg.err),
					Message:  msg.err.Error(),
					At:       s.now(),
				})
			}
		}
		// Each post-merge tier index N corresponds to Tier (N+3); record
		// it as the high-water mark so a polling consumer can tell how
		// far the fan-out actually got even if a later tier short-
		// circuits on ctx cancellation.
		if completed := tierIdx + 3; completed > report.Observation.TierComplete {
			report.Observation.TierComplete = completed
		}
	}
	// Stamp Partial after every phase has run. Partial is true when the
	// caller capped MaxTier below the registered ceiling — that's the
	// signal the UI uses to keep polling. A Scan that ran every tier
	// (MaxTier=0 OR MaxTier>=tierTotal) leaves Partial=false.
	if maxTier > 0 && tierTotal > 0 && maxTier < tierTotal {
		report.Observation.Partial = true
	}

	// Post-merge derived signals. Trust score is computed from the full
	// merged Report, not a provider — that way it stays O(1) CPU work
	// with no extra goroutines or cache pressure. We thread the request's
	// real OrgID so the per-(org, signal) override resolver actually
	// matches the operator's risk-tuning rows (Validator D.2).
	ComputeTrustScoreForOrg(report, req.OrgID)

	// Transitive risk overlay: walks Report.Dependencies.Direct,
	// looks up each dep's cached intelligence row, builds a one-level
	// depgraph, and runs risk.EvaluateTree to fold descendants into
	// Report.Risk.RolledUp + Resolution.TransitiveBlame. No-ops when
	// the cache or risk evaluation aren't populated yet.
	if s.store != nil {
		evaluateTransitiveRisk(ctx, s.store, req.OrgID, report)
	}

	// Async transitive enqueue: fire detached Scans for each direct
	// + peer dep (depth-bounded by ctx). Does NOT block the parent —
	// the goroutines outlive this function; the caller is already
	// done by the time these complete. The recursive enqueue chain
	// (each child Scan re-runs this block) is what produces full
	// transitive coverage.
	s.enqueueDependencyScans(ctx, report)

	// If ctx was cancelled before some providers returned, emit a timeout
	// warning for each missing provider.
	if ctx.Err() != nil {
		seen := map[string]bool{}
		for _, t := range report.Observation.ProviderTimings {
			seen[t.Provider] = true
		}
		for _, p := range eligible {
			if !seen[p.Name()] {
				report.Observation.Warnings = append(report.Observation.Warnings, Warning{
					Provider: p.Name(),
					Code:     WarnTimeout,
					Message:  "deadline exceeded before provider completed",
					At:       s.now(),
				})
			}
		}
	}
	return report
}

// refreshAsync runs a fresh Scan in the background, writing through to the
// cache. Used for stale-while-revalidate callers. Re-enters Scan so the
// singleflight coalescer applies.
func (s *DefaultService) refreshAsync(req Request) {
	parent := s.bg
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, DefaultDeadline)
	defer cancel()
	req.Options.AllowStale = false
	req.Options.MaxStaleness = 1 * time.Nanosecond // force a fetch
	_, _ = s.Scan(ctx, req)
}

func validateKey(k Key) error {
	// Wrap ErrInvalidKey so callers (e.g. internal/scan worker) can
	// detect parse-shape failures via errors.Is and skip retry budgets
	// that only make sense for transient upstream failures. The
	// %w-formatted message stays human-readable for logs.
	if strings.TrimSpace(k.Ecosystem) == "" {
		return fmt.Errorf("%w: key.ecosystem required", ErrInvalidKey)
	}
	if strings.TrimSpace(k.Package) == "" {
		return fmt.Errorf("%w: key.package required", ErrInvalidKey)
	}
	if strings.TrimSpace(k.Version) == "" {
		return fmt.Errorf("%w: key.version required", ErrInvalidKey)
	}
	return nil
}

func singleflightKey(orgID string, k Key) string {
	return orgID + "|" + k.Ecosystem + "|" + k.Package + "|" + k.Version
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// warnCodeForError maps common error shapes to stable warning codes so UI
// consumers can filter. Falls back to parse_failed for unclassified errors.
func warnCodeForError(err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return WarnTimeout
	}
	return WarnParseFailed
}

// partialIsBlocking reports whether a single provider's PartialReport is
// already decisive enough to short-circuit the rest of the phase-1
// fan-out. The proxy's enforcement layer treats MalwareStatus="malicious"
// as a hard block (server_repo_pipeline.go reads it via
// pkgMeta.MalwareStatus on the projected metadata row), so the moment a
// provider reports "malicious" we can stop waiting on its peers — their
// results would not change the verdict.
//
// We deliberately do NOT short-circuit on TyposquatStatus="suspected"
// (fuzzy match, "advisory" severity per the policy evaluator) — only the
// strong-evidence "confirmed_safe"-style typosquat outcomes warrant
// halting the fan-out. The current corpus only emits "suspected", so
// keeping the gate strict means this helper today fires only on malware.
func partialIsBlocking(p PartialReport) bool {
	if p.SupplyChain == nil {
		return false
	}
	return strings.EqualFold(p.SupplyChain.MalwareStatus, "malicious")
}

// mergePartial copies non-zero fields from p into r. Providers are
// expected to only set what they produced, so zero fields leave the prior
// content intact.
func mergePartial(r *Report, p PartialReport) {
	if p.Release != nil {
		mergeRelease(&r.Release, *p.Release)
	}
	if p.URLs != nil {
		mergeURLs(&r.URLs, *p.URLs)
	}
	if p.Artifact != nil {
		mergeArtifact(&r.Artifact, *p.Artifact)
	}
	if p.People != nil {
		mergePeople(&r.People, *p.People)
	}
	if p.Metadata != nil {
		mergeMetadata(&r.Metadata, *p.Metadata)
	}
	if p.Provenance != nil {
		mergeProvenance(&r.Provenance, *p.Provenance)
	}
	if p.Scan != nil {
		MergeScan(&r.Scan, *p.Scan)
	}
	if p.SupplyChain != nil {
		mergeSupplyChain(&r.SupplyChain, *p.SupplyChain)
	}
	if p.Vulns != nil {
		mergeVulns(&r.Vulnerabilities, *p.Vulns)
	}
	if p.Maintenance != nil {
		mergeMaintenance(&r.Maintenance, *p.Maintenance)
	}
	if p.Dependencies != nil {
		mergeDependencies(&r.Dependencies, *p.Dependencies)
	}
	if len(p.Warnings) > 0 {
		r.Observation.Warnings = append(r.Observation.Warnings, p.Warnings...)
	}
}

// The merge* helpers are intentionally explicit so a reader can see which
// fields each section considers "populate-if-empty". The alternative —
// reflection-based merging — would be shorter but silently fragile when
// new fields land.

func mergeRelease(dst *ReleaseSection, src ReleaseSection) {
	if src.PublishedAt != nil {
		dst.PublishedAt = src.PublishedAt
	}
	if src.CreatedAt != nil {
		dst.CreatedAt = src.CreatedAt
	}
	if src.ModifiedAt != nil {
		dst.ModifiedAt = src.ModifiedAt
	}
	if src.LatestVersion != "" {
		dst.LatestVersion = src.LatestVersion
	}
	if src.Listed != nil {
		dst.Listed = src.Listed
	}
	if src.Yanked != nil {
		dst.Yanked = src.Yanked
	}
	if src.Prerelease != nil {
		dst.Prerelease = src.Prerelease
	}
	// Deprecated: non-empty src wins. An empty src preserves dst because
	// the npm registry does not always return the deprecation string on
	// every probe — a refresher tick must not silently clear a value the
	// first packument fetch observed.
	if src.Deprecated != "" {
		dst.Deprecated = src.Deprecated
	}
}

func mergeURLs(dst *URLSection, src URLSection) {
	if src.MetadataURL != "" {
		dst.MetadataURL = src.MetadataURL
	}
	if src.ArtifactURL != "" {
		dst.ArtifactURL = src.ArtifactURL
	}
	if src.SourceRepoURL != "" {
		dst.SourceRepoURL = src.SourceRepoURL
	}
	if src.HomepageURL != "" {
		dst.HomepageURL = src.HomepageURL
	}
	if src.DocumentationURL != "" {
		dst.DocumentationURL = src.DocumentationURL
	}
	if src.IssuesURL != "" {
		dst.IssuesURL = src.IssuesURL
	}
	if src.ReadmeURL != "" {
		dst.ReadmeURL = src.ReadmeURL
	}
}

func mergeArtifact(dst *ArtifactSection, src ArtifactSection) {
	if src.Filename != "" {
		dst.Filename = src.Filename
	}
	if src.Packaging != "" {
		dst.Packaging = src.Packaging
	}
	if src.Size != 0 {
		dst.Size = src.Size
	}
	if src.Digests.SHA256 != "" {
		dst.Digests.SHA256 = src.Digests.SHA256
	}
	if src.Digests.SHA512 != "" {
		dst.Digests.SHA512 = src.Digests.SHA512
	}
	if src.Digests.SHA1 != "" {
		dst.Digests.SHA1 = src.Digests.SHA1
	}
	if src.Digests.MD5 != "" {
		dst.Digests.MD5 = src.Digests.MD5
	}
	if src.Digests.Blake2b256 != "" {
		dst.Digests.Blake2b256 = src.Digests.Blake2b256
	}
	if src.Digests.Integrity != "" {
		dst.Digests.Integrity = src.Digests.Integrity
	}
	if src.Digests.Declared != "" {
		dst.Digests.Declared = src.Digests.Declared
	}
	if src.Digests.Actual != "" {
		dst.Digests.Actual = src.Digests.Actual
	}
	if src.Digests.Verified {
		dst.Digests.Verified = true
	}
	// Signature fields are pure projections of the merged Provenance
	// section produced by provider_signature_verify.go. Pointer +
	// non-empty checks preserve the three-state contract: a nil patch
	// field never clobbers a richer prior value.
	if src.SignatureVerified != nil {
		v := *src.SignatureVerified
		dst.SignatureVerified = &v
	}
	if src.SignatureKind != "" {
		dst.SignatureKind = src.SignatureKind
	}
	if src.SignatureKeyID != "" {
		dst.SignatureKeyID = src.SignatureKeyID
	}
}

func mergePeople(dst *PeopleSection, src PeopleSection) {
	if len(src.Authors) > 0 {
		dst.Authors = src.Authors
	}
	if len(src.Maintainers) > 0 {
		dst.Maintainers = src.Maintainers
	}
	if len(src.PublisherIDs) > 0 {
		dst.PublisherIDs = src.PublisherIDs
	}
	if src.TrustedPublisher != nil {
		dst.TrustedPublisher = src.TrustedPublisher
	}
}

func mergeMetadata(dst *MetadataSection, src MetadataSection) {
	if src.Summary != "" {
		dst.Summary = src.Summary
	}
	if src.Description != "" {
		dst.Description = src.Description
	}
	if len(src.Keywords) > 0 {
		dst.Keywords = src.Keywords
	}
	if src.LicenseExpression != "" {
		dst.LicenseExpression = src.LicenseExpression
	}
	if src.RequiresRuntime != "" {
		dst.RequiresRuntime = src.RequiresRuntime
	}
	if len(src.Platforms) > 0 {
		dst.Platforms = src.Platforms
	}
}

func mergeProvenance(dst *ProvenanceSection, src ProvenanceSection) {
	if src.Kind != "" {
		dst.Kind = src.Kind
	}
	if src.Status != "" {
		dst.Status = src.Status
	}
	if src.Available {
		dst.Available = true
	}
	if src.Verified {
		dst.Verified = true
	}
	if src.Endpoint != "" {
		dst.Endpoint = src.Endpoint
	}
	if src.SubjectDigest != "" {
		dst.SubjectDigest = src.SubjectDigest
	}
	if src.BundleURL != "" {
		dst.BundleURL = src.BundleURL
	}
	if src.SignerID != "" {
		dst.SignerID = src.SignerID
	}
	if src.BuilderID != "" {
		dst.BuilderID = src.BuilderID
	}
	if src.SourceRepo != "" {
		dst.SourceRepo = src.SourceRepo
	}
	if src.TransparencyLog != "" {
		dst.TransparencyLog = src.TransparencyLog
	}
	if len(src.CertChain) > 0 {
		dst.CertChain = src.CertChain
	}
	// BundleFormat / SourceCommit — non-empty src wins. Tier-3
	// signature-verify can fill these in after a Tier-1 placeholder.
	if src.BundleFormat != "" {
		dst.BundleFormat = src.BundleFormat
	}
	if src.SourceCommit != "" {
		dst.SourceCommit = src.SourceCommit
	}
	// SLSALevel — max wins. A higher reading from a more thorough
	// provider must not be clobbered by a later, weaker probe.
	if src.SLSALevel > dst.SLSALevel {
		dst.SLSALevel = src.SLSALevel
	}
	// CacheStale — OR-merge. Once any provider observed a Sigstore cache
	// miss, surface it so policy (ForbidCacheStale) can act.
	if src.CacheStale {
		dst.CacheStale = true
	}
	// Warnings — append and deduplicate. Multiple providers may emit
	// the same non-fatal note; we preserve every distinct one.
	if len(src.Warnings) > 0 {
		seen := make(map[string]struct{}, len(dst.Warnings)+len(src.Warnings))
		for _, w := range dst.Warnings {
			seen[w] = struct{}{}
		}
		for _, w := range src.Warnings {
			if _, ok := seen[w]; ok {
				continue
			}
			seen[w] = struct{}{}
			dst.Warnings = append(dst.Warnings, w)
		}
	}
}

// MergeScan merges an ArtifactScanSection patch into dst using OR / latest-
// wins semantics. Exported as part of the open-core seam: the premium
// agenttool-verify provider's tests (internal/intelligence/premium) assert
// the post-merge override behaviour through this helper.
func MergeScan(dst *ArtifactScanSection, src ArtifactScanSection) {
	if src.Performed {
		dst.Performed = true
	}
	if src.ScannedAt != nil {
		dst.ScannedAt = src.ScannedAt
	}
	if src.ScannedArtifactSHA != "" {
		dst.ScannedArtifactSHA = src.ScannedArtifactSHA
	}
	if src.InstallScriptKind != "" {
		dst.InstallScriptKind = src.InstallScriptKind
	}
	if src.HasInstallScript {
		dst.HasInstallScript = true
	}
	if src.InstallScriptFetches {
		dst.InstallScriptFetches = true
	}
	if src.HiddenUnicodeHits != 0 {
		dst.HiddenUnicodeHits = src.HiddenUnicodeHits
	}
	if len(src.HiddenUnicodeKinds) > 0 {
		dst.HiddenUnicodeKinds = src.HiddenUnicodeKinds
	}
	if len(src.ManifestFilesSeen) > 0 {
		dst.ManifestFilesSeen = src.ManifestFilesSeen
	}
	if len(src.ExtraFindings) > 0 {
		if dst.ExtraFindings == nil {
			dst.ExtraFindings = make(map[string]any, len(src.ExtraFindings))
		}
		for k, v := range src.ExtraFindings {
			dst.ExtraFindings[k] = v
		}
	}
	// Socket-gap Wave 1 — OR-merge so the first provider to set a
	// boolean wins and subsequent providers can only affirm (not clear).
	if src.ShrinkwrapPresent {
		dst.ShrinkwrapPresent = true
	}
	// ShrinkwrapSuppressed — OR-merge. Once a provider observes a
	// lockfile entry that suppresses install scripts, the signal stays
	// sticky across the rest of the fan-in.
	if src.ShrinkwrapSuppressed {
		dst.ShrinkwrapSuppressed = true
	}
	if src.ManifestConfusion {
		dst.ManifestConfusion = true
	}
	if len(src.ManifestConfusionFields) > 0 {
		dst.ManifestConfusionFields = src.ManifestConfusionFields
	}
	// Socket-gap Wave 3 — per-scanner boolean fan-in. Each provider
	// sets exactly one bit; OR-merge preserves them across the fan-out.
	if src.UsesEval {
		dst.UsesEval = true
	}
	if src.NetworkAccess {
		dst.NetworkAccess = true
	}
	if src.ShellAccess {
		dst.ShellAccess = true
	}
	if src.FilesystemAccess {
		dst.FilesystemAccess = true
	}
	if src.EnvVarAccess {
		dst.EnvVarAccess = true
	}
	if src.NativeBinaryPresent {
		dst.NativeBinaryPresent = true
	}
	if src.HighEntropyStrings {
		dst.HighEntropyStrings = true
	}
	if src.URLStrings {
		dst.URLStrings = true
	}
	if src.MinifiedCode {
		dst.MinifiedCode = true
	}
	// Socket-gap Wave 4 — same OR-merge semantics for the boolean
	// signals; numeric fields (TrivialPackageLOC, TooManyFilesCount,
	// MaintainerAccountAgeDays) take the first non-zero value.
	if src.TrivialPackage {
		dst.TrivialPackage = true
	}
	if src.TrivialPackageLOC != 0 && dst.TrivialPackageLOC == 0 {
		dst.TrivialPackageLOC = src.TrivialPackageLOC
	}
	if src.TooManyFiles {
		dst.TooManyFiles = true
	}
	if src.TooManyFilesCount != 0 && dst.TooManyFilesCount == 0 {
		dst.TooManyFilesCount = src.TooManyFilesCount
	}
	if src.NonExistentAuthor {
		dst.NonExistentAuthor = true
	}
	// FirstTimeCollaborator is three-state (*bool):
	//   - any *true wins (a Tier-3 provider positively flagged a new
	//     collaborator; later providers can only affirm).
	//   - if dst is nil and src is non-nil, copy src so a *false from a
	//     single provider sticks instead of leaving the field unset.
	//   - nil never overwrites a populated dst.
	if src.FirstTimeCollaborator != nil {
		if *src.FirstTimeCollaborator {
			t := true
			dst.FirstTimeCollaborator = &t
		} else if dst.FirstTimeCollaborator == nil {
			f := false
			dst.FirstTimeCollaborator = &f
		}
	}
	if src.SuspiciousRepoStars {
		dst.SuspiciousRepoStars = true
	}
	// Maintainer-account-age merge: take the youngest non-zero
	// reading. Zero stays "no signal".
	if src.MaintainerAccountAgeDays > 0 {
		if dst.MaintainerAccountAgeDays == 0 || src.MaintainerAccountAgeDays < dst.MaintainerAccountAgeDays {
			dst.MaintainerAccountAgeDays = src.MaintainerAccountAgeDays
		}
	}

	// AI artifact OR-merge — pickle / model-card findings are sticky
	// once any provider asserts them.
	if src.DangerousPickleOpcode {
		dst.DangerousPickleOpcode = true
	}
	if len(src.DangerousPickleFiles) > 0 {
		dst.DangerousPickleFiles = src.DangerousPickleFiles
	}
	if src.DangerousPickleSummary != "" {
		dst.DangerousPickleSummary = src.DangerousPickleSummary
	}
	if src.SuspiciousPickleOpcode {
		dst.SuspiciousPickleOpcode = true
	}
	if src.UnsafeSerializationFormat {
		dst.UnsafeSerializationFormat = true
	}
	if src.PrefersSafetensorsAvailable {
		dst.PrefersSafetensorsAvailable = true
	}
	if src.ModelCardInjection {
		dst.ModelCardInjection = true
	}
	if len(src.ModelCardKinds) > 0 {
		dst.ModelCardKinds = src.ModelCardKinds
	}
	if src.PromptTemplateInjection {
		dst.PromptTemplateInjection = true
	}
	// Agent-tool / MCP merge — the AgentToolDeclared bit is a gate that
	// also lets the Tier-3 agent_tool_verify provider override
	// MCPServerUnverified back to false post-merge: when a partial sets
	// AgentToolDeclared we copy MCPServerUnverified from src verbatim,
	// so a Tier-3 patch with MCPServerUnverified=false clears the
	// Tier-2 default after provenance is observed.
	if src.AgentToolDeclared {
		dst.AgentToolDeclared = true
		dst.MCPServerUnverified = src.MCPServerUnverified
	}
	if src.AgentToolDangerousCapability {
		dst.AgentToolDangerousCapability = true
	}
	if len(src.AgentToolCapabilities) > 0 {
		dst.AgentToolCapabilities = src.AgentToolCapabilities
	}

	// Gap 4b: minified file list. The file list is more specific than
	// the existing MinifiedCode bool — take the first non-empty list.
	if len(src.MinifiedFiles) > 0 && len(dst.MinifiedFiles) == 0 {
		dst.MinifiedFiles = src.MinifiedFiles
	}

	// Gap 2: capability report. First non-nil wins.
	if src.CapabilityReport != nil && dst.CapabilityReport == nil {
		dst.CapabilityReport = src.CapabilityReport
	}
}

func mergeSupplyChain(dst *SupplyChainSection, src SupplyChainSection) {
	if src.MalwareStatus != "" {
		dst.MalwareStatus = src.MalwareStatus
	}
	if src.MalwareID != "" {
		dst.MalwareID = src.MalwareID
	}
	if src.MalwareSummary != "" {
		dst.MalwareSummary = src.MalwareSummary
	}
	if src.TyposquatStatus != "" {
		dst.TyposquatStatus = src.TyposquatStatus
	}
	if src.TyposquatConfidence != "" {
		dst.TyposquatConfidence = src.TyposquatConfidence
	}
	if src.TyposquatSimilarTo != "" {
		dst.TyposquatSimilarTo = src.TyposquatSimilarTo
	}
	if src.TrustScore != 0 {
		dst.TrustScore = src.TrustScore
	}
	if src.TrustScoreBreakdown != "" {
		dst.TrustScoreBreakdown = src.TrustScoreBreakdown
	}
	if src.PublisherChanged != nil {
		dst.PublisherChanged = src.PublisherChanged
	}
	if len(src.PublisherAdded) > 0 {
		dst.PublisherAdded = src.PublisherAdded
	}
	if len(src.PublisherRemoved) > 0 {
		dst.PublisherRemoved = src.PublisherRemoved
	}
	if src.VersionAnomaly != nil {
		dst.VersionAnomaly = src.VersionAnomaly
	}
	if len(src.VersionAnomalyFlags) > 0 {
		dst.VersionAnomalyFlags = src.VersionAnomalyFlags
	}
	if src.PublishVelocity24h != 0 {
		dst.PublishVelocity24h = src.PublishVelocity24h
	}
	if src.PublishVelocityAnomaly != nil {
		dst.PublishVelocityAnomaly = src.PublishVelocityAnomaly
	}
	if src.RepoLinkStatus != "" {
		dst.RepoLinkStatus = src.RepoLinkStatus
	}
	if src.RepoLinkLastChecked != nil {
		dst.RepoLinkLastChecked = src.RepoLinkLastChecked
	}
	if src.RepoLastCommitAt != nil {
		dst.RepoLastCommitAt = src.RepoLastCommitAt
	}
	if src.RepoArchived != nil {
		dst.RepoArchived = src.RepoArchived
	}
	if src.ReservedNamespaceViolation != nil {
		dst.ReservedNamespaceViolation = src.ReservedNamespaceViolation
	}
	if src.ReservedNamespaceReason != "" {
		dst.ReservedNamespaceReason = src.ReservedNamespaceReason
	}
}

// mergeMaintenance populates Report.Maintenance from a provider's
// patch. Every field has a "missing" representation (nil for pointers,
// 0 for counts) so zero values never clobber a richer prior value.
// mergeVulns unions findings from multiple CVE providers — without this,
// the second provider to write Vulns wholesale-replaces the first, which
// is exactly how OSV's PyPI hits were being clobbered by Trivy's empty
// scan result on idna 3.6 / requests 2.31.0. CVE strings are deduped,
// CVSS takes the max, ScannedAt prefers the most recent.
func mergeVulns(dst *VulnSection, src VulnSection) {
	if src.ScannedAt != nil {
		if dst.ScannedAt == nil || src.ScannedAt.After(*dst.ScannedAt) {
			dst.ScannedAt = src.ScannedAt
		}
	}
	if src.IsVulnerable {
		dst.IsVulnerable = true
	}
	if src.CVSSScore > dst.CVSSScore {
		dst.CVSSScore = src.CVSSScore
	}
	if src.EPSSScore > dst.EPSSScore {
		dst.EPSSScore = src.EPSSScore
	}
	if src.KnownExploited {
		dst.KnownExploited = true
	}
	if src.ScannerDBDigest != "" && dst.ScannerDBDigest == "" {
		dst.ScannerDBDigest = src.ScannerDBDigest
	}
	// Union CVEs by string identity.
	if len(src.CVEs) > 0 {
		seen := make(map[string]struct{}, len(dst.CVEs)+len(src.CVEs))
		for _, c := range dst.CVEs {
			seen[c] = struct{}{}
		}
		for _, c := range src.CVEs {
			if _, ok := seen[c]; ok {
				continue
			}
			seen[c] = struct{}{}
			dst.CVEs = append(dst.CVEs, c)
		}
	}
	// Union CVEDetails by CVE id; prefer the entry that carries a
	// FixedVersion since that's the actionable signal.
	if len(src.CVEDetails) > 0 {
		idx := make(map[string]int, len(dst.CVEDetails))
		for i, d := range dst.CVEDetails {
			idx[d.CVE] = i
		}
		for _, d := range src.CVEDetails {
			if i, ok := idx[d.CVE]; ok {
				if dst.CVEDetails[i].FixedVersion == "" && d.FixedVersion != "" {
					dst.CVEDetails[i] = d
				}
				continue
			}
			idx[d.CVE] = len(dst.CVEDetails)
			dst.CVEDetails = append(dst.CVEDetails, d)
		}
	}
	// KEVEntries: same union-by-CVE treatment.
	if len(src.KEVEntries) > 0 {
		idx := make(map[string]struct{}, len(dst.KEVEntries))
		for _, k := range dst.KEVEntries {
			idx[k.CVE] = struct{}{}
		}
		for _, k := range src.KEVEntries {
			if _, ok := idx[k.CVE]; ok {
				continue
			}
			idx[k.CVE] = struct{}{}
			dst.KEVEntries = append(dst.KEVEntries, k)
		}
	}
}

func mergeMaintenance(dst *MaintenanceSection, src MaintenanceSection) {
	if src.LatestReleaseAt != nil {
		dst.LatestReleaseAt = src.LatestReleaseAt
	}
	if src.LastRepoCommitAt != nil {
		dst.LastRepoCommitAt = src.LastRepoCommitAt
	}
	if src.VersionCount != 0 {
		dst.VersionCount = src.VersionCount
	}
	if src.MaintainerCount != 0 {
		dst.MaintainerCount = src.MaintainerCount
	}
	if src.RepoArchived != nil {
		dst.RepoArchived = src.RepoArchived
	}
	// WeeklyDownloads: nil means "not yet fetched"; any non-nil value
	// (including the -1 sentinel) wins over nil.
	if src.WeeklyDownloads != nil {
		dst.WeeklyDownloads = src.WeeklyDownloads
	}
	// VersionTimeline: a non-empty slice always wins. The registry
	// provider populates this whole-cloth from the upstream packument,
	// so an incoming non-empty slice is authoritative.
	if len(src.VersionTimeline) > 0 {
		dst.VersionTimeline = src.VersionTimeline
	}
	// FirstPublishedAt — earliest publish time across the version
	// timeline. Set by the registry provider after applyTimeline runs.
	// Merge as "non-nil wins"; if both contributors have a value, take
	// the EARLIER one (a Tier-3 enricher reading a wider history must
	// not regress the timeline-derived value).
	if src.FirstPublishedAt != nil {
		if dst.FirstPublishedAt == nil || src.FirstPublishedAt.Before(*dst.FirstPublishedAt) {
			dst.FirstPublishedAt = src.FirstPublishedAt
		}
	}
	// GitHub repo activity. Zero is a valid value (a brand-new repo
	// has zero stars) so we cannot use "src != 0 wins" without losing
	// data; instead we treat any non-zero source value as authoritative
	// because the only producer is the registry provider's GitHub
	// fetcher, which never emits a partial result — either all four
	// fields populate or none do.
	if src.Stars != 0 || src.Forks != 0 || src.OpenIssues != 0 || src.Subscribers != 0 {
		dst.Stars = src.Stars
		dst.Forks = src.Forks
		dst.OpenIssues = src.OpenIssues
		dst.Subscribers = src.Subscribers
	}
}

// mergeDependencies overwrites the destination lists when the source
// non-empty. Dependency lists are produced wholesale by the
// registrymetadata provider — there is no incremental contributor —
// so a non-empty incoming Direct/Dev/Peer/Optional always replaces.
func mergeDependencies(dst *DependenciesSection, src DependenciesSection) {
	if len(src.Direct) > 0 {
		dst.Direct = src.Direct
	}
	if len(src.Dev) > 0 {
		dst.Dev = src.Dev
	}
	if len(src.Peer) > 0 {
		dst.Peer = src.Peer
	}
	if len(src.Optional) > 0 {
		dst.Optional = src.Optional
	}
}

var _ Service = (*DefaultService)(nil)
