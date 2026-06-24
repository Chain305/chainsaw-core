package intelligence

import (
	"context"
	"errors"
	"log/slog"
	"time"
)

// ErrNotFound indicates a cached Report does not exist for a Key.
var ErrNotFound = errors.New("intelligence: report not found")

// ErrInvalidKey is the sentinel returned by Scan when the request Key
// is shape-malformed (empty ecosystem, package, or version). It is a
// deterministic, retry-immune failure — callers (notably the scan
// worker) use errors.Is to short-circuit retry budgets so a crafted
// lockfile of malformed keys cannot pin the worker pool.
var ErrInvalidKey = errors.New("intelligence: invalid key")

// Service is the single entrypoint for package intelligence. Inline proxy,
// admin HTTP API, and future external consumers all go through this.
type Service interface {
	// Scan is cache-first, singleflight-coalesced, and partial-success.
	// It never returns an error except when ctx is cancelled or the input
	// is malformed — provider failures degrade the Report with Warnings.
	Scan(ctx context.Context, req Request) (*Report, error)

	// Get returns the cached Report or ErrNotFound. Never fetches upstream.
	Get(ctx context.Context, orgID string, key Key) (*Report, error)

	// Search powers the admin UI list view. Backed by the scalar columns
	// on intelligence_reports plus the name tsvector index.
	Search(ctx context.Context, q SearchQuery) (*SearchResults, error)

	// Facets returns the aggregate counts used by the Shodan-style
	// sidebar (ecosystem breakdown, signal toggle counts, risk tiers).
	// Counts are over the full org — the UI's sidebar shows "what's
	// available to filter on" rather than "what's left after my filter".
	Facets(ctx context.Context, orgID string) (*FacetCounts, error)

	// VerifyChecksum is the fail-closed hot path used by the proxy's
	// existing checksum enforcer. Runs only the checksum provider,
	// bypassing the full Tier-1 fan-out.
	VerifyChecksum(ctx context.Context, req ChecksumRequest) (ChecksumVerdict, error)
}

// Config wires the DefaultService's dependencies.
type Config struct {
	Store     *Store
	Providers []Provider
	Logger    *slog.Logger
	// Now lets tests freeze time. nil → time.Now.
	Now func() time.Time
}

// NoopService is the zero-dependency Service — returns ErrNotFound on
// every Get, an empty Report with a WarnFeatureDisabled warning on every
// Scan. Wired when the CHAINSAW_INTELLIGENCE_SERVICE flag is off.
type NoopService struct{}

// Scan on the noop returns an empty Report tagged feature_disabled. This
// keeps the inline proxy path type-safe while the feature is flagged off.
func (NoopService) Scan(ctx context.Context, req Request) (*Report, error) {
	now := time.Now().UTC()
	r := &Report{
		Identity: IdentitySection{
			Ecosystem: req.Key.Ecosystem,
			Package:   req.Key.Package,
			Version:   req.Key.Version,
		},
		Observation: ObservationSection{
			CollectedAt:   now,
			FreshUntil:    now,
			RefreshReason: req.Options.RefreshReason,
			Warnings: []Warning{{
				Provider: "service",
				Code:     WarnFeatureDisabled,
				Message:  "intelligence service is disabled",
				At:       now,
			}},
		},
	}
	return r, nil
}

// Get always returns ErrNotFound on the noop.
func (NoopService) Get(ctx context.Context, orgID string, key Key) (*Report, error) {
	return nil, ErrNotFound
}

// Search returns an empty result set.
func (NoopService) Search(ctx context.Context, q SearchQuery) (*SearchResults, error) {
	return &SearchResults{}, nil
}

// Facets returns an empty facet block.
func (NoopService) Facets(ctx context.Context, orgID string) (*FacetCounts, error) {
	return &FacetCounts{}, nil
}

// VerifyChecksum on the noop compares declared==actual directly (no DB).
// Matches the trivial case of the real provider so proxy tests that wire a
// NoopService still see checksum enforcement work end-to-end.
func (NoopService) VerifyChecksum(ctx context.Context, req ChecksumRequest) (ChecksumVerdict, error) {
	if req.Declared == "" {
		return ChecksumVerdict{Status: "unavailable", Reason: "no declared hash"}, nil
	}
	if req.Actual == "" {
		return ChecksumVerdict{Status: "unavailable", Reason: "no actual hash"}, nil
	}
	if req.Declared == req.Actual {
		return ChecksumVerdict{Matched: true, Status: "matched"}, nil
	}
	return ChecksumVerdict{Status: "mismatch", Reason: "declared hash does not match actual"}, nil
}

var _ Service = NoopService{}
