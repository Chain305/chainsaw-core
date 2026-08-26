package intelligence

// The caller-facing half of the `latest`-sentinel cleanup (P8-45).
//
// latest_resolution.go decides WHICH coordinates get dereferenced before a
// Scan; core/pgstore/migrate_latest_sentinel.go knows how to remove the
// rows that were written before that dereference existed. pgstore cannot
// import this package (this one imports pgstore, store.go:14), so the
// predicate parameters travel the other way: this file hands them over,
// sourced from latestResolvableEcosystems — the same slice the resolver
// itself switches on.
//
// That indirection is the point, and here it is a safety property rather
// than a tidiness one. The cleanup issues a DELETE against a shared,
// org-less cache table. If a second hand-maintained list of "ecosystems we
// can resolve" ever drifted WIDER than the resolver, the purge would delete
// rows whose coordinate is still unresolvable — they would come straight
// back with the identical NOT EVALUATED answer, one upstream fetch each.
// If it drifted NARROWER, rows would be left serving a wrong verdict
// forever. One slice, no drift.
//
// Nothing here runs automatically. See the pgstore file's header for why a
// DELETE is opt-in rather than a boot-time migration, and for what is
// deliberately retained.

import (
	"context"

	"github.com/chain305/chainsaw-core/pgstore"
)

// LatestSentinelRule exports this package's resolver definition in the
// shape pgstore's cleanup consumes. The slice is copied so a caller cannot
// mutate the package-level definition through the returned value.
//
// docker and the Maven family are absent from latestResolvableEcosystems
// by construction, which is what keeps a real docker `latest` tag and a
// Maven `LATEST` resolver directive out of the DELETE. See
// ResolvableLatestSentinel for why each is excluded.
func LatestSentinelRule() pgstore.LatestSentinelRule {
	return pgstore.LatestSentinelRule{
		Sentinel:   LatestSentinel,
		Ecosystems: append([]string(nil), latestResolvableEcosystems...),
	}
}

// LatestSentinelCleanupCounts is the read-only dry run, bucketed by
// ecosystem into what would be deleted and what would be retained. Run it
// immediately before purging.
func (s *Store) LatestSentinelCleanupCounts(ctx context.Context) ([]pgstore.LatestSentinelCount, error) {
	if s == nil || s.sql == nil {
		return nil, nil
	}
	return s.sql.LatestSentinelCounts(ctx, LatestSentinelRule())
}

// PurgeLatestSentinelCoordinates removes the intelligence_reports rows
// keyed on the literal string `latest` in the ecosystems this package can
// now dereference. Returns the number of rows removed.
//
// OPT-IN. Not wired into Open(), bootstrap, or any refresh tick. Call it
// from an operator-triggered path, after LatestSentinelCleanupCounts.
func (s *Store) PurgeLatestSentinelCoordinates(ctx context.Context) (int64, error) {
	if s == nil || s.sql == nil {
		return 0, nil
	}
	return s.sql.PurgeLatestSentinelCoordinates(ctx, LatestSentinelRule())
}
