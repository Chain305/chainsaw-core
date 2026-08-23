package intelligence

// The caller-facing half of the unevaluable-coordinate cleanup.
//
// version_evaluable.go defines WHICH coordinates can never be ordered against
// an advisory range and stops new ones being ingested;
// core/pgstore/migrate_unevaluable_coordinates.go knows how to remove the rows
// that were written before that gate existed. pgstore cannot import this
// package (this one imports pgstore, core/intelligence/store.go:14), so the
// predicate parameters travel the other way: this file hands them over.
//
// That indirection is the point. If the ingest gate ever learns a new alias —
// a fourth Maven-family ecosystem name, another Maven meta-version — the
// cleanup picks it up from the same slice, so the population that gets deleted
// cannot drift from the population that gets refused.
//
// Nothing here runs automatically. See the pgstore file's header for why a
// DELETE is opt-in rather than a boot-time migration, and for what is
// deliberately retained.

import (
	"context"

	"github.com/chain305/chainsaw-core/pgstore"
)

// UnevaluableCoordinateRule exports this package's ingest-gate constants in
// the shape pgstore's cleanup consumes. The slices are copied so a caller
// cannot mutate the package-level definitions through the returned value.
func UnevaluableCoordinateRule() pgstore.UnevaluableCoordinateRule {
	return pgstore.UnevaluableCoordinateRule{
		UnresolvedPropertyMarker: unresolvedPropertyMarker,
		MavenFamilyEcosystems:    append([]string(nil), mavenFamilyEcosystems...),
		MavenNonVersions:         append([]string(nil), mavenNonVersions...),
	}
}

// UnevaluableCoordinateCleanupCounts is the read-only dry run for the cleanup,
// bucketed by ecosystem into what would be deleted and what would be retained.
//
// It answers a narrower question than UnevaluableVersionCounts, and both are
// worth having: that one is the census of the blind spot (every unevaluable
// row, bucketed by REASON, which is what tells an operator which producer to
// go fix), this one is the preview of a mutation (the same rows bucketed into
// delete/keep). Run the census to understand the problem; run this immediately
// before purging.
func (s *Store) UnevaluableCoordinateCleanupCounts(ctx context.Context) ([]pgstore.UnevaluableCoordinateCount, error) {
	if s == nil || s.sql == nil {
		return nil, nil
	}
	return s.sql.UnevaluableCoordinateCounts(ctx, UnevaluableCoordinateRule())
}

// PurgeUnevaluableCoordinates removes the intelligence_reports rows whose
// version can never be matched, using this package's own definition of
// "unevaluable". Returns the number of rows removed.
//
// OPT-IN. This is not wired into Open(), bootstrap, or any refresh tick, and
// it should not be: see core/pgstore/migrate_unevaluable_coordinates.go for
// the reasoning. Call it from an operator-triggered path, after
// UnevaluableCoordinateCleanupCounts.
func (s *Store) PurgeUnevaluableCoordinates(ctx context.Context) (int64, error) {
	if s == nil || s.sql == nil {
		return 0, nil
	}
	return s.sql.PurgeUnevaluableCoordinates(ctx, UnevaluableCoordinateRule())
}
