package intelligence

// The read side of the incomplete-transitive-coverage backlog.
//
// WHY THIS EXISTS
//
// evaluateTransitiveRisk scores a package against the dependency rows that
// happen to be in cache AT THE MOMENT THE PARENT IS SCANNED. On a cold cache
// that is often none of them: the scanner runs the tree overlay first and
// enqueueDependencyScans second, so the very first scan of a root almost
// always models an empty closure, persists a rollup computed from it, and
// only then starts warming the children.
//
// Nothing ever went back. The parent's persisted verdict stayed pinned to the
// closure it saw on that first pass, however much of the tree arrived
// afterwards. `TransitiveCoverage.Complete` recorded that the rollup was
// partial and four surfaces render the number, but no sweep consumed it — the
// same shape of gap the matcher-epoch sweep was built to close, and it is
// filled here the same way.
//
// Measured on the 7,099-row production export: 699 rows carry
// `complete: false`; 296 of them have a closure that has since warmed; and
// 122 of those now model a STRICTLY WORSE verdict than the one persisted —
// `allow` rows that are really `warn` or `quarantine`. Every one of the 122
// moved in the under-reporting direction. Zero moved the other way, which is
// what makes this a one-directional correctness bug rather than churn:
// `nuget/Microsoft.AspNetCore.Routing.Abstractions@2.2.0` is served `allow`
// and models `quarantine` on 1 critical + 2 high transitive advisories.
//
// The recompute is deliberately CHEAP — see Refresher.recomputeCoverageRow.
// The root's own facts have not changed, only its descendants' availability,
// so the overlay is re-run against the current cache with no upstream fetch.

import (
	"context"
	"fmt"
)

// coverageIncompleteExpr is the SQL predicate for "this row's rollup was
// computed against a partial closure".
//
// `->>'complete' = 'false'` rather than `NOT (...)::boolean` so a row whose
// report predates the field, or never ran the overlay at all, is NOT selected:
// those have no coverage record and re-running the overlay on them would tell
// us nothing new. Only a row that explicitly recorded an incomplete walk is a
// candidate.
//
// Kept as one constant because the walk repeats it in the predicate and the
// COUNT, and a divergence between them is the failure mode where the backlog
// gauge never reaches zero no matter how long the sweep runs.
const coverageIncompleteExpr = `report->'supplyChain'->'transitiveCoverage'->>'complete'`

// coverageResolvedExpr lifts the number of direct deps that WERE resolved at
// scan time, so the sweep can order by it and skip rows that resolved nothing
// last. COALESCE to 0 mirrors the field's omitempty encoding.
const coverageResolvedExpr = `COALESCE(NULLIF(report->'supplyChain'->'transitiveCoverage'->>'resolved', '')::int, 0)`

// CoverageStaleRow is one coordinate whose rollup was computed against a
// partial dependency closure.
//
// As with MatcherStaleRow there is deliberately no OrgID: intelligence_reports
// has no org_id column because a package fact is universal, so the recompute
// runs with OrgID "" exactly as the dep-enqueuer does.
type CoverageStaleRow struct {
	Ecosystem string
	Package   string
	Version   string
	// Resolved is how many direct deps the ORIGINAL scan managed to
	// resolve. The sweep compares the post-recompute number against it to
	// decide whether anything actually changed.
	Resolved int
}

// CoverageStaleCursor is the keyset position for IterateCoverageStale.
//
// Keyset rather than OFFSET for the same reason as the matcher-epoch walk:
// the sweep mutates its own result set. A row that recomputes to complete
// leaves the predicate, and with OFFSET every row behind it shifts forward so
// the next page skips exactly as many rows as the last page fixed.
type CoverageStaleCursor struct {
	Resolved  int
	Ecosystem string
	Package   string
	Version   string
}

// IsZero reports whether the cursor is the start-of-walk sentinel.
func (c CoverageStaleCursor) IsZero() bool { return c.Ecosystem == "" }

// CoverageRecomputeSource is the narrowed surface the coverage sweeper needs.
// Mirrors RecomputeSource so tests can drive the sweep from an in-memory slice.
type CoverageRecomputeSource interface {
	IterateCoverageStale(ctx context.Context, after CoverageStaleCursor, limit int) ([]CoverageStaleRow, CoverageStaleCursor, error)
	CountCoverageStale(ctx context.Context) (int, error)
}

// IterateCoverageStale returns the next page of coordinates whose persisted
// rollup was computed against a partial closure.
//
// Ordering is fewest-resolved first, then the primary key. A row that resolved
// 0 of 9 deps is carrying the largest possible error — its rollup is a
// direct-only score wearing a transitive label — so it is worth the most per
// recompute. It is also the population most likely to have warmed since, being
// the rows scanned earliest against the coldest cache.
//
// The PK tiebreak makes the total order strict, which is what the keyset
// comparison requires.
func (s *Store) IterateCoverageStale(ctx context.Context, after CoverageStaleCursor, limit int) ([]CoverageStaleRow, CoverageStaleCursor, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return nil, CoverageStaleCursor{}, nil
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}

	args := []any{}
	keyset := ""
	if !after.IsZero() {
		keyset = fmt.Sprintf(
			" AND (%s, ecosystem, package_name, version) > ($1, $2, $3, $4)",
			coverageResolvedExpr)
		args = append(args, after.Resolved, after.Ecosystem, after.Package, after.Version)
	}
	args = append(args, limit)

	query := fmt.Sprintf(`
		SELECT ecosystem, package_name, version, %s AS resolved
		FROM intelligence_reports
		WHERE %s = 'false'%s
		ORDER BY resolved ASC, ecosystem ASC, package_name ASC, version ASC
		LIMIT $%d
	`, coverageResolvedExpr, coverageIncompleteExpr, keyset, len(args))

	rows, err := s.sql.DB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, CoverageStaleCursor{}, fmt.Errorf("intelligence: iterate coverage-stale: %w", err)
	}
	defer rows.Close()

	out := make([]CoverageStaleRow, 0, limit)
	for rows.Next() {
		var r CoverageStaleRow
		if err := rows.Scan(&r.Ecosystem, &r.Package, &r.Version, &r.Resolved); err != nil {
			return nil, CoverageStaleCursor{}, fmt.Errorf("intelligence: scan coverage-stale row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, CoverageStaleCursor{}, fmt.Errorf("intelligence: iterate coverage-stale rows: %w", err)
	}

	// A short page ends the walk. Returning a non-zero cursor would cost an
	// extra empty round-trip and make "did we finish" ambiguous for the
	// caller's budget accounting.
	if len(out) < limit {
		return out, CoverageStaleCursor{}, nil
	}
	last := out[len(out)-1]
	return out, CoverageStaleCursor{
		Resolved:  last.Resolved,
		Ecosystem: last.Ecosystem,
		Package:   last.Package,
		Version:   last.Version,
	}, nil
}

// CountCoverageStale returns the size of the incomplete-coverage backlog.
// Producer for the chainsaw_intel_coverage_backlog gauge.
func (s *Store) CountCoverageStale(ctx context.Context) (int, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return 0, nil
	}
	var n int
	query := fmt.Sprintf(
		`SELECT COUNT(*) FROM intelligence_reports WHERE %s = 'false'`, coverageIncompleteExpr)
	if err := s.sql.DB().QueryRowContext(ctx, query).Scan(&n); err != nil {
		return 0, fmt.Errorf("intelligence: count coverage-stale: %w", err)
	}
	return n, nil
}
