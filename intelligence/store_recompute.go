package intelligence

// The read side of the matcher-epoch recompute backlog.
//
// Store.Facets already COUNTs the backlog (see the StalePending column in
// Facets' aggregate) and four consumers render that number, ending at a stat
// pill on the package-inventory sidebar. Nothing DRAINED it. The scheduled
// Refresher walks package_metadata, and package_metadata is written only by
// the proxy download path (internal/server/package_metadata.go), the internal
// upload handler and the CocoaPods trunk handler — so every
// intelligence_reports row minted by the CLI lockfile scanner, `intel scan`,
// the async scan worker, transitive fan-out, cache-warm, the publish pre-run,
// MCP and the refresher's OWN new-version discovery had no walkable row and
// could never be recomputed. Those rows report MatcherStale forever, which is
// precisely the outcome the epoch counter exists to retract.
//
// This file supplies the second walk source, keyed on the population itself
// rather than on a table that happens to correlate with it: the same epoch
// predicate Facets uses, paginated so a sweep can be paced and resumed.
//
// The epoch is read out of the report JSONB rather than a column because that
// is where it is persisted; TestMatcherEpochJSONPathMatchesTheSQL
// (store_matcher_stale_test.go) pins the path against the struct tags, and the
// COALESCE reproduces MatcherStale()'s treatment of a row written before the
// field existed — no key means epoch 0, which is below every real epoch.

import (
	"context"
	"fmt"
)

// matcherEpochExpr is the SQL that lifts the persisted matcher epoch out of
// the report blob. Held as one constant because the sweep repeats it three
// times in a single statement (predicate, keyset tuple, ORDER BY) and a
// divergence between any two of them would page incorrectly — skipping rows
// while still reporting progress, which is the failure mode that is hardest
// to notice.
//
// Kept textually identical to the expression in Store.Facets and
// Store.Search. If you change one, change all three: the counter that says
// "3,171 pending" and the walk that drains them must agree on what pending
// means, or the pill never reaches zero no matter how long the sweep runs.
const matcherEpochExpr = `COALESCE(NULLIF(report->'observation'->>'matcherEpoch', '')::int, 0)`

// MatcherStaleRow is one coordinate awaiting recompute. It carries only what
// a Scan needs (the coordinate) plus the epoch it is currently at, which the
// sweeper logs and orders on.
//
// There is deliberately no OrgID: intelligence_reports has no org_id column
// (core/pgstore/migrate.go:1444 drops it) because a package fact is universal.
// A recompute therefore runs with OrgID "" exactly as the transitive
// dep-enqueuer does (dep_enqueuer.go:174).
type MatcherStaleRow struct {
	Ecosystem string
	Package   string
	Version   string
	Epoch     int
}

// MatcherStaleCursor is the keyset position for IterateMatcherStale.
//
// Keyset rather than OFFSET because the sweep mutates its own result set: a
// row that is successfully recomputed leaves the predicate. With OFFSET the
// rows behind it shift forward and the next page skips exactly as many rows
// as the last page fixed. With a keyset, a recomputed row simply stops
// matching and everything after it keeps its position.
type MatcherStaleCursor struct {
	Epoch     int
	Ecosystem string
	Package   string
	Version   string
}

// IsZero reports whether the cursor is the start-of-walk sentinel. Ecosystem
// is NOT NULL and never empty in a real row, so an empty Ecosystem is an
// unambiguous "before the first row".
func (c MatcherStaleCursor) IsZero() bool { return c.Ecosystem == "" }

// RecomputeSource is the narrowed surface the sweeper needs from the store.
// Mirrors MetadataSource (refresher.go) so tests can drive the sweep from an
// in-memory slice without a Postgres handle, while production passes the real
// *Store.
type RecomputeSource interface {
	IterateMatcherStale(ctx context.Context, after MatcherStaleCursor, limit int) ([]MatcherStaleRow, MatcherStaleCursor, error)
	CountMatcherStale(ctx context.Context) (int, error)
}

// IterateMatcherStale returns the next page of coordinates whose persisted
// matcher epoch is behind CurrentMatcherEpoch, plus the cursor to resume from.
// A zero returned cursor means the walk is complete.
//
// Ordering is oldest epoch first, then the primary key. Epoch-ascending is the
// deliberate choice for two reasons. First, severity: a row at epoch 3 is
// superseded by every matcher fix from 4 onwards, so it is wrong in more ways
// and has been wrong for longer than a row at epoch 5 — draining it first
// retires the most accumulated error per Scan. Second, termination: with three
// further bumps planned, a newest-first order would let each bump's fresh
// arrivals jump ahead of the rows the previous bump never finished, and the
// oldest rows would starve indefinitely. Ascending epoch cannot starve —
// nothing new is ever added below the current floor.
//
// The PK tiebreak makes the total order strict, which is what the keyset
// comparison requires; within one epoch the order is arbitrary but stable.
func (s *Store) IterateMatcherStale(ctx context.Context, after MatcherStaleCursor, limit int) ([]MatcherStaleRow, MatcherStaleCursor, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return nil, MatcherStaleCursor{}, nil
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}

	args := []any{CurrentMatcherEpoch}
	keyset := ""
	if !after.IsZero() {
		// Row-value comparison so the four sort keys advance as one
		// tuple. Spelling them out as chained ORs is where this kind of
		// pagination usually acquires an off-by-one.
		keyset = fmt.Sprintf(
			" AND (%s, ecosystem, package_name, version) > ($2, $3, $4, $5)",
			matcherEpochExpr)
		args = append(args, after.Epoch, after.Ecosystem, after.Package, after.Version)
	}
	args = append(args, limit)

	query := fmt.Sprintf(`
		SELECT ecosystem, package_name, version, %s AS matcher_epoch
		FROM intelligence_reports
		WHERE %s < $1%s
		ORDER BY matcher_epoch ASC, ecosystem ASC, package_name ASC, version ASC
		LIMIT $%d
	`, matcherEpochExpr, matcherEpochExpr, keyset, len(args))

	rows, err := s.sql.DB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, MatcherStaleCursor{}, fmt.Errorf("intelligence: iterate matcher-stale: %w", err)
	}
	defer rows.Close()

	out := make([]MatcherStaleRow, 0, limit)
	for rows.Next() {
		var r MatcherStaleRow
		if err := rows.Scan(&r.Ecosystem, &r.Package, &r.Version, &r.Epoch); err != nil {
			return nil, MatcherStaleCursor{}, fmt.Errorf("intelligence: scan matcher-stale row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, MatcherStaleCursor{}, fmt.Errorf("intelligence: iterate matcher-stale rows: %w", err)
	}

	// A short page is the end of the walk. Returning a non-zero cursor here
	// would cost one extra empty round-trip per sweep and, more importantly,
	// would make "did we finish" ambiguous for the caller's budget accounting.
	if len(out) < limit {
		return out, MatcherStaleCursor{}, nil
	}
	last := out[len(out)-1]
	return out, MatcherStaleCursor{
		Epoch:     last.Epoch,
		Ecosystem: last.Ecosystem,
		Package:   last.Package,
		Version:   last.Version,
	}, nil
}

// CountMatcherStale returns the size of the recompute backlog — the same
// number Store.Facets reports as FacetCounts.StalePending, isolated so the
// sweeper can sample it without paying for the eleven other aggregates on that
// row.
//
// This is the producer for the chainsaw_intel_recompute_backlog gauge. Facets
// is only reached when a human loads the inventory sidebar, so before this
// existed the backlog was observable exclusively by someone looking at a
// dashboard — no metric, no alert, and therefore no way for a sweep that
// stopped draining to be noticed by anything other than a person who happened
// to remember yesterday's number.
func (s *Store) CountMatcherStale(ctx context.Context) (int, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return 0, nil
	}
	var n int
	query := fmt.Sprintf(
		`SELECT COUNT(*) FROM intelligence_reports WHERE %s < $1`, matcherEpochExpr)
	if err := s.sql.DB().QueryRowContext(ctx, query, CurrentMatcherEpoch).Scan(&n); err != nil {
		return 0, fmt.Errorf("intelligence: count matcher-stale: %w", err)
	}
	return n, nil
}
