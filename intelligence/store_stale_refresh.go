package intelligence

// The read half of the stale-report refresh sweep. See
// refresher_stale_reports.go for why the sweep exists.

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// StaleReportRow is one coordinate whose stored report has aged past the
// staleness bound. It carries no org: `intelligence_reports` has no `org_id`
// column (that is L-02), and a refresh does not need one — `Scan` produces the
// org-independent report and `recomputeRow` already refreshes by Key alone.
type StaleReportRow struct {
	Ecosystem   string
	Package     string
	Version     string
	CollectedAt time.Time
}

// StaleReportCursor is the keyset position: (collected_at, ecosystem, package,
// version). The PK tiebreak makes the order strict, which the keyset
// comparison requires.
type StaleReportCursor struct {
	CollectedAt time.Time
	Ecosystem   string
	Package     string
	Version     string
}

func (c StaleReportCursor) IsZero() bool { return c.CollectedAt.IsZero() && c.Ecosystem == "" }

// StaleReportScope is the sweep's population: every report older than
// OlderThan, plus — when ArtifactEcosystems is non-empty — every report that
// has never had an artifact scan, in an ecosystem the sweep can fetch bytes
// for, once it is older than ArtifactOlderThan.
//
// The second half exists because staleness alone never reaches them. The
// dependency cache-warm and new-version detection refresh a row WITHOUT bytes
// and stamp it fresh, so the one writer that does fetch bytes (this sweep)
// skipped it for another 24h, and a popular dependency was re-warmed bytes-less
// indefinitely. Measured 2026-09-24: nuget 140 of 143 freshly refreshed rows
// had no artifact scan, maven 603 of 870.
//
// ArtifactOlderThan is the retry cool-down for a package whose bytes cannot be
// fetched at all (a Maven `pom` packaging, a 404, a gated model): each such row
// costs one extra refresh per cool-down, not one per tick. A row whose report
// carries WarnArtifactTooLarge is excluded outright: an over-cap artifact stays
// over the cap, so retrying it every cool-down would re-download up to the cap
// for nothing. The plain staleness half still refreshes it.
//
// "Never scanned" reads the merged report JSON — what the report itself says —
// rather than the has_artifact_scan projection. The upsert ORs that column with
// its stored value, so it cannot go false after a bytes-less rewrite; measured
// 2026-09-24, zero rows had the column false with the JSON true.
type StaleReportScope struct {
	OlderThan          time.Time
	ArtifactEcosystems []string
	ArtifactOlderThan  time.Time

	// StaleAnalyzer and StaleAnalyzerVersion select the SELECTIVE-BACKFILL
	// half (A-3): coordinates whose artifact holds an analysis from a
	// superseded version of one named analyzer. Both must be set; build them
	// through StaleAnalyzerScope rather than by hand, so a typo'd analyzer
	// name is rejected instead of selecting zero rows and reading as
	// "nothing to do".
	//
	// This half exists so that an analyzer upgrade reworks only the rows that
	// analyzer ran on. It rides the sweep every other half rides — there is
	// no separate worker, no separate budget and no separate backlog gauge.
	StaleAnalyzer        string
	StaleAnalyzerVersion int
}

// declaredCoordinateAntiJoin excludes every coordinate that a LIVE monitored
// target declares (C-6). It is ANDed onto both halves of the scope, and it is
// unconditional: there is no knob, because a knob here would be a knob for
// "silently eat the declared-inventory alert".
//
// WHY THIS SWEEP MUST NOT TOUCH A DECLARED COORDINATE. The sweep refreshes by
// Key and dispatches NOTHING — refresher_stale_reports.go, refresher_recompute.go
// and refresher_coverage.go contain zero references to the alerter, and
// OnRefreshedReport has exactly one call site (refresher.go, the primary walk).
// Declared inventory is the one audience an orphan can have: monitored_targets
// carries org_id, and a declared coordinate the proxy never served has NO
// package_metadata row (that table's only non-test writer is the proxy serve
// path, internal/server/package_metadata.go), so the walk never visits it.
// internal/monitorsweep diffs `Get` against `Scan` on the single shared
// intelligence_reports row, and its Scan passes no MaxStaleness — so once this
// sweep has refreshed the row, that diff is prior == next and the transition is
// gone. The sweep was consuming the only diff window a paying audience had, and
// then throwing it away.
//
// HOW THIS DIFFERS FROM THE "NO ANTI-JOIN" DECISION IN refresher_stale_reports.go.
// That header refuses an anti-join against package_metadata, and the reason it
// gives is that the join BUYS NOTHING: "a coordinate the walk covers is kept
// fresh by the walk, so the staleness predicate already excludes it." That
// reasoning is correct and it does not transfer. This join is not deduplicating
// work — it is protecting a diff window that only one other caller can open,
// and the staleness predicate cannot express that because staleness is exactly
// what both callers key on. The cost is also opposite: the package_metadata
// join would have scanned a table the size of the walk for no answer, whereas
// monitored_targets is small and GIN-indexed on package_set
// (idx_monitored_targets_package_set).
//
// NO COVERAGE IS LOST. A declared coordinate is still refreshed — by
// monitorsweep, on its own 30-minute cadence, which is what re-opens the window
// it now gets to keep.
//
// THE TABLE NAME IS THE WHOLE DEPENDENCY. core/ cannot import internal/, and it
// does not need to: monitored_targets' schema is created by
// core/pgstore.Store.ensureMonitoredTargetsSchema, so core already owns this
// table; internal/monitoredtargets is only its Go-side reader. The alternative
// seam — a row predicate injected through RefresherConfig — was rejected for
// two reasons. It would run per candidate row, turning one SQL predicate into
// one round trip per row of the backlog, and it would sit OUTSIDE the COUNT(*)
// that feeds chainsaw_intel_stale_report_backlog, so the gauge and the walk
// would disagree about the population. Sharing one predicate between the count
// and the iteration is the same discipline core/pgstore's retainedClause uses
// for exactly that reason.
//
// The package_set SHAPE is duplicated knowledge: these three keys are
// scan.PackageKey's json tags, and core cannot import that type.
// TestDeclaredPackageSetShapeMatchesPackageKey in internal/monitoredtargets
// fails if the tags are renamed, which is the only way this string can rot.
// THE SHAPE IS UNCORRELATED ON PURPOSE, AND THE OBVIOUS SHAPE IS UNUSABLE.
// The first cut of this was the natural one — a correlated
// `NOT EXISTS (… WHERE mt.package_set @> jsonb_build_array(jsonb_build_object(
// 'ecosystem', intelligence_reports.ecosystem, …)))` — and it is a trap.
// Measured on a seeded database (5,000 stale reports, one target declaring
// 19,083 coordinates): it did not finish in 120 seconds and took the Docker VM
// down with it. Two reasons compound. The right-hand operand is built from the
// OUTER row, so the GIN index cannot be probed with a constant and the planner
// picks a nested loop; and monitored_targets holds very few rows, so the inner
// side is a seq scan that DETOASTS a ~1.5 MB package_set and walks all 19,083
// elements once per candidate report row.
//
// So the subquery references no outer column: it flattens every live target's
// package_set ONCE, and the planner evaluates it a single time into a hash.
// The IS NOT NULL guards are load-bearing rather than defensive — with NOT IN,
// a single NULL in the subquery makes the predicate NULL for every row, which
// would exclude the ENTIRE backlog and silently switch the sweep off. An
// element missing a key would do it.
const declaredCoordinateAntiJoin = `(intelligence_reports.ecosystem,
		 intelligence_reports.package_name,
		 intelligence_reports.version) NOT IN (
		SELECT p->>'ecosystem', p->>'name', p->>'version'
		  FROM monitored_targets mt, LATERAL jsonb_array_elements(mt.package_set) p
		 WHERE mt.archived_at IS NULL
		   AND p->>'ecosystem' IS NOT NULL
		   AND p->>'name' IS NOT NULL
		   AND p->>'version' IS NOT NULL)`

// reportArtifactSHAExpr resolves a report row's artifact digest, preferring the
// denormalised column and falling back to the report JSONB.
//
// BOTH ARMS ARE LOAD-BEARING, AND THE REASON IS A MIGRATION WINDOW, NOT
// INDECISION.
//
// The column became real only when store.go started sourcing it from
// Artifact.Digests.SHA256; before that it was NULL for every row in the corpus,
// because its old source (Scan.ScannedArtifactSHA) is a field no provider has
// ever assigned. Rows gain the column only as they are re-upserted, and this
// cache is only backfilled as rows rescan — a window with no fixed end, since
// the stale-report sweep measured 91.8% of the coordinates the walk never
// reaches as stale. So:
//
//	column  the only arm that SURVIVES a metadata-only rescan. The upsert
//	        COALESCEs it, whereas `report` is replaced wholesale and
//	        mergeReportPayload preserves Digests.Actual and .Verified but NOT
//	        .SHA256 — so a byte-scanned row that is later Tier-1 refreshed
//	        keeps the column and loses the JSON key.
//	JSONB   every row written before the column was real whose last scan
//	        carried bytes.
//
// They can never disagree: both are Artifact.Digests.SHA256, one denormalised
// from the other in the same statement.
//
// Digests.Actual is NOT a third arm, though it survives the merge where SHA256
// does not. On the swift path `digests.Actual = altHex` holds a sha1/sha512
// when the declared algorithm is not sha256, so it is not reliably a sha256 and
// must not be compared against one. The cost is stated rather than hidden: a
// pre-column row that was byte-scanned and has since been metadata-refreshed
// has neither arm and is unselectable until its next scan with bytes. Those are
// precisely the rows the stale sweep targets.
//
// No expression index backs the JSONB arm. The backfill is a background sweep
// over a table in the low tens of thousands of rows, and an extra index on the
// hottest write path in the product is a worse trade than a sequential scan on
// a sweep that runs when an analyzer is upgraded. The column arm needs none
// either: it is read, never searched.
const reportArtifactSHAExpr = `COALESCE(
		NULLIF(intelligence_reports.artifact_sha256, ''),
		NULLIF(intelligence_reports.report->'artifact'->'digests'->>'sha256', ''))`

// where renders the scope as a WHERE predicate whose placeholders start at $1,
// and returns its arguments.
//
// Every return ANDs declaredCoordinateAntiJoin on. Both callers
// (CountStaleReports, IterateStaleReports) go through here, which is the point:
// a second rendering of this predicate is how the gauge and the walk would
// drift apart.
// It now renders as ONE return over a list of halves rather than a return per
// half. That is deliberate: the previous shape had each half append the
// anti-join itself, which is the drift
// TestStaleReportScopeExcludesDeclaredOnTheArtifactHalf was written to catch.
// With one tail there is nothing left to forget, and adding a fourth half
// cannot reintroduce it.
func (sc StaleReportScope) where() (string, []any) {
	args := []any{sc.OlderThan}
	halves := []string{"collected_at < $1"}

	if len(sc.ArtifactEcosystems) > 0 {
		args = append(args, sc.ArtifactOlderThan)
		olderThan := len(args)
		in := make([]string, len(sc.ArtifactEcosystems))
		for i, eco := range sc.ArtifactEcosystems {
			args = append(args, eco)
			in[i] = fmt.Sprintf("$%d", len(args))
		}
		halves = append(halves, fmt.Sprintf(`(collected_at < $%d
		AND NOT COALESCE((report->'artifactScan'->>'performed')::boolean, false)
		AND NOT COALESCE(report->'observation'->'warnings' @> '[{"code":"%s"}]'::jsonb, false)
		AND ecosystem IN (%s))`, olderThan, WarnArtifactTooLarge, strings.Join(in, ", ")))
	}

	// The selective-backfill half (A-3). Uncorrelated on the analyzer, keyed
	// on the digest the report already stores, and `< $version` so a row
	// already at the current version is never reselected.
	//
	// EXISTS rather than a join: a coordinate can hold several analyzer
	// generations for the same digest, and a join would return the coordinate
	// once per superseded row — inflating both the backlog gauge and the
	// sweep's budget consumption with duplicates of the same work.
	if sc.StaleAnalyzer != "" && sc.StaleAnalyzerVersion > AnalyzerNotCacheable {
		args = append(args, sc.StaleAnalyzer, sc.StaleAnalyzerVersion)
		halves = append(halves, fmt.Sprintf(`(%s IS NOT NULL AND EXISTS (
		SELECT 1 FROM artifact_analyses a
		 WHERE a.artifact_sha256  = %s
		   AND a.analyzer         = $%d
		   AND a.analyzer_version < $%d))`,
			reportArtifactSHAExpr, reportArtifactSHAExpr, len(args)-1, len(args)))
	}

	pred := halves[0]
	if len(halves) > 1 {
		pred = "(" + strings.Join(halves, " OR ") + ")"
	}
	return pred + " AND " + declaredCoordinateAntiJoin, args
}

// CountStaleReports sizes the backlog. Producer for the
// chainsaw_intel_stale_report_backlog gauge.
func (s *Store) CountStaleReports(ctx context.Context, scope StaleReportScope) (int, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return 0, nil
	}
	var n int
	pred, args := scope.where()
	if err := s.sql.DB().QueryRowContext(ctx, `SELECT COUNT(*) FROM intelligence_reports WHERE `+pred, args...).Scan(&n); err != nil {
		return 0, fmt.Errorf("intelligence: count stale reports: %w", err)
	}
	return n, nil
}

// IterateStaleReports pages the backlog OLDEST FIRST.
//
// Oldest-first, not newest: the sweep runs on a per-tick budget, so the order
// decides which coordinates get refreshed when the backlog exceeds it. The
// oldest row is the one whose stored verdict has had the longest time to stop
// being true, which is the whole reason this sweep exists.
func (s *Store) IterateStaleReports(ctx context.Context, scope StaleReportScope, after StaleReportCursor, limit int) ([]StaleReportRow, StaleReportCursor, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return nil, StaleReportCursor{}, nil
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}

	pred, args := scope.where()
	keyset := ""
	if !after.IsZero() {
		n := len(args)
		keyset = fmt.Sprintf(" AND (collected_at, ecosystem, package_name, version) > ($%d, $%d, $%d, $%d)", n+1, n+2, n+3, n+4)
		args = append(args, after.CollectedAt, after.Ecosystem, after.Package, after.Version)
	}
	args = append(args, limit)

	query := fmt.Sprintf(`
		SELECT ecosystem, package_name, version, collected_at
		FROM intelligence_reports
		WHERE %s%s
		ORDER BY collected_at ASC, ecosystem ASC, package_name ASC, version ASC
		LIMIT $%d
	`, pred, keyset, len(args))

	rows, err := s.sql.DB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, StaleReportCursor{}, fmt.Errorf("intelligence: iterate stale reports: %w", err)
	}
	defer rows.Close()

	out := make([]StaleReportRow, 0, limit)
	for rows.Next() {
		var r StaleReportRow
		if err := rows.Scan(&r.Ecosystem, &r.Package, &r.Version, &r.CollectedAt); err != nil {
			return nil, StaleReportCursor{}, fmt.Errorf("intelligence: scan stale report row: %w", err)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, StaleReportCursor{}, fmt.Errorf("intelligence: iterate stale report rows: %w", err)
	}

	// A short page ends the walk, same convention as the sibling sweeps: a
	// non-zero cursor would cost an extra empty round-trip and make "did we
	// finish" ambiguous for the caller's budget accounting.
	if len(out) < limit {
		return out, StaleReportCursor{}, nil
	}
	last := out[len(out)-1]
	return out, StaleReportCursor{
		CollectedAt: last.CollectedAt,
		Ecosystem:   last.Ecosystem,
		Package:     last.Package,
		Version:     last.Version,
	}, nil
}
