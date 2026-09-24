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
// costs one extra refresh per cool-down, not one per tick.
//
// "Never scanned" reads the merged report JSON — what the report itself says —
// rather than the has_artifact_scan projection. The upsert ORs that column with
// its stored value, so it cannot go false after a bytes-less rewrite; measured
// 2026-09-24, zero rows had the column false with the JSON true.
type StaleReportScope struct {
	OlderThan          time.Time
	ArtifactEcosystems []string
	ArtifactOlderThan  time.Time
}

// where renders the scope as a WHERE predicate whose placeholders start at $1,
// and returns its arguments.
func (sc StaleReportScope) where() (string, []any) {
	args := []any{sc.OlderThan}
	if len(sc.ArtifactEcosystems) == 0 {
		return "collected_at < $1", args
	}
	args = append(args, sc.ArtifactOlderThan)
	in := make([]string, len(sc.ArtifactEcosystems))
	for i, eco := range sc.ArtifactEcosystems {
		args = append(args, eco)
		in[i] = fmt.Sprintf("$%d", len(args))
	}
	return fmt.Sprintf(`(collected_at < $1 OR (collected_at < $2
		AND NOT COALESCE((report->'artifactScan'->>'performed')::boolean, false)
		AND ecosystem IN (%s)))`, strings.Join(in, ", ")), args
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
