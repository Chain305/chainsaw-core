package intelligence

// The read half of the stale-report refresh sweep. See
// refresher_stale_reports.go for why the sweep exists.

import (
	"context"
	"fmt"
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

// CountStaleReports sizes the backlog. Producer for the
// chainsaw_intel_stale_report_backlog gauge.
func (s *Store) CountStaleReports(ctx context.Context, olderThan time.Time) (int, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return 0, nil
	}
	var n int
	const q = `SELECT COUNT(*) FROM intelligence_reports WHERE collected_at < $1`
	if err := s.sql.DB().QueryRowContext(ctx, q, olderThan).Scan(&n); err != nil {
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
func (s *Store) IterateStaleReports(ctx context.Context, olderThan time.Time, after StaleReportCursor, limit int) ([]StaleReportRow, StaleReportCursor, error) {
	if s == nil || s.sql == nil || s.sql.DB() == nil {
		return nil, StaleReportCursor{}, nil
	}
	if limit <= 0 {
		limit = 200
	}
	if limit > 1000 {
		limit = 1000
	}

	args := []any{olderThan}
	keyset := ""
	if !after.IsZero() {
		keyset = " AND (collected_at, ecosystem, package_name, version) > ($2, $3, $4, $5)"
		args = append(args, after.CollectedAt, after.Ecosystem, after.Package, after.Version)
	}
	args = append(args, limit)

	query := fmt.Sprintf(`
		SELECT ecosystem, package_name, version, collected_at
		FROM intelligence_reports
		WHERE collected_at < $1%s
		ORDER BY collected_at ASC, ecosystem ASC, package_name ASC, version ASC
		LIMIT $%d
	`, keyset, len(args))

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
