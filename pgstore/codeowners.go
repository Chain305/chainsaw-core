package pgstore

import (
	"context"
	"database/sql"
	"fmt"
)

// Mapping mirrors codeowners.Mapping. We redeclare it here rather than
// importing internal/codeowners to keep pgstore at the bottom of the
// dependency graph (codeowners imports pgstore via its Store interface,
// but pgstore must not import codeowners).
type Mapping struct {
	Pattern string
	Owners  []string
	LineNo  int
}

// UpsertCodeowners replaces the persisted CODEOWNERS mapping for
// repoID with the supplied set. The whole set is rewritten in a single
// transaction so partial sync failures cannot leave a half-updated
// view to ownership queries. ordinal is the row's position in the
// supplied slice — it determines the "last match wins" tie-break on
// reads.
func (s *Store) UpsertCodeowners(ctx context.Context, repoID string, mappings []Mapping) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("pgstore: store not initialized")
	}
	if repoID == "" {
		return fmt.Errorf("pgstore: empty repo_id")
	}
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM codeowners_mappings WHERE repo_id=?`, repoID); err != nil {
			return fmt.Errorf("delete prior codeowners for %s: %w", repoID, err)
		}
		for i, m := range mappings {
			owners := m.Owners
			if owners == nil {
				owners = []string{}
			}
			if _, err := tx.ExecContext(ctx,
				`INSERT INTO codeowners_mappings (repo_id, ordinal, pattern, owners, updated_at)
				 VALUES (?, ?, ?, ?, NOW())`,
				repoID, i, m.Pattern, owners,
			); err != nil {
				return fmt.Errorf("insert codeowners row %d: %w", i, err)
			}
		}
		return nil
	})
}

// GetCodeowners returns the persisted CODEOWNERS mapping for repoID,
// ordered by ordinal so "last match wins" works in callers that walk
// from the end. An unsynced repo returns (nil, nil).
func (s *Store) GetCodeowners(ctx context.Context, repoID string) ([]Mapping, error) {
	if s == nil || s.db == nil {
		return nil, fmt.Errorf("pgstore: store not initialized")
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT pattern, owners, ordinal
		 FROM codeowners_mappings
		 WHERE repo_id=?
		 ORDER BY ordinal ASC`,
		repoID,
	)
	if err != nil {
		return nil, fmt.Errorf("query codeowners: %w", err)
	}
	defer rows.Close()

	var out []Mapping
	for rows.Next() {
		var m Mapping
		// Same Postgres-text-array gotcha as internal/finding/pg_store.go:
		// pgx-stdlib supports []string as an INSERT param but does not
		// auto-decode text[] back into *[]string on Scan. Without the
		// PgTextArray wrapper this returned:
		//   sql: Scan error on column index 1, name "owners":
		//     unsupported Scan, storing driver.Value type string into type *[]string
		var owners PgTextArray
		if err := rows.Scan(&m.Pattern, &owners, &m.LineNo); err != nil {
			return nil, fmt.Errorf("scan codeowners row: %w", err)
		}
		m.Owners = []string(owners)
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate codeowners rows: %w", err)
	}
	return out, nil
}
