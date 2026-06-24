package pgstore

// Schema-version tracking for the `chainsaw doctor --upgrade-check`
// flow.
//
// The rest of pgstore is managed via idempotent `CREATE TABLE IF NOT
// EXISTS` statements (see store.go's migrate()). That model is great
// for fresh installs and forward-only adds, but gives operators no way
// to ask "is the DB in the shape this binary expects?" before cutting
// over to a new release. Doctor needs a single scalar it can compare
// against the binary's baked-in version.
//
// Design choice (Option A from the audit task): add a tiny single-row
// `schema_version` table that holds the current schema's semantic
// version string. On every `pgstore.Open` call migrate() upserts the
// binary's `CurrentSchemaVersion` into the row. Doctor then SELECTs
// the row without needing the full migration pipeline and compares
// against the same constant.
//
// Why not a numbered migration system (Option B)? The rest of the
// codebase has zero numbered .sql files, no goose, no
// golang-migrate. Adding one just for the doctor hook would introduce
// a second source of truth for schema changes, which is worse than
// the current "CREATE TABLE IF NOT EXISTS + doc in MIGRATIONS.md"
// convention we already ship. When the migration style eventually
// changes, this table will still be a useful scalar version marker.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
)

// CurrentSchemaVersion is the schema revision this binary expects.
// Bump this whenever a non-idempotent schema change lands (something
// that could leave an older DB unable to satisfy a query the new
// binary issues). For idempotent-only adds (new table, nullable
// column) bumping is optional but encouraged — it makes the doctor
// output crisp after an upgrade.
//
// Kept in sync with the repo root `VERSION` file. When in doubt,
// match the release tag for the first version that ships this
// schema shape.
//
// 0.17.0 — Billy safety hardening adds billy_call_logs and
// billy_safety_events tables plus an attempt_count column on the
// former. All forward-only idempotent additions; existing deployments
// upgrade cleanly via CREATE/ALTER ... IF NOT EXISTS.
const CurrentSchemaVersion = "0.17.0"

// ErrNoSchemaVersion is returned by Store.SchemaVersion when the
// schema_version table is missing or empty. For a freshly-provisioned
// DB this is the expected path: Store.migrate() will then INSERT
// `CurrentSchemaVersion`. Doctor distinguishes this case from a real
// query failure.
var ErrNoSchemaVersion = errors.New("schema_version row not present")

// ensureSchemaVersion creates the schema_version table (if needed)
// and reconciles the stored value with CurrentSchemaVersion. The
// table is a single-row, single-column marker — no primary key is
// required because we only ever insert one row, but we include a
// CHECK (id = 1) guard so accidental extra rows surface immediately.
//
// Semantics:
//   - absent row  → INSERT CurrentSchemaVersion (fresh DB)
//   - match       → no-op
//   - older stored → UPDATE to CurrentSchemaVersion, log at Info
//   - newer stored → leave row untouched, log at Warn. This is the
//     downgrade-binary-against-newer-DB scenario; we
//     don't fail because some forward-compat
//     deployments intentionally run N-1 binaries
//     against N schemas during rollbacks.
func (s *Store) ensureSchemaVersion() error {
	if s == nil || s.db == nil {
		return nil
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_version (
		id INTEGER NOT NULL PRIMARY KEY DEFAULT 1,
		version TEXT NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
		CHECK (id = 1)
	)`); err != nil {
		return fmt.Errorf("create schema_version table: %w", err)
	}

	stored, err := s.schemaVersionOrEmpty()
	if err != nil {
		return fmt.Errorf("read schema_version: %w", err)
	}
	switch {
	case stored == "":
		if _, err := s.db.Exec(
			`INSERT INTO schema_version(id, version, updated_at) VALUES(1, ?, CURRENT_TIMESTAMP)
			 ON CONFLICT (id) DO NOTHING`,
			CurrentSchemaVersion,
		); err != nil {
			return fmt.Errorf("insert schema_version: %w", err)
		}
	case stored == CurrentSchemaVersion:
		// no-op
	case schemaVersionLess(stored, CurrentSchemaVersion):
		slog.Info("pgstore: schema upgrade applied",
			"previous", stored,
			"current", CurrentSchemaVersion)
		if _, err := s.db.Exec(
			`UPDATE schema_version SET version = ?, updated_at = CURRENT_TIMESTAMP WHERE id = 1`,
			CurrentSchemaVersion,
		); err != nil {
			return fmt.Errorf("update schema_version: %w", err)
		}
	default:
		// Stored is newer than the binary. Tolerate but warn so
		// operators running a downgrade see the signal.
		slog.Warn("pgstore: database schema is newer than binary",
			"binary", CurrentSchemaVersion,
			"database", stored,
			"hint", "see MIGRATIONS.md for downgrade guidance")
	}
	return nil
}

// SchemaVersion returns the currently-stored schema version string, or
// ErrNoSchemaVersion if the marker row is missing. Intended for the
// doctor probe — read-only, cheap, no side effects.
func (s *Store) SchemaVersion(ctx context.Context) (string, error) {
	if s == nil || s.db == nil {
		return "", fmt.Errorf("store not initialized")
	}
	v, err := s.schemaVersionWithCtx(ctx)
	if err != nil {
		return "", err
	}
	if v == "" {
		return "", ErrNoSchemaVersion
	}
	return v, nil
}

func (s *Store) schemaVersionOrEmpty() (string, error) {
	var v string
	err := s.db.QueryRow(`SELECT version FROM schema_version WHERE id = 1`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

func (s *Store) schemaVersionWithCtx(ctx context.Context) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT version FROM schema_version WHERE id = 1`).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

// schemaVersionLess compares two version strings lexicographically
// segment-by-segment with numeric-aware fallbacks. We deliberately
// avoid pulling in semver/v3 for what is effectively a 3-token
// compare; doctor's "older vs newer vs equal" decision does not need
// pre-release or build-metadata awareness.
//
// Returns true iff a < b.
func schemaVersionLess(a, b string) bool {
	if a == b {
		return false
	}
	as := splitSemverLike(a)
	bs := splitSemverLike(b)
	n := len(as)
	if len(bs) < n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		if as[i] == bs[i] {
			continue
		}
		// Numeric compare when both segments are integers; else
		// string compare so unusual suffixes still yield a decision.
		ai, aok := toInt(as[i])
		bi, bok := toInt(bs[i])
		if aok && bok {
			return ai < bi
		}
		return as[i] < bs[i]
	}
	// All shared segments equal → shorter version is older.
	return len(as) < len(bs)
}

func splitSemverLike(v string) []string {
	var out []string
	start := 0
	for i := 0; i < len(v); i++ {
		if v[i] == '.' {
			out = append(out, v[start:i])
			start = i + 1
		}
	}
	if start <= len(v) {
		out = append(out, v[start:])
	}
	return out
}

func toInt(s string) (int, bool) {
	n := 0
	if s == "" {
		return 0, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
