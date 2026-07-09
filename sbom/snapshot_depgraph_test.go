package sbom

// snapshot_depgraph_test.go exercises the ADR-012 Item 4 dep_graph_doc
// column end-to-end against an in-memory SQLite DB: InsertSnapshot ->
// GetSnapshot preserves the persisted graph bytes, and a row written
// WITHOUT a graph (the legacy-NULL case) reads back with an empty
// DepGraphDoc rather than erroring.

import (
	"context"
	"database/sql"
	"testing"

	_ "modernc.org/sqlite" // pure-Go driver; no CGO.
)

// newSnapshotDB opens an in-memory SQLite DB with a sbom_snapshots table
// shaped to match the production schema's read/write surface. We use
// SQLite types (INTEGER PRIMARY KEY AUTOINCREMENT, TEXT) rather than the
// Postgres BIGSERIAL/TIMESTAMPTZ the migration emits — the store's SQL is
// dialect-portable (`?` placeholders, RETURNING) and only the column
// NAMES/nullability matter for this round-trip.
func newSnapshotDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:depgraph_snap_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	_, err = db.Exec(`CREATE TABLE sbom_snapshots (
		snapshot_id INTEGER PRIMARY KEY AUTOINCREMENT,
		org_id TEXT NOT NULL,
		client_id TEXT,
		repo TEXT,
		taken_at TIMESTAMP NOT NULL,
		trigger TEXT NOT NULL,
		components_count INTEGER NOT NULL DEFAULT 0,
		sbom_doc TEXT NOT NULL DEFAULT '{}',
		dep_graph_doc TEXT NULL
	)`)
	if err != nil {
		t.Fatalf("create table: %v", err)
	}
	return db
}

func TestInsertGetSnapshot_PreservesDepGraph(t *testing.T) {
	db := newSnapshotDB(t)
	ctx := context.Background()

	graphDoc := []byte(`{"nodes":[{"eco":"npm","name":"a","version":"1","direct":true,"prod":true}],"edges":[],"roots":[0],"fired_signals":{"0":["sig-1"]}}`)
	id, err := InsertSnapshot(ctx, db, Snapshot{
		OrgID:           "org-1",
		Trigger:         TriggerScheduled,
		ComponentsCount: 1,
		SBOMDoc:         []byte(`{"bomFormat":"CycloneDX"}`),
		DepGraphDoc:     graphDoc,
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	got, err := GetSnapshot(ctx, db, "org-1", id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if string(got.DepGraphDoc) != string(graphDoc) {
		t.Fatalf("dep_graph_doc not preserved:\n got=%s\nwant=%s", got.DepGraphDoc, graphDoc)
	}
	// The byte-identical sbom_doc download path must remain untouched.
	if string(got.SBOMDoc) != `{"bomFormat":"CycloneDX"}` {
		t.Fatalf("sbom_doc altered: %s", got.SBOMDoc)
	}
}

func TestInsertGetSnapshot_LegacyNullReadsAsEmpty(t *testing.T) {
	db := newSnapshotDB(t)
	ctx := context.Background()

	// No DepGraphDoc supplied — store must write NULL, not a placeholder.
	id, err := InsertSnapshot(ctx, db, Snapshot{
		OrgID:   "org-1",
		Trigger: TriggerManual,
		SBOMDoc: []byte(`{}`),
	})
	if err != nil {
		t.Fatalf("insert: %v", err)
	}

	// Confirm the column is actually NULL at the row level (the legacy
	// shape an old install would have).
	var raw sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT dep_graph_doc FROM sbom_snapshots WHERE snapshot_id = ?`, id).
		Scan(&raw); err != nil {
		t.Fatalf("raw select: %v", err)
	}
	if raw.Valid {
		t.Fatalf("dep_graph_doc should be NULL, got %q", raw.String)
	}

	got, err := GetSnapshot(ctx, db, "org-1", id)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(got.DepGraphDoc) != 0 {
		t.Fatalf("legacy NULL row should read empty DepGraphDoc, got %q", got.DepGraphDoc)
	}
}
