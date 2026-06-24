package sbom

// snapshot_store_test.go — unit tests for the validation helpers in
// snapshot_store.go. The DB-touching paths (Insert / List / Get) are
// covered by the integration suite when CHAINSAW_DATABASE_URL is set;
// these tests exercise the pure-function checks that fail before any
// SQL runs (org-scope, trigger validation, JSON shape).

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

// fakeDB returns a non-nil *sql.DB with a driver that's never used. We
// only need a non-nil pointer so the validation guards run; the SQL
// path is short-circuited by the validation rejections we're asserting.
func fakeDB(t *testing.T) *sql.DB {
	t.Helper()
	// Use the always-available pgx stdlib registration with a deliberately
	// unparseable DSN — Open is lazy, it doesn't dial until we run a
	// query, so this works for pure-validation tests.
	db, err := sql.Open("pgx", "postgres://localhost:1/__test_unused__")
	if err != nil {
		t.Fatalf("open fake db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestValidTrigger(t *testing.T) {
	cases := map[string]bool{
		TriggerScheduled:        true,
		TriggerManual:           true,
		TriggerPolicyViolation:  true,
		TriggerIncidentResponse: true,
		"":                      false,
		"unknown":               false,
		"SCHEDULED":             false, // case-sensitive on purpose
	}
	for in, want := range cases {
		if got := validTrigger(in); got != want {
			t.Errorf("validTrigger(%q)=%v want %v", in, got, want)
		}
	}
}

func TestInsertSnapshot_RejectsBadInputs(t *testing.T) {
	// nil DB
	if _, err := InsertSnapshot(context.Background(), nil, Snapshot{}); err == nil {
		t.Fatal("expected error for nil db")
	}

	db := fakeDB(t)

	// empty org_id is a tenant-isolation violation; must fail loud.
	if _, err := InsertSnapshot(context.Background(), db, Snapshot{
		Trigger: TriggerManual,
	}); err == nil || !strings.Contains(err.Error(), "org_id required") {
		t.Fatalf("expected org_id error, got %v", err)
	}

	// invalid trigger: must reject before the DB CHECK
	if _, err := InsertSnapshot(context.Background(), db, Snapshot{
		OrgID:   "org-1",
		Trigger: "garbage",
	}); err == nil || !strings.Contains(err.Error(), "invalid trigger") {
		t.Fatalf("expected trigger error, got %v", err)
	}

	// invalid JSON body must reject — we don't want to write malformed
	// docs that the dashboard then can't parse.
	if _, err := InsertSnapshot(context.Background(), db, Snapshot{
		OrgID:   "org-1",
		Trigger: TriggerManual,
		SBOMDoc: []byte("{not json"),
	}); err == nil || !strings.Contains(err.Error(), "valid JSON") {
		t.Fatalf("expected JSON error, got %v", err)
	}
}

func TestListSnapshots_RejectsEmptyOrg(t *testing.T) {
	if _, err := ListSnapshots(context.Background(), nil, "", SnapshotFilters{}); err == nil {
		t.Fatal("expected error for nil db")
	}
	db := fakeDB(t)
	if _, err := ListSnapshots(context.Background(), db, "", SnapshotFilters{}); err == nil {
		t.Fatal("expected error for empty org_id")
	}
}

func TestListSnapshots_RejectsBadTrigger(t *testing.T) {
	_, err := ListSnapshots(context.Background(), fakeDB(t), "org-1", SnapshotFilters{Trigger: "nope"})
	if err == nil || !strings.Contains(err.Error(), "invalid trigger filter") {
		t.Fatalf("expected trigger filter error, got %v", err)
	}
}

func TestGetSnapshot_NotFoundOnZeroID(t *testing.T) {
	db := fakeDB(t)
	_, err := GetSnapshot(context.Background(), db, "org-1", 0)
	if err != ErrSnapshotNotFound {
		t.Fatalf("expected ErrSnapshotNotFound, got %v", err)
	}
	_, err = GetSnapshot(context.Background(), db, "org-1", -1)
	if err != ErrSnapshotNotFound {
		t.Fatalf("expected ErrSnapshotNotFound, got %v", err)
	}
}

func TestNullIfEmpty(t *testing.T) {
	if v := nullIfEmpty(""); v != nil {
		t.Errorf("expected nil for empty, got %v", v)
	}
	if v := nullIfEmpty("   "); v != nil {
		t.Errorf("expected nil for whitespace, got %v", v)
	}
	if v := nullIfEmpty("client-1"); v != "client-1" {
		t.Errorf("expected pass-through, got %v", v)
	}
}
