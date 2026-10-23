package pgstore

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Structural guards — no database. The DB test below skips without
// CHAINSAW_DATABASE_URL, and a backfill whose only coverage skips silently
// has no coverage.
// ---------------------------------------------------------------------------

// TestStampLapsingLegacyExceptionsIsWiredIntoBoot: the backfill only helps if
// it runs in the same boot that first serves the fixed settingsForOrg. A
// stamp function nobody calls looks green forever while every legacy
// exception lapses at deploy.
func TestStampLapsingLegacyExceptionsIsWiredIntoBoot(t *testing.T) {
	b, err := os.ReadFile("migrate_columns.go")
	if err != nil {
		t.Fatalf("read migrate_columns.go: %v", err)
	}
	src := string(b)
	callIdx := strings.Index(src, "s.stampLapsingLegacyExceptions()")
	if callIdx < 0 {
		t.Fatal("ensureEnhancedColumns no longer calls stampLapsingLegacyExceptions; legacy " +
			"exceptions in non-default orgs would lapse at deploy with no grace window")
	}
	colsIdx := strings.Index(src, "s.ensurePolicyColumns()")
	if colsIdx < 0 {
		t.Fatal("ensurePolicyColumns call not found in migrate_columns.go")
	}
	if callIdx < colsIdx {
		t.Error("stampLapsingLegacyExceptions runs before ensurePolicyColumns; policies.kind and " +
			"policies.expires_at may not exist yet on an old database")
	}
}

// TestStampLapsingLegacyExceptionsIsOneShot pins the property that keeps the
// backfill from becoming a permanent renewal: the marker insert and the
// UPDATE are one statement, and the UPDATE is gated on the insert winning.
func TestStampLapsingLegacyExceptionsIsOneShot(t *testing.T) {
	b, err := os.ReadFile("migrate_exception_expiry.go")
	if err != nil {
		t.Fatalf("read migrate_exception_expiry.go: %v", err)
	}
	src := string(b)
	for _, want := range []string{
		"ON CONFLICT (name) DO NOTHING",
		"RETURNING 1",
		"WHERE EXISTS (SELECT 1 FROM marker)",
	} {
		if !strings.Contains(src, want) {
			t.Errorf("stamp no longer contains %q; without the marker gate every boot re-stamps "+
				"exceptions that reached 30 days, so nothing in a non-default org ever expires", want)
		}
	}
	// The discriminator must be IsExpiredException's: expires_at is honoured
	// on ANY allow row, so a predicate without it stamps plain allow rules.
	if !strings.Contains(exceptionExpiryBackfillPredicate, "p.kind = 'exception'") ||
		!strings.Contains(exceptionExpiryBackfillPredicate, `"isvulnerable":true`) {
		t.Error("predicate lost the exception discriminator; it would put an expiry on plain allow rules")
	}
}

// TestStampPredicateNoCliffNoPending pins the two predicate decisions the
// pre-merge review made blocking, DB-free:
//   - no created_at bound: a bound leaves young NULL-expiry exceptions to
//     lapse days after deploy, though they read "no expiry" until then;
//   - enabled rows only: both approve paths refuse a NULL-expiry row, so
//     stamping a pending one makes it approvable with an unchosen expiry.
func TestStampPredicateNoCliffNoPending(t *testing.T) {
	pred := exceptionExpiryBackfillPredicate
	if strings.Contains(pred, "created_at") {
		t.Error("predicate bounds created_at; young exceptions would lapse shortly after deploy")
	}
	if strings.Contains(pred, "pending_approval") || !strings.Contains(pred, "p.status = 'enabled'") {
		t.Error("predicate must stamp status = 'enabled' rows only, never pending_approval")
	}
}

// ---------------------------------------------------------------------------
// Database integration.
// ---------------------------------------------------------------------------

func TestStampLapsingLegacyExceptions(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CHAINSAW_DATABASE_URL"))
	if dsn == "" {
		if os.Getenv("CHAINSAW_TEST_REQUIRE_DB") != "" {
			t.Fatal("CHAINSAW_TEST_REQUIRE_DB is set but CHAINSAW_DATABASE_URL is empty")
		}
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping integration test")
	}
	store, err := Open(dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	db := store.DB()

	nonce := fmt.Sprintf("%d", time.Now().UnixNano())
	org := "excexp_org_" + nonce
	agedOrg := "excexp_aged_" + nonce
	// Own marker and own orgs: the stamp is global in production, and on
	// a shared test DB a global run would stamp other tests' rows and
	// consume the real marker.
	marker := "test_" + exceptionExpiryBackfillName + "_" + nonce
	scope := `AND p.org_id IN ($2, $3)`
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM data_backfills WHERE name = $1`, marker)
		for _, o := range []string{org, agedOrg} {
			_, _ = db.Exec(`DELETE FROM policies WHERE org_id = $1`, o)
			_, _ = db.Exec(`DELETE FROM settings WHERE org_id = $1`, o)
			_, _ = db.Exec(`DELETE FROM orgs WHERE id = $1`, o)
		}
	})
	for _, o := range []string{org, agedOrg} {
		if _, err := db.Exec(`INSERT INTO orgs (id, name, slug) VALUES ($1, $1, $1)`, o); err != nil {
			t.Fatalf("insert org %s: %v", o, err)
		}
	}
	if _, err := db.Exec(`INSERT INTO settings (org_id, key, value) VALUES ($1, 'exception.age', '45')`, agedOrg); err != nil {
		t.Fatalf("insert exception.age: %v", err)
	}

	now := time.Now().UTC()
	old := now.Add(-40 * 24 * time.Hour)
	// precedence is unique per org (idx_policies_org_precedence_unique).
	precedence := 0
	insert := func(orgID, id, kind, status, conditions string, created time.Time, expires any) {
		t.Helper()
		precedence++
		_, err := db.Exec(`
			INSERT INTO policies (id, org_id, name, precedence, mode, status, kind, conditions,
			                      parameter_hash, created_at, updated_at, expires_at)
			VALUES ($1, $2, $1, $8, 'allow', $3, $4, $5, $1, $6, $6, $7)`,
			id, orgID, status, kind, conditions, created, expires, precedence)
		if err != nil {
			t.Fatalf("insert %s: %v", id, err)
		}
	}
	p := func(s string) string { return s + "_" + nonce }
	insert(org, p("lapsing"), "exception", "enabled", `{}`, old, nil)
	insert(org, p("legacyvuln"), "", "enabled", `{"isVulnerable":true}`, old, nil)
	insert(org, p("pending"), "exception", "pending_approval", `{}`, old, nil)
	insert(org, p("plainallow"), "", "enabled", `{}`, old, nil)
	insert(org, p("young"), "exception", "enabled", `{}`, now.Add(-10*24*time.Hour), nil)
	insert(org, p("dated"), "exception", "enabled", `{}`, old, now.Add(5*24*time.Hour))
	insert(org, p("disabled"), "exception", "disabled", `{}`, old, nil)
	insert(agedOrg, p("agedorg"), "exception", "enabled", `{}`, old, nil)

	expiresOf := func(id string) *time.Time {
		t.Helper()
		var e *time.Time
		if err := db.QueryRow(`SELECT expires_at FROM policies WHERE id = $1`, id).Scan(&e); err != nil {
			t.Fatalf("read %s: %v", id, err)
		}
		return e
	}
	scoped := func() int64 {
		t.Helper()
		var n int64
		if err := db.QueryRow(`SELECT count(*) FROM policies p WHERE p.org_id IN ($1, $2) AND `+
			exceptionExpiryBackfillPredicate, org, agedOrg).Scan(&n); err != nil {
			t.Fatalf("scoped census: %v", err)
		}
		return n
	}
	if got := scoped(); got != 3 {
		t.Fatalf("census counted %d of this test's rows, want 3 (lapsing, legacyvuln, young)", got)
	}

	n, err := store.stampLapsingLegacyExceptionsScoped(marker, scope, org, agedOrg)
	if err != nil {
		t.Fatalf("stamp: %v", err)
	}
	if n != 3 {
		t.Errorf("stamped %d rows, want 3", n)
	}

	// young: created 10 days ago. Without the stamp it would lapse 20
	// days after deploy despite having read "no expiry" until then.
	for _, id := range []string{p("lapsing"), p("legacyvuln"), p("young")} {
		e := expiresOf(id)
		if e == nil {
			t.Errorf("%s: not stamped", id)
			continue
		}
		if d := e.Sub(now); d < 29*24*time.Hour || d > 31*24*time.Hour {
			t.Errorf("%s: expires_at %s is not ~30 days out", id, e)
		}
	}
	// pending: both approve paths refuse a NULL-expiry row, so a stamp
	// would make it approvable with an expiry no reviewer chose.
	for _, id := range []string{p("plainallow"), p("pending"), p("disabled"), p("agedorg")} {
		if e := expiresOf(id); e != nil {
			t.Errorf("%s: stamped expires_at=%s, want NULL", id, e)
		}
	}
	if e := expiresOf(p("dated")); e == nil || e.Sub(now) > 6*24*time.Hour {
		t.Errorf("dated: explicit expiry was overwritten: %v", e)
	}

	// One-shot: a qualifying row that appears later (an exception created
	// after deploy that reached 30 days) must NOT be stamped by a reboot.
	insert(org, p("later"), "exception", "enabled", `{}`, old, nil)
	n, err = store.stampLapsingLegacyExceptionsScoped(marker, scope, org, agedOrg)
	if err != nil {
		t.Fatalf("second stamp: %v", err)
	}
	if n != 0 || expiresOf(p("later")) != nil {
		t.Errorf("second run stamped %d rows (later=%v); the backfill is renewing exceptions on every boot",
			n, expiresOf(p("later")))
	}
}
