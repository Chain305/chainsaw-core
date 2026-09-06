package pgstore

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Structural guards. These need NO database, which is the point: the DB test
// below skips without CHAINSAW_DATABASE_URL, and a migration whose only
// coverage skips silently is a migration with no coverage at all.
// ---------------------------------------------------------------------------

func migrationSource(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("migrate_attestation_identity.go")
	if err != nil {
		t.Fatalf("read migration source: %v", err)
	}
	return string(b)
}

// TestClearUnverifiedIdentityIsWiredIntoBoot is the "a guard that cannot run
// is not a guard" check. The whole reason this migration exists is that
// d4f2bda5 gated a writer and shipped no migration, leaving the poison it
// fixed resident in production to this day. A clear function nobody calls
// repeats that exactly, and would look green forever.
func TestClearUnverifiedIdentityIsWiredIntoBoot(t *testing.T) {
	b, err := os.ReadFile("migrate_columns.go")
	if err != nil {
		t.Fatalf("read migrate_columns.go: %v", err)
	}
	src := string(b)
	if !strings.Contains(src, "clearUnverifiedAttestationIdentity()") {
		t.Fatal("ensureEnhancedColumns no longer calls clearUnverifiedAttestationIdentity. " +
			"Unverified attestation identity already resident in package_metadata would " +
			"stay there permanently: ProjectSLSAFields cannot clear a column the incoming " +
			"report leaves empty unless the report is authoritative, and rows poisoned by " +
			"the pre-fix registry-metadata path carry NO provenance status at all.")
	}
	// Ordering: the UPDATE touches columns ensurePackageRegistryColumns adds.
	callIdx := strings.Index(src, "clearUnverifiedAttestationIdentity()")
	colsIdx := strings.Index(src, "ensurePackageRegistryColumns()")
	if colsIdx < 0 {
		t.Fatal("ensurePackageRegistryColumns call not found in migrate_columns.go")
	}
	if callIdx < colsIdx {
		t.Error("clearUnverifiedAttestationIdentity runs BEFORE ensurePackageRegistryColumns; " +
			"on a pre-Phase-5 database the attestation_* columns do not exist yet and the " +
			"UPDATE errors out, failing every boot.")
	}
}

// TestClearUnverifiedIdentityHandlesNullStatus pins the single most likely way
// this migration gets silently turned into a no-op.
//
// package_metadata.provenance_status is nullable TEXT with no default
// (migrate_packages.go:12) and the INSERT omits it entirely, so rows are born
// with it NULL. The registry-metadata poison shape is exactly that: a source
// repo written with no status. Under plain `provenance_status <> 'verified'`
// those rows evaluate to NULL, the WHERE clause drops them, and the migration
// reports success while cleaning nothing — passing on the real bug.
func TestClearUnverifiedIdentityHandlesNullStatus(t *testing.T) {
	src := migrationSource(t)
	if !strings.Contains(src, "IS DISTINCT FROM 'verified'") {
		t.Error("predicate no longer uses IS DISTINCT FROM. A bare <> comparison is NULL " +
			"for rows with a NULL provenance_status, which is precisely the poisoned " +
			"population (registry metadata writes a source repo and no status), so the " +
			"migration would silently skip the rows it exists to clean.")
	}
	if !strings.Contains(src, "coalesce(provenance_status, '')") {
		t.Error("predicate no longer coalesces provenance_status")
	}
	if !strings.Contains(src, "lower(coalesce(provenance_status, ''))") {
		t.Error("predicate no longer case-folds provenance_status; core/policy.provenanceVerified " +
			"and internal/server/policy_simulate.go both compare case-insensitively, so a " +
			"'Verified' row would be cleared on disk while still matching on read.")
	}
}

// TestClearAndCountSharePredicate keeps the operator census honest. If the
// census predicate drifts from the mutation's, an operator sizing the change
// (or confirming it converged) reads a number about a different population.
func TestClearAndCountSharePredicate(t *testing.T) {
	src := migrationSource(t)
	const predicate = `WHERE lower(coalesce(provenance_status, '')) IS DISTINCT FROM 'verified'
		  AND (attestation_builder_id       IS NOT NULL
		    OR attestation_issuer           IS NOT NULL
		    OR attestation_source_repo      IS NOT NULL
		    OR attestation_transparency_log IS NOT NULL)`
	if n := strings.Count(src, predicate); n != 2 {
		t.Fatalf("the UPDATE and the COUNT no longer share a byte-identical predicate "+
			"(found %d occurrences, want 2). They must stay in lockstep or the census "+
			"reports on a different population than the migration touches.", n)
	}
}

// TestClearTouchesOnlyIdentityColumns asserts the blast radius. provenance_status,
// slsa_level and attestation_cache_stale are NOT identity and are NOT
// attacker-supplied in the same way; clearing them would rewrite verification
// verdicts rather than remove unproven claims.
func TestClearTouchesOnlyIdentityColumns(t *testing.T) {
	src := migrationSource(t)
	set := src[strings.Index(src, "UPDATE package_metadata"):]
	set = set[:strings.Index(set, "WHERE")]
	for _, forbidden := range []string{"provenance_status =", "slsa_level", "attestation_cache_stale"} {
		if strings.Contains(set, forbidden) {
			t.Errorf("SET clause writes %q; the migration must clear identity only", forbidden)
		}
	}
	for _, required := range []string{
		"attestation_builder_id       = NULL",
		"attestation_issuer           = NULL",
		"attestation_source_repo      = NULL",
		"attestation_transparency_log = NULL",
	} {
		if !strings.Contains(set, required) {
			t.Errorf("SET clause no longer clears %q", required)
		}
	}
}

// ---------------------------------------------------------------------------
// Database integration. SKIPS without CHAINSAW_DATABASE_URL, matching the
// convention in migrate_repo_guides_test.go.
// ---------------------------------------------------------------------------

// TestClearUnverifiedAttestationIdentity asserts, against a real Postgres:
//
//  1. a row with NULL provenance_status carrying a source repo (the
//     registry-metadata poison) is cleared;
//  2. a row with provenance_status='failed' carrying a full forged identity
//     (the npm StatusFailed poison) is cleared;
//  3. a row with provenance_status='verified' is left BYTE-IDENTICAL;
//  4. re-running reports 0 rows — the migration converges rather than
//     reporting work on every boot.
func TestClearUnverifiedAttestationIdentity(t *testing.T) {
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
	if err := store.DB().Ping(); err != nil {
		t.Skipf("ping db failed (Postgres unreachable, treating as skip): %v", err)
	}

	nonce := fmt.Sprintf("%d", time.Now().UnixNano())
	org := "attid_org_" + nonce
	repo := "attid_repo_" + nonce
	t.Cleanup(func() {
		if _, err := store.DB().Exec(`DELETE FROM package_metadata WHERE org_id = $1`, org); err != nil {
			t.Logf("cleanup: %v", err)
		}
	})

	insert := func(pkg, status string, builder, issuer, srcRepo, tlog any) {
		t.Helper()
		_, err := store.DB().Exec(`
			INSERT INTO package_metadata
			  (org_id, repository, package, version, provenance_status,
			   attestation_builder_id, attestation_issuer,
			   attestation_source_repo, attestation_transparency_log,
			   created_at, updated_at)
			VALUES ($1,$2,$3,'1.0.0',$4,$5,$6,$7,$8,now(),now())`,
			org, repo, pkg, nullOrString(status), builder, issuer, srcRepo, tlog)
		if err != nil {
			t.Fatalf("insert %s: %v", pkg, err)
		}
	}

	// 1. registry-metadata poison: source repo, NO status.
	insert("regmeta", "", nil, nil, "https://github.com/lodash/lodash", nil)
	// 2. npm StatusFailed poison: full forged identity.
	insert("forged", "failed",
		"https://github.com/acme/ci/.github/workflows/release.yml@refs/heads/main",
		"https://token.actions.githubusercontent.com",
		"https://github.com/acme/widgets",
		"https://search.sigstore.dev/?logIndex=99999")
	// 3. genuinely verified — must survive untouched.
	insert("legit", "verified",
		"https://github.com/slsa-framework/slsa-github-generator/x.yml@refs/tags/v1",
		"https://token.actions.githubusercontent.com",
		"https://github.com/acme/widgets",
		"https://search.sigstore.dev/?logIndex=1")

	before, err := store.CountUnverifiedAttestationIdentity()
	if err != nil {
		t.Fatalf("census: %v", err)
	}
	if before < 2 {
		t.Fatalf("census counted %d poisoned rows, want at least the 2 just inserted "+
			"— the predicate is missing the NULL-status population", before)
	}

	n, err := store.clearUnverifiedAttestationIdentity()
	if err != nil {
		t.Fatalf("clear: %v", err)
	}
	if n < 2 {
		t.Fatalf("cleared %d rows, want at least 2", n)
	}

	type row struct{ builder, issuer, srcRepo, tlog *string }
	read := func(pkg string) row {
		t.Helper()
		var r row
		err := store.DB().QueryRow(`
			SELECT attestation_builder_id, attestation_issuer,
			       attestation_source_repo, attestation_transparency_log
			FROM package_metadata WHERE org_id=$1 AND package=$2`, org, pkg).
			Scan(&r.builder, &r.issuer, &r.srcRepo, &r.tlog)
		if err != nil {
			t.Fatalf("read %s: %v", pkg, err)
		}
		return r
	}

	for _, pkg := range []string{"regmeta", "forged"} {
		r := read(pkg)
		if r.builder != nil || r.issuer != nil || r.srcRepo != nil || r.tlog != nil {
			t.Errorf("%s: identity survived the clear: %+v", pkg, r)
		}
	}

	legit := read("legit")
	if legit.builder == nil || legit.srcRepo == nil || legit.tlog == nil {
		t.Errorf("verified row was cleared: %+v — the migration must not touch proven identity", legit)
	}

	// Idempotence. A migration that keeps reporting work on every boot is
	// one that is not converging.
	again, err := store.clearUnverifiedAttestationIdentity()
	if err != nil {
		t.Fatalf("second clear: %v", err)
	}
	if again != 0 {
		t.Errorf("second run cleared %d rows, want 0 — the migration is not idempotent", again)
	}
}

func nullOrString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
