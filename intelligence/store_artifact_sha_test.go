package intelligence

// DB-backed proof that intelligence_reports.artifact_sha256 is REAL.
//
// It was NULL for every row from the day the table was created: the upsert
// sourced it from Report.Scan.ScannedArtifactSHA, a field the Report type
// declares, MergeScan copies, and no provider has ever assigned. It is now
// sourced from Artifact.Digests.SHA256 — the digest provider_checksum computes
// by hashing the bytes.
//
// Three properties, one per test, because they fail independently:
//   - a computed digest lands in the column
//   - a later metadata-only upsert does not erase it (the COALESCE)
//   - a caller-DECLARED digest never populates it

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
)

func openArtifactSHADB(t *testing.T) *pgstore.Store {
	t.Helper()
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open pgstore: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// shaFixture is one coordinate plus a handle on its stored column.
type shaFixture struct {
	db    *pgstore.Store
	store *Store
	key   Key
}

func newSHAFixture(t *testing.T, tag string) *shaFixture {
	t.Helper()
	db := openArtifactSHADB(t)
	uniq := strings.ReplaceAll(time.Now().UTC().Format("20060102150405.000000000"), ".", "")
	key := Key{Ecosystem: "npm", Package: tag + "-" + uniq, Version: "1.0.0"}
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_reports WHERE ecosystem=$1 AND package_name=$2`,
			key.Ecosystem, key.Package)
	})
	return &shaFixture{db: db, store: NewStore(db), key: key}
}

// column returns the stored artifact_sha256, and whether it is non-NULL.
func (f *shaFixture) column(t *testing.T) (string, bool) {
	t.Helper()
	var got sql.NullString
	err := f.db.DB().QueryRow(
		`SELECT artifact_sha256 FROM intelligence_reports
		  WHERE ecosystem=$1 AND package_name=$2 AND version=$3`,
		f.key.Ecosystem, f.key.Package, f.key.Version).Scan(&got)
	if err != nil {
		t.Fatalf("read artifact_sha256: %v", err)
	}
	return got.String, got.Valid
}

// report builds a minimal upsertable Report for this coordinate.
func (f *shaFixture) report(digests ArtifactDigest) *Report {
	now := time.Now().UTC()
	return &Report{
		Identity: IdentitySection{
			Ecosystem: f.key.Ecosystem,
			Package:   f.key.Package,
			Version:   f.key.Version,
		},
		Artifact: ArtifactSection{Digests: digests},
		Observation: ObservationSection{
			CollectedAt:  now,
			FreshUntil:   now.Add(24 * time.Hour),
			MatcherEpoch: CurrentMatcherEpoch,
		},
	}
}

const testComputedSHA = "9f2c1b4e5a6d7f80112233445566778899aabbccddeeff00112233445566778"

// TestArtifactSHAColumnIsPopulatedFromTheComputedDigest: the column follows
// Artifact.Digests.SHA256.
func TestArtifactSHAColumnIsPopulatedFromTheComputedDigest(t *testing.T) {
	f := newSHAFixture(t, "shacol")
	ctx := context.Background()

	// 64 hex chars, as computeArtifactSHA256 produces.
	sha := testComputedSHA + "9"
	if err := f.store.Upsert(ctx, "", f.report(ArtifactDigest{SHA256: sha, Actual: sha})); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	got, ok := f.column(t)
	if !ok {
		t.Fatal("artifact_sha256 is NULL after an upsert carrying a computed digest. " +
			"The column was NULL for every row in the corpus because the upsert read " +
			"Scan.ScannedArtifactSHA, which no provider assigns; it must now read " +
			"Artifact.Digests.SHA256.")
	}
	if got != sha {
		t.Errorf("artifact_sha256 = %q, want %q", got, sha)
	}
}

// TestArtifactSHAColumnSurvivesAMetadataOnlyUpsert is the COALESCE.
//
// A Tier-1 refresh carries no bytes, so provider_checksum does not run and
// Digests.SHA256 is empty. The column must keep what it already held — a
// digest is a fact about bytes once seen, and the artifact-coverage facet
// decays every refresh cycle if a metadata pass can erase it.
//
// This is also the arm that makes the column strictly better than the report
// JSONB: `report` is replaced wholesale on every upsert and
// mergeReportPayload preserves Digests.Actual and .Verified but NOT .SHA256,
// so the JSON key is lost here while the column is not.
func TestArtifactSHAColumnSurvivesAMetadataOnlyUpsert(t *testing.T) {
	f := newSHAFixture(t, "shacoal")
	ctx := context.Background()

	sha := testComputedSHA + "a"
	if err := f.store.Upsert(ctx, "", f.report(ArtifactDigest{SHA256: sha, Actual: sha})); err != nil {
		t.Fatalf("seed upsert: %v", err)
	}
	if got, ok := f.column(t); !ok || got != sha {
		t.Fatalf("seed did not store the digest (got %q ok=%v), so the erasure "+
			"assertion below would pass vacuously", got, ok)
	}

	// Metadata-only: no digests at all.
	if err := f.store.Upsert(ctx, "", f.report(ArtifactDigest{})); err != nil {
		t.Fatalf("metadata-only upsert: %v", err)
	}

	got, ok := f.column(t)
	if !ok {
		t.Fatal("a metadata-only upsert ERASED artifact_sha256. The upsert's " +
			"COALESCE(EXCLUDED.artifact_sha256, intelligence_reports.artifact_sha256) " +
			"is what prevents this; without it every Tier-1 refresh drops the digest " +
			"and the A-3 backfill join loses the row.")
	}
	if got != sha {
		t.Errorf("artifact_sha256 = %q after a metadata-only upsert, want the prior %q",
			got, sha)
	}
}

// TestArtifactSHAColumnIgnoresADeclaredDigest: a caller- or registry-declared
// digest must never name the bytes.
//
// Digests.Declared is whatever the registry asserted and is precisely the value
// provider_checksum exists to CHECK. Sourcing the column from it would let an
// upstream claim decide the identity of bytes nobody hashed — and the A-3 cache
// keys analyses on this digest, so a wrong one would address another artifact's
// analysis.
func TestArtifactSHAColumnIgnoresADeclaredDigest(t *testing.T) {
	f := newSHAFixture(t, "shadecl")
	ctx := context.Background()

	// Declared present, computed absent: exactly a metadata-only scan of a
	// coordinate whose registry advertises a hash.
	declared := testComputedSHA + "b"
	if err := f.store.Upsert(ctx, "", f.report(ArtifactDigest{Declared: declared})); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if got, ok := f.column(t); ok {
		t.Errorf("artifact_sha256 = %q from a DECLARED-only digest, want NULL. The "+
			"column must come from the computed hash of the bytes; a declared value "+
			"is an upstream claim, and the A-3 analysis cache keys on this digest.", got)
	}
}

// TestArtifactSHAColumnIgnoresASwiftActualDigest.
//
// Digests.Actual survives mergeReportPayload where .SHA256 does not, which
// makes it a tempting source. It is not one: on the swift path
// `digests.Actual = altHex` holds a sha1/sha512 whenever the declared
// algorithm is not sha256, so Actual is not reliably a sha256 and must never
// key anything compared against one.
func TestArtifactSHAColumnIgnoresASwiftActualDigest(t *testing.T) {
	f := newSHAFixture(t, "shaswift")
	ctx := context.Background()

	// A 40-char sha1, as the swift path would leave in Actual.
	if err := f.store.Upsert(ctx, "", f.report(ArtifactDigest{
		Actual: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
		SHA1:   "da39a3ee5e6b4b0d3255bfef95601890afd80709",
	})); err != nil {
		t.Fatalf("upsert: %v", err)
	}

	if got, ok := f.column(t); ok {
		t.Errorf("artifact_sha256 = %q from Digests.Actual, want NULL. Actual is the "+
			"digest under the VERIFIED algorithm, which on the swift path is not "+
			"sha256.", got)
	}
}
