package attestation

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
)

func TestNullString(t *testing.T) {
	if got := nullString(""); got != nil {
		t.Errorf("empty: got %v, want nil", got)
	}
	if got := nullString("x"); got != "x" {
		t.Errorf("non-empty: got %v, want \"x\"", got)
	}
}

func TestStoreNilSafe(t *testing.T) {
	var s *Store
	if err := s.Upsert(context.Background(), &Attestation{Ecosystem: "npm"}); err != nil {
		t.Errorf("nil store Upsert: %v", err)
	}
	if _, err := s.Get(context.Background(), "npm", "p", "1", "sigstore"); !errors.Is(err, ErrNotFound) {
		t.Errorf("nil store Get: want ErrNotFound, got %v", err)
	}
	got, err := s.List(context.Background(), "npm", "p", "1")
	if err != nil || got != nil {
		t.Errorf("nil store List: got %v %v, want nil nil", got, err)
	}
}

func TestUpsertRequiresIdentity(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping DB-backed attestation test")
	}
	sqlStore, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = sqlStore.Close() })
	s := NewStore(sqlStore)

	cases := []*Attestation{
		{Package: "p", Version: "1", AttestationType: "sigstore"}, // no ecosystem
		{Ecosystem: "npm", Version: "1", AttestationType: "sigstore"},
		{Ecosystem: "npm", Package: "p", AttestationType: "sigstore"},
		{Ecosystem: "npm", Package: "p", Version: "1"},
	}
	for _, a := range cases {
		if err := s.Upsert(context.Background(), a); err == nil {
			t.Errorf("Upsert(%+v): want error for missing identity", a)
		}
	}
}

func TestUpsertGetListRoundTrip(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping DB-backed attestation test")
	}
	sqlStore, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = sqlStore.Close() })
	s := NewStore(sqlStore)
	pkg := "chainsaw-attest-test-" + time.Now().UTC().Format("20060102150405.000000000")
	t.Cleanup(func() {
		_, _ = sqlStore.DB().Exec(`DELETE FROM attestations WHERE package_name=$1`, pkg)
	})

	now := time.Now().UTC().Truncate(time.Microsecond)
	provenance := &Attestation{
		Ecosystem:          "npm",
		Package:            pkg,
		Version:            "1.0.0",
		AttestationType:    "sigstore",
		SubjectDigest:      "sha256:abc",
		BundleFormat:       "sigstore-bundle",
		SLSALevel:          3,
		BuilderID:          "https://github.com/slsa-framework/slsa-github-generator",
		SourceRepo:         "https://github.com/foo/bar",
		SourceCommit:       "deadbeef",
		TransparencyLogURL: "https://search.sigstore.dev/?logIndex=1",
		Bundle:             []byte(`{"bundle":1}`),
		VerifiedAt:         now,
	}
	sbom := &Attestation{
		Ecosystem:       "npm",
		Package:         pkg,
		Version:         "1.0.0",
		AttestationType: "sbom",
		SubjectDigest:   "sha256:abc",
		BundleFormat:    "in-toto",
		Bundle:          []byte(`{"sbom":1}`),
		VerifiedAt:      now,
	}
	for _, a := range []*Attestation{provenance, sbom} {
		if err := s.Upsert(context.Background(), a); err != nil {
			t.Fatalf("Upsert %s: %v", a.AttestationType, err)
		}
	}

	got, err := s.Get(context.Background(), "npm", pkg, "1.0.0", "sigstore")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.SLSALevel != 3 || got.BuilderID == "" || got.SourceCommit != "deadbeef" {
		t.Errorf("round-trip lost fields: %+v", got)
	}
	if string(got.Bundle) != `{"bundle":1}` {
		t.Errorf("Bundle = %q", got.Bundle)
	}

	list, err := s.List(context.Background(), "npm", pkg, "1.0.0")
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("List len = %d, want 2", len(list))
	}

	// Re-upsert with a higher SLSA level — most-recent-wins replaces.
	provenance.SLSALevel = 4
	if err := s.Upsert(context.Background(), provenance); err != nil {
		t.Fatalf("re-upsert: %v", err)
	}
	got, err = s.Get(context.Background(), "npm", pkg, "1.0.0", "sigstore")
	if err != nil {
		t.Fatalf("Get after re-upsert: %v", err)
	}
	if got.SLSALevel != 4 {
		t.Errorf("re-upsert: SLSALevel = %d, want 4", got.SLSALevel)
	}
}

func TestGetReturnsErrNotFound(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping DB-backed attestation test")
	}
	sqlStore, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = sqlStore.Close() })
	s := NewStore(sqlStore)
	if _, err := s.Get(context.Background(), "npm", "no-such-pkg", "0.0.0", "sigstore"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}
