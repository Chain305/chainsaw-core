package config

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/tenancy"
)

// createStore opens the DB-backed store plus a per-test org, so the rows
// written here can never collide with another test's view of the default
// org. Gated on CHAINSAW_DATABASE_URL like every other DB test in the tree.
func createStore(t *testing.T) (*pgstore.Store, string) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CHAINSAW_DATABASE_URL"))
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping DB-backed repository create test")
	}
	store, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	org := tenancy.NormalizeOrgID("repocreate-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")))
	clean := func() { _, _ = store.DB().Exec(`DELETE FROM repositories WHERE org_id=$1`, org) }
	clean()
	t.Cleanup(func() {
		clean()
		_ = store.Close()
	})
	return store, org
}

func sampleRepo(name string) RepositoryConfig {
	anon := false
	return RepositoryConfig{
		Name:            name,
		Format:          "npm",
		Type:            "proxy",
		AnonymousAccess: &anon,
		Remote:          RemoteConfig{URL: "https://registry.npmjs.org/", TimeoutSeconds: 60},
		Cache:           CacheConfig{NegativeTTLSeconds: 300},
	}
}

func TestCreateRepositoryForOrgRoundTrip(t *testing.T) {
	store, org := createStore(t)

	stored, err := CreateRepositoryForOrg(store, org, sampleRepo("audit-npm"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if stored.Name != "audit-npm" || stored.Format != "npm" || stored.Type != "proxy" {
		t.Fatalf("round-tripped config mismatch: %+v", stored)
	}
	if stored.Remote.URL != "https://registry.npmjs.org/" {
		t.Fatalf("remote url: got %q", stored.Remote.URL)
	}
	if stored.Cache.NegativeTTLSeconds != 300 {
		t.Fatalf("negative ttl: got %d", stored.Cache.NegativeTTLSeconds)
	}
	if !stored.EnabledValue() {
		t.Fatalf("a created repository must be enabled by default")
	}
}

// TestCreateRepositoryForOrgRejectsDuplicate is the 409 source of truth.
// upsertRepository on its own is ON CONFLICT DO UPDATE, so without the
// existence check a second create would silently redefine the first.
func TestCreateRepositoryForOrgRejectsDuplicate(t *testing.T) {
	store, org := createStore(t)

	if _, err := CreateRepositoryForOrg(store, org, sampleRepo("audit-npm")); err != nil {
		t.Fatalf("first create: %v", err)
	}
	second := sampleRepo("audit-npm")
	second.Remote.URL = "https://example.invalid/"
	_, err := CreateRepositoryForOrg(store, org, second)
	if !errors.Is(err, ErrRepositoryExists) {
		t.Fatalf("second create: got %v, want ErrRepositoryExists", err)
	}

	// And the original definition must be untouched.
	existing, err := fetchRepository(store.DB(), org, "audit-npm")
	if err != nil {
		t.Fatalf("fetch after duplicate: %v", err)
	}
	if existing.Remote.URL != "https://registry.npmjs.org/" {
		t.Fatalf("duplicate create clobbered the existing remote: %q", existing.Remote.URL)
	}
}

// TestCreateRepositoryForOrgKeepsSiblings is the reason this is not
// ReplaceRepositoriesForOrg: that helper DELETEs every row for the org
// before writing, which would wipe the rest of the org on a single create.
func TestCreateRepositoryForOrgKeepsSiblings(t *testing.T) {
	store, org := createStore(t)

	if err := ReplaceRepositoriesForOrg(store, org, []RepositoryConfig{
		sampleRepo("npmjs"),
		sampleRepo("pypi-proxy"),
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := CreateRepositoryForOrg(store, org, sampleRepo("audit-npm")); err != nil {
		t.Fatalf("create: %v", err)
	}

	loaded, hasRepos, err := LoadFromStoreForOrg(store, org)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !hasRepos {
		t.Fatalf("expected repositories for org %s", org)
	}
	names := map[string]bool{}
	for _, repo := range loaded.Repositories {
		names[repo.Name] = true
	}
	for _, want := range []string{"npmjs", "pypi-proxy", "audit-npm"} {
		if !names[want] {
			t.Fatalf("repository %q missing after create; got %v", want, names)
		}
	}
}

func TestCreateRepositoryForOrgRejectsIncompleteInput(t *testing.T) {
	store, org := createStore(t)

	if _, err := CreateRepositoryForOrg(nil, org, sampleRepo("audit-npm")); err == nil {
		t.Fatalf("expected a nil store to be rejected")
	}
	noName := sampleRepo("   ")
	if _, err := CreateRepositoryForOrg(store, org, noName); err == nil {
		t.Fatalf("expected a blank name to be rejected")
	}
	noFormat := sampleRepo("audit-npm")
	noFormat.Format = ""
	if _, err := CreateRepositoryForOrg(store, org, noFormat); err == nil {
		t.Fatalf("expected a blank format to be rejected")
	}
}
