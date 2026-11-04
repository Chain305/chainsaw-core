package config

import (
	"slices"
	"testing"

	"github.com/chain305/chainsaw-core/pgstore"
)

func offerStore(t *testing.T) (*pgstore.Store, string) {
	t.Helper()
	store, org := createStore(t)
	clean := func() { _, _ = store.DB().Exec(`DELETE FROM seed_repository_offers WHERE org_id=$1`, org) }
	clean()
	t.Cleanup(clean)
	return store, org
}

func orgRepoNames(t *testing.T, store *pgstore.Store, org string) []string {
	t.Helper()
	rows, err := store.DB().Query(`SELECT name FROM repositories WHERE org_id=$1 ORDER BY name`, org)
	if err != nil {
		t.Fatalf("list repos: %v", err)
	}
	defer rows.Close()
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatalf("scan: %v", err)
		}
		names = append(names, n)
	}
	return names
}

// A seeded org that later gets a new seed repository receives it once; a
// repository it deleted is not re-created.
func TestOfferNewSeedRepositoriesAddsOnlyNewNames(t *testing.T) {
	store, org := offerStore(t)
	v1 := []RepositoryConfig{sampleRepo("npm-a"), sampleRepo("npm-b")}
	if err := ReplaceRepositoriesForOrg(store, org, v1); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := store.DB().Exec(`DELETE FROM repositories WHERE org_id=$1 AND name='npm-b'`, org); err != nil {
		t.Fatalf("delete: %v", err)
	}

	v2 := append(v1, sampleRepo("npm-new"))
	added, err := OfferNewSeedRepositoriesForOrg(store, org, v2)
	if err != nil {
		t.Fatalf("offer: %v", err)
	}
	if !slices.Equal(added, []string{"npm-new"}) {
		t.Fatalf("added = %v, want [npm-new]", added)
	}
	if got := orgRepoNames(t, store, org); !slices.Equal(got, []string{"npm-a", "npm-new"}) {
		t.Fatalf("repos = %v, want [npm-a npm-new] (deleted npm-b must stay deleted)", got)
	}

	// Second boot: nothing new, and deleting the new one sticks too.
	if _, err := store.DB().Exec(`DELETE FROM repositories WHERE org_id=$1 AND name='npm-new'`, org); err != nil {
		t.Fatalf("delete: %v", err)
	}
	added, err = OfferNewSeedRepositoriesForOrg(store, org, v2)
	if err != nil || len(added) != 0 {
		t.Fatalf("second offer: added=%v err=%v, want none", added, err)
	}
	if got := orgRepoNames(t, store, org); !slices.Equal(got, []string{"npm-a"}) {
		t.Fatalf("repos = %v, want [npm-a]", got)
	}
}

// An org with no recorded offers (every org that predates the table) is
// baselined: its missing seed repositories may be deliberate deletions.
func TestOfferNewSeedRepositoriesBaselinesUnrecordedOrg(t *testing.T) {
	store, org := offerStore(t)
	if _, err := CreateRepositoryForOrg(store, org, sampleRepo("npm-a")); err != nil {
		t.Fatalf("create: %v", err)
	}
	seed := []RepositoryConfig{sampleRepo("npm-a"), sampleRepo("npm-deleted-long-ago")}
	added, err := OfferNewSeedRepositoriesForOrg(store, org, seed)
	if err != nil || len(added) != 0 {
		t.Fatalf("baseline: added=%v err=%v, want none", added, err)
	}
	if got := orgRepoNames(t, store, org); !slices.Equal(got, []string{"npm-a"}) {
		t.Fatalf("repos = %v, want [npm-a]", got)
	}
	added, err = OfferNewSeedRepositoriesForOrg(store, org, append(seed, sampleRepo("npm-next")))
	if err != nil || !slices.Equal(added, []string{"npm-next"}) {
		t.Fatalf("after baseline: added=%v err=%v, want [npm-next]", added, err)
	}
}

// A name the org already uses for its own repository is recorded as offered
// and the org's repository is left untouched.
func TestOfferNewSeedRepositoriesKeepsOrgOwnedName(t *testing.T) {
	store, org := offerStore(t)
	if err := ReplaceRepositoriesForOrg(store, org, []RepositoryConfig{sampleRepo("npm-a")}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	mine := sampleRepo("homebrew")
	mine.Remote.URL = "https://mirror.example.internal/"
	if _, err := CreateRepositoryForOrg(store, org, mine); err != nil {
		t.Fatalf("create: %v", err)
	}
	seedHB := sampleRepo("homebrew")
	seedHB.Format = "homebrew"
	seedHB.Remote.URL = "https://ghcr.io"
	added, err := OfferNewSeedRepositoriesForOrg(store, org, []RepositoryConfig{sampleRepo("npm-a"), seedHB})
	if err != nil || len(added) != 0 {
		t.Fatalf("offer: added=%v err=%v, want none", added, err)
	}
	var url string
	if err := store.DB().QueryRow(`SELECT remote_url FROM repositories WHERE org_id=$1 AND name='homebrew'`, org).Scan(&url); err != nil {
		t.Fatalf("read: %v", err)
	}
	if url != "https://mirror.example.internal/" {
		t.Fatalf("org-owned repository overwritten: remote_url=%q", url)
	}
}
