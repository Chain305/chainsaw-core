package config

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/tenancy"
)

// recordSeedOffersTx marks every named repository as offered to the org.
// Existing offers are kept: an offer is never withdrawn, which is what stops
// a repository the org deleted from coming back.
func recordSeedOffersTx(tx *sql.Tx, orgID string, repos []RepositoryConfig) error {
	for _, repo := range repos {
		name := strings.TrimSpace(repo.Name)
		if name == "" {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO seed_repository_offers(org_id, name) VALUES(?, ?)
			ON CONFLICT(org_id, name) DO NOTHING`, orgID, name); err != nil {
			return err
		}
	}
	return nil
}

// OfferNewSeedRepositoriesForOrg gives an existing org each seed repository
// it has never been offered, and returns the names it created.
//
// Repositories are seeded only when an org is created (or has none at boot),
// so a seed repository added in a later release never reached existing orgs:
// v0.22.151's homebrew repository answered 404 CHW-4306 for every org that
// predated it until a hand-written backfill. This closes that gap without
// re-creating anything an org deleted, by remembering offers rather than
// diffing against the org's current rows:
//
//   - An org with no offers recorded is BASELINED: every current seed name is
//     recorded and nothing is created. That covers every org that existed
//     before this table, whose missing seed repositories may be deliberate
//     deletions, and an org whose offers were never recorded.
//   - Otherwise each seed name not yet offered is recorded and, when the org
//     has no repository of that name, created from the seed.
//
// A per-org advisory lock serialises replicas booting together.
func OfferNewSeedRepositoriesForOrg(store *pgstore.Store, orgID string, seed []RepositoryConfig) ([]string, error) {
	if store == nil {
		return nil, errors.New("database store is required")
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	var added []string
	err := store.WithTx(context.Background(), func(tx *sql.Tx) error {
		added = nil
		if _, err := tx.Exec(`SELECT pg_advisory_xact_lock(hashtext(?))`, "seed_repository_offers:"+orgID); err != nil {
			return err
		}
		offered := map[string]bool{}
		rows, err := tx.Query(`SELECT name FROM seed_repository_offers WHERE org_id=?`, orgID)
		if err != nil {
			return err
		}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return err
			}
			offered[name] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(offered) == 0 {
			return recordSeedOffersTx(tx, orgID, seed)
		}
		for _, repo := range seed {
			name := strings.TrimSpace(repo.Name)
			if name == "" || offered[name] {
				continue
			}
			var exists bool
			if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM repositories WHERE org_id=? AND name=?)`,
				orgID, name).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				if err := upsertRepository(tx, orgID, repo); err != nil {
					return err
				}
				added = append(added, name)
			}
			if err := recordSeedOffersTx(tx, orgID, []RepositoryConfig{repo}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return added, nil
}
