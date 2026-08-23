package pgstore

// Data backfill: repair per-org client-configuration guide prose that was
// snapshotted before 78f3548f.
//
// Why a backfill is needed at all. The setup-wizard guide is not rendered
// from configs/seed.yaml at request time — it is COPIED into
// `repositories.client_configuration_guide_template` once, per org, when the
// org's repositories are first seeded (internal/server/repositories_seed.go →
// config.ReplaceRepositoriesForOrgTx, and the equivalent branch in
// initRepositories). Fixing the YAML therefore reaches new orgs only. Every
// org created before the fixed image rolled out keeps its snapshot forever,
// because config.SaveToStore rewrites the DEFAULT org only
// (core/config/store.go:758-761) — so the default org self-heals on boot and
// no tenant org does.
//
// What the stale snapshots serve:
//   - a registry URL missing the `/chainproxy` prefix, e.g.
//     `https://chain305.com/repository/@slug/npmjs/` — a guaranteed 404; and
//   - the superseded "base64-encode your client id and secret into a Bearer
//     token" prose, which 401s on every request, because the server parses a
//     Bearer token by splitting on the colon and base64 contains none.
//
// Render-time substitution cannot rescue these rows. The fix introduced a NEW
// placeholder token — repositoryGuideFreshMarker below — and old prose
// contains zero instances of it, so there is nothing in the persisted text to
// substitute against. The text has to be replaced.
//
// Why this is NOT config.ReplaceRepositoriesForOrgTx. That helper DELETEs the
// org's repository rows before re-inserting them
// (core/config/store.go:783), which would silently discard every
// operator-customised value on the row: `enabled`, `anonymous_access`,
// `remote_url`, `remote_headers`, `format_options`, `public_base_url`. A
// tenant that had disabled a proxy or repointed it at an internal mirror
// would come back from the migration with the seed defaults. This backfill is
// therefore a targeted, COLUMN-ONLY update: it writes exactly one column and
// touches nothing else on the row.
//
// KNOWN, ACCEPTED COLLATERAL: an operator who hand-edited a guide AND is
// still on pre-78f3548f prose gets their edit overwritten. There is no way to
// distinguish "hand-edited old prose" from "untouched old prose" — both lack
// the marker — and leaving a hand-edited row on a URL that 404s and an auth
// snippet that 401s is the worse outcome. Accepted deliberately.
//
// Convention note: pgstore has no numbered migration runner (see the TODO at
// the top of migrate.go). Schema changes are idempotent DDL applied on every
// Open(); backfills are idempotent statements next to them, e.g.
// backfillDefaultPlanAssignment in migrate_seed.go. There is no rollback
// step, here or anywhere else in this package — the same forward-only model.
// This one differs from its neighbours in exactly one way: it needs the seed
// prose, which lives in configs/seed.yaml and is loaded by core/config. That
// package imports pgstore (core/config/clients.go:15), so pgstore cannot
// import it back. The replacement text is therefore passed IN by the caller,
// which reads it from the same `cfg.Repositories` the seeder itself uses — so
// the backfill cannot drift from configs/seed.yaml.
//
// Intended call site — cmd/chainsaw-proxy/main.go, initRepositories(), which
// already holds both the *pgstore.Store and the parsed cfg:
//
//	guides := make([]RepositoryGuide, 0, len(cfg.Repositories))
//	for _, r := range cfg.Repositories {
//	    guides = append(guides, pgstore.RepositoryGuide{
//	        Name: r.Name, Guide: r.ClientConfigurationGuide,
//	    })
//	}
//	n, err := store.BackfillStaleRepositoryGuides(ctx, guides)
//
// Run StaleRepositoryGuideCounts first for the read-only dry run.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// repositoryGuideFreshMarker is the placeholder token introduced by 78f3548f.
// Its presence in a persisted guide is the marker that the row was written
// from post-fix prose; its absence is the marker that the row is stale.
//
// This is the whole idempotency mechanism, and it is also what bounds the
// blast radius: a row that already carries the token is never rewritten, so
// re-running the backfill is a no-op and a post-fix customisation survives.
//
// If seed.yaml ever stops using this token, this constant must move with it —
// TestRepositoryGuideMarkerMatchesSeedYAML pins that.
const repositoryGuideFreshMarker = "your-chainsaw-base"

// RepositoryGuide is one (repository name, guide prose) pair, sourced by the
// caller from the same config the seeder uses. Guide is trimmed before it is
// written, matching config.upsertRepository, so a backfilled row is
// byte-identical to a freshly-seeded one.
type RepositoryGuide struct {
	Name  string
	Guide string
}

// backfillStaleRepositoryGuideSQL rewrites one repository's guide column
// across every org that still holds pre-78f3548f prose.
//
// Predicate, clause by clause:
//
//	name = $2                       — scoped to one seeded repository; the
//	                                  statement runs once per entry in the
//	                                  caller's list. Deliberately NOT scoped
//	                                  by org: every tenant org created before
//	                                  the fix is affected.
//	... IS NOT NULL AND <> ''       — an org with no guide prose at all never
//	                                  had one; this migration repairs stale
//	                                  prose, it does not introduce prose.
//	                                  (SQL three-valued logic would exclude
//	                                  NULL via the <> '' test alone; spelled
//	                                  out because this statement mutates data.)
//	... NOT LIKE '%<marker>%'       — the idempotency and blast-radius clause.
//	                                  Rows already on post-fix prose are left
//	                                  alone, so a second run changes nothing.
//	... <> $1                       — belt and braces: a row already holding
//	                                  exactly the replacement text is skipped
//	                                  even if that text somehow lacks the
//	                                  marker, so this can never become a
//	                                  statement that rewrites the same bytes
//	                                  on every boot.
//
// Only the guide column and updated_at are in the SET list. enabled,
// anonymous_access, remote_url, remote_headers, format_options and
// public_base_url are untouched by construction.
const backfillStaleRepositoryGuideSQL = `
	UPDATE repositories
	   SET client_configuration_guide_template = ?,
	       updated_at = CURRENT_TIMESTAMP
	 WHERE name = ?
	   AND client_configuration_guide_template IS NOT NULL
	   AND client_configuration_guide_template <> ''
	   AND client_configuration_guide_template NOT LIKE '%` + repositoryGuideFreshMarker + `%'
	   AND client_configuration_guide_template <> ?`

// staleRepositoryGuideCountSQL is the read-only dry run. It shares the stale
// predicate with the UPDATE above so an operator cannot enumerate one
// population and then mutate a different one.
const staleRepositoryGuideCountSQL = `
	SELECT name, count(*)
	  FROM repositories
	 WHERE client_configuration_guide_template IS NOT NULL
	   AND client_configuration_guide_template <> ''
	   AND client_configuration_guide_template NOT LIKE '%` + repositoryGuideFreshMarker + `%'
	 GROUP BY name`

// StaleRepositoryGuideCounts reports how many repository rows still carry
// pre-78f3548f guide prose, keyed by repository name. Read-only; run it
// before BackfillStaleRepositoryGuides to size the change.
//
// The count is deliberately unfiltered by the caller's guide list: a name
// that appears here but not in configs/seed.yaml is a repository the backfill
// cannot repair (an operator-created proxy, or one dropped from the seed),
// and seeing it is more useful than silently excluding it.
func (s *Store) StaleRepositoryGuideCounts(ctx context.Context) (map[string]int, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	rows, err := s.ReadDB().QueryContext(ctx, staleRepositoryGuideCountSQL)
	if err != nil {
		return nil, fmt.Errorf("count stale repository guides: %w", err)
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var name string
		var n int
		if err := rows.Scan(&name, &n); err != nil {
			return nil, fmt.Errorf("scan stale repository guide count: %w", err)
		}
		counts[name] = n
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate stale repository guide counts: %w", err)
	}
	return counts, nil
}

// BackfillStaleRepositoryGuides replaces pre-78f3548f guide prose with the
// supplied replacement text, one statement per named repository, across every
// org. It returns the number of rows rewritten.
//
// Idempotent: the second call returns 0 because every row it touched now
// carries repositoryGuideFreshMarker. Safe to call on every boot.
//
// All statements run in one transaction. A partial failure would otherwise
// leave the fleet split between two guide revisions, which is harder to
// reason about than "the migration did not run".
//
// Entries with an empty name, or whose replacement text is blank after
// trimming, are skipped: blanking a guide would replace a wrong URL with no
// instructions at all.
func (s *Store) BackfillStaleRepositoryGuides(ctx context.Context, guides []RepositoryGuide) (int64, error) {
	if s == nil || s.db == nil || len(guides) == 0 {
		return 0, nil
	}

	var updated int64
	err := s.WithTx(ctx, func(tx *sql.Tx) error {
		for _, g := range guides {
			name := strings.TrimSpace(g.Name)
			// Trimmed to match config.upsertRepository, which stores
			// strings.TrimSpace(repo.ClientConfigurationGuide). Without the
			// trim a backfilled row would differ from a freshly-seeded one by
			// leading/trailing whitespace, and the `<> $1` no-op guard above
			// would stop matching.
			guide := strings.TrimSpace(g.Guide)
			if name == "" || guide == "" {
				continue
			}
			res, err := tx.ExecContext(ctx, backfillStaleRepositoryGuideSQL, guide, name, guide)
			if err != nil {
				return fmt.Errorf("backfill guide for repository %q: %w", name, err)
			}
			n, err := res.RowsAffected()
			if err != nil {
				return fmt.Errorf("rows affected backfilling repository %q: %w", name, err)
			}
			updated += n
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return updated, nil
}
