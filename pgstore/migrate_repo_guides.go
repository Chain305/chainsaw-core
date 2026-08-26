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
	"sort"
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
// The raw SQL count is deliberately unfiltered by the caller's guide list.
// The three-way split below is applied in Go, because "matches the stale
// predicate" and "the backfill can do something about it" are different
// questions and the answer to the second one is not in the database.
//
// repairable reports whether the backfill could actually change a row for
// this repository — i.e. whether the replacement prose the caller supplied
// for it contains the freshness marker at all.
//
// HISTORY, and the correction (P8-28). cef96422 introduced this filter to
// stop a permanent phantom count: the first production run reported "stale
// rows found total=63 by_repository=map[docker-hub:38 swift:25]" next to
// "rows_updated=0", on every boot. The comment it shipped with said
// docker-hub and swift "address the bare host rather than the /chainproxy
// path, so their prose contains no `your-chainsaw-base` token and never
// will". That is true of docker-hub and FALSE of swift — the swift guide is
// full of the token (see the retired_repository_guides entry in
// configs/seed.yaml). Swift was excluded for an entirely different reason:
// 5373b2ff deleted it from `repositories:`, so it was not in the caller's
// guide list at all, and a name that is not in the list can never be in
// repairable() no matter what its prose says.
//
// The two exclusions therefore mean opposite things and must not share a
// bucket:
//
//	markerless — seed guide EXISTS, carries no marker (docker-hub). Every
//	             row matches the stale predicate forever, and the UPDATE
//	             leaves them alone whenever the stored text already equals
//	             the replacement. Counting them is the phantom.
//	orphaned   — NO guide exists to replace the row with. Nothing can ever
//	             repair it. Silently dropping these turned a visible problem
//	             into an invisible one, which is why the caller logs the
//	             bucket at WARN with the names.
//
// Orphans are not a swift-specific accident: any repository an operator
// creates by hand, and any future seed deletion, lands here the same way.
// The answer for a seeded-then-deleted repository is the
// retired_repository_guides list, which keeps its prose reachable so it
// stays in repairable(); the answer for an operator-created repository is
// that the operator owns its guide.
func repairable(guides []RepositoryGuide) map[string]struct{} {
	out := make(map[string]struct{}, len(guides))
	for _, g := range guides {
		if strings.Contains(g.Guide, repositoryGuideFreshMarker) {
			out[g.Name] = struct{}{}
		}
	}
	return out
}

// knownGuideNames is every repository the caller supplied prose for,
// whether or not that prose carries the marker. A stale row whose name is
// absent from this set is an orphan.
func knownGuideNames(guides []RepositoryGuide) map[string]struct{} {
	out := make(map[string]struct{}, len(guides))
	for _, g := range guides {
		if strings.TrimSpace(g.Name) != "" {
			out[g.Name] = struct{}{}
		}
	}
	return out
}

// StaleGuideCounts is the stale population split by what can be done about
// it. Each map is repository name -> row count across all orgs.
type StaleGuideCounts struct {
	// Repairable rows the backfill will rewrite on this boot.
	Repairable map[string]int
	// Markerless rows belong to a seeded repository whose prose carries no
	// freshness marker, so they match the stale predicate permanently. The
	// UPDATE still runs for them and still writes nothing while the stored
	// text equals the replacement. Reported for diagnosis, not alarm.
	Markerless map[string]int
	// Orphaned rows have no seed guide at all. Nothing in this process can
	// repair them; an operator has to.
	Orphaned map[string]int
}

// Total is every stale row, across all three buckets.
func (c StaleGuideCounts) Total() int {
	n := 0
	for _, m := range []map[string]int{c.Repairable, c.Markerless, c.Orphaned} {
		for _, v := range m {
			n += v
		}
	}
	return n
}

// RepairableTotal is the population the UPDATE is allowed to touch — the
// number that should agree with BackfillStaleRepositoryGuides's return.
func (c StaleGuideCounts) RepairableTotal() int {
	n := 0
	for _, v := range c.Repairable {
		n += v
	}
	return n
}

// OrphanNames lists the orphaned repository names in sorted order, for a
// log line an operator can act on.
func (c StaleGuideCounts) OrphanNames() []string {
	out := make([]string, 0, len(c.Orphaned))
	for name := range c.Orphaned {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func (s *Store) StaleRepositoryGuideCounts(ctx context.Context, guides []RepositoryGuide) (StaleGuideCounts, error) {
	counts := StaleGuideCounts{
		Repairable: map[string]int{},
		Markerless: map[string]int{},
		Orphaned:   map[string]int{},
	}
	if s == nil || s.db == nil {
		return counts, nil
	}
	repair := repairable(guides)
	known := knownGuideNames(guides)
	rows, err := s.ReadDB().QueryContext(ctx, staleRepositoryGuideCountSQL)
	if err != nil {
		return counts, fmt.Errorf("count stale repository guides: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		var n int
		if err := rows.Scan(&name, &n); err != nil {
			return counts, fmt.Errorf("scan stale repository guide count: %w", err)
		}
		_, canRepair := repair[name]
		_, isSeeded := known[name]
		switch {
		case canRepair:
			counts.Repairable[name] = n
		case isSeeded:
			counts.Markerless[name] = n
		default:
			counts.Orphaned[name] = n
		}
	}
	if err := rows.Err(); err != nil {
		return counts, fmt.Errorf("iterate stale repository guide counts: %w", err)
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
