package pgstore

// Opt-in cleanup: remove intelligence_reports rows whose `version` component
// can never be ordered against an advisory bound.
//
// WHAT THESE ROWS ARE. Three shapes, all verified against production on
// 2026-08-23 (27 rows across maven / gradle / maven-hosted):
//
//	maven  | org.apache.commons:commons-lang3 | ${commons.lang3.version}
//	gradle | com.google.code.findbugs:jsr305  | ${jsr305.version}
//	maven  | com.t_est.upload:t-est-maven-…   | metadata
//
// `${…}` is a build-tool property the manifest was read before interpolating;
// `metadata` is a synthetic marker the upload path stamps on
// maven-metadata.xml so the file gets a coordinate at all. Neither names a
// point on a version line, so no advisory range can ever match, so the row
// reports clean forever regardless of what the package actually ships — and
// every surface that lists it counts it as covered.
//
// intelligence.UnevaluableVersionReason is the shared definition of "cannot
// be matched" and the ingest gate that stops new ones being written;
// intelligence.Store.UnevaluableVersionCounts is the read-only census of the
// whole population, bucketed by (ecosystem, reason). This file is the missing
// third piece: the way to actually remove them.
//
// WHY IT IS OPT-IN AND NOT A BOOT-TIME MIGRATION. Its neighbours in this
// package (backfillDefaultPlanAssignment, BackfillStaleRepositoryGuides) run
// on every Open() because they are idempotent UPDATEs that converge on a
// known-good value. This one DELETEs, and a delete that runs unattended on
// every start has a far worse failure mode than the thing it cleans up: these
// 27 rows are inert — they are marked WarnVersionNotEvaluable, core/coverage
// classifies that as not_applicable so they cannot trip the fail-closed gate,
// and the OSV provider never ran for them — whereas a predicate that is
// slightly wrong, or a rule struct a caller populates slightly wrong, silently
// eats real inventory on every pod restart with no operator in the loop. The
// asymmetry is the whole argument. Hygiene, not urgency: it is exported, it is
// callable, it is called by nothing at boot, and the operator runs
// UnevaluableCoordinateCounts first.
//
// DELETE, NOT MARK-AND-KEEP — and why that is defensible here. The coordinate
// carries no information a rescan could not reproduce: intelligence_reports is
// a CACHE keyed on (ecosystem, package_name, version), the row holds a fetched
// report and no operator-authored state, and if the same manifest is ingested
// again the row simply comes back (now interpolated, since
// intelligence.resolveMavenVersion resolves same-document properties, or else
// re-marked by the ingest gate). Nothing references these rows — no foreign
// key in the schema points at intelligence_reports — so a delete cannot
// orphan anything.
//
// The counter-argument was made explicitly when the census was added: the rows
// are the evidence that some producer is emitting uninterpolated manifests,
// and deleting evidence to tidy a table is a bad trade. That argument held
// while there was no marker and no producer fix. Both now exist, and the
// census re-derives the population from the stored coordinate rather than from
// a marker — so it still reports anything a future producer sneaks in, whether
// or not this cleanup has ever run. Deleting no longer costs the evidence.
//
// WHAT IS RETAINED, DELIBERATELY. A row with is_malicious = TRUE is never
// deleted, even when its version is unevaluable. The malware verdict is
// derived from the artifact's own bytes, not from a version comparison, so it
// is real information that survives its coordinate being junk — and re-deriving
// it depends on the artifact still being fetchable, which is exactly what is
// least likely for a package that got flagged. Those rows are reported
// separately by UnevaluableCoordinateCounts as Retained, so the operator sees
// that the choice was made rather than discovering a silent exclusion. (In the
// 2026-08-23 production population, Retained is zero.)
//
// Convention note: pgstore has no numbered migration runner (see the TODO at
// the top of migrate.go) and no rollback step anywhere — the same forward-only
// model applies here, which is a second reason this one is not automatic.
//
// Intended use, from a caller that already holds the *pgstore.Store — the
// rule is supplied by core/intelligence (intelligence.UnevaluableCoordinateRule)
// so this package cannot drift from the definition that refuses the same
// coordinates at ingest:
//
//	rule := intelligence.UnevaluableCoordinateRule()
//	counts, err := store.UnevaluableCoordinateCounts(ctx, rule) // dry run
//	// ...operator reads the counts...
//	n, err := store.PurgeUnevaluableCoordinates(ctx, rule)

import (
	"context"
	"fmt"
	"strings"
)

// UnevaluableCoordinateRule carries the predicate parameters this cleanup
// matches on. It is passed IN rather than declared here for the same reason
// RepositoryGuide is: core/intelligence imports pgstore
// (core/intelligence/store.go:14), so pgstore cannot import it back to read
// the constants. Sourcing the values from the ingest gate's own definition is
// what keeps the deleted population identical to the refused one.
//
// All three fields mirror core/intelligence/version_evaluable.go:
// unresolvedPropertyMarker, mavenFamilyEcosystems, mavenNonVersions.
type UnevaluableCoordinateRule struct {
	// UnresolvedPropertyMarker is the substring that identifies an
	// uninterpolated build-tool property — `${`. REQUIRED: an empty value
	// makes the whole rule invalid rather than matching nothing, because
	// Postgres `strpos(version, '')` returns 1 for every row and an empty
	// marker would therefore select the entire table.
	UnresolvedPropertyMarker string

	// MavenFamilyEcosystems are the ecosystem names that resolve to Maven
	// coordinates. Compared case-insensitively against btrim(ecosystem).
	MavenFamilyEcosystems []string

	// MavenNonVersions are the Maven-family version strings that name no
	// concrete release ("metadata", "release", "latest"). Compared
	// case-insensitively against btrim(version), and ONLY within
	// MavenFamilyEcosystems — "latest" is an ordinary docker tag, and an
	// unscoped match would delete real inventory.
	MavenNonVersions []string
}

// normalized returns the rule with every string trimmed and lowercased where
// the SQL compares lowercased, and drops empty entries. An invalid rule
// (missing marker) is reported by err.
func (r UnevaluableCoordinateRule) normalized() (UnevaluableCoordinateRule, error) {
	out := UnevaluableCoordinateRule{
		UnresolvedPropertyMarker: strings.TrimSpace(r.UnresolvedPropertyMarker),
	}
	if out.UnresolvedPropertyMarker == "" {
		// Fail loudly. Defaulting to "${" here would mean a caller that
		// forgot to populate the struct still deleted rows, which is the
		// exact accident this whole file is arranged to prevent.
		return out, fmt.Errorf("pgstore: unevaluable-coordinate rule has no UnresolvedPropertyMarker; " +
			"populate it from intelligence.UnevaluableCoordinateRule()")
	}
	for _, e := range r.MavenFamilyEcosystems {
		if s := strings.ToLower(strings.TrimSpace(e)); s != "" {
			out.MavenFamilyEcosystems = append(out.MavenFamilyEcosystems, s)
		}
	}
	for _, v := range r.MavenNonVersions {
		if s := strings.ToLower(strings.TrimSpace(v)); s != "" {
			out.MavenNonVersions = append(out.MavenNonVersions, s)
		}
	}
	return out, nil
}

// unevaluablePredicate builds the WHERE fragment and its arguments.
//
// Clause by clause — each mirrors one branch of
// intelligence.UnevaluableVersionReason, in the same order:
//
//	version IS NULL OR btrim(version) = ''   → version_empty. NULL is spelled
//	                                           out even though the current DDL
//	                                           declares the column NOT NULL,
//	                                           because older installs predate
//	                                           that and a NULL version is
//	                                           exactly the row to catch.
//	strpos(version, ?) > 0                   → version_unresolved_property.
//	                                           strpos rather than LIKE: no
//	                                           wildcard-escaping question
//	                                           about `$` or `{`.
//	lower(btrim(ecosystem)) IN (…)           → maven_non_version. The
//	  AND lower(btrim(version)) IN (…)         ecosystem test is what keeps a
//	                                           docker tag named "latest" out.
//
// The Maven clause is omitted entirely when either list is empty, so an
// under-populated rule narrows the match instead of widening it.
func (r UnevaluableCoordinateRule) unevaluablePredicate() (string, []any) {
	clauses := []string{
		"version IS NULL",
		"btrim(version) = ''",
		"strpos(version, ?) > 0",
	}
	args := []any{r.UnresolvedPropertyMarker}

	if len(r.MavenFamilyEcosystems) > 0 && len(r.MavenNonVersions) > 0 {
		ecoMarks := make([]string, 0, len(r.MavenFamilyEcosystems))
		for _, e := range r.MavenFamilyEcosystems {
			ecoMarks = append(ecoMarks, "?")
			args = append(args, e)
		}
		verMarks := make([]string, 0, len(r.MavenNonVersions))
		for _, v := range r.MavenNonVersions {
			verMarks = append(verMarks, "?")
			args = append(args, v)
		}
		clauses = append(clauses, fmt.Sprintf(
			"(lower(btrim(ecosystem)) IN (%s) AND lower(btrim(version)) IN (%s))",
			strings.Join(ecoMarks, ", "), strings.Join(verMarks, ", ")))
	}
	return "(" + strings.Join(clauses, " OR ") + ")", args
}

// retainedClause is the exclusion that keeps a malware verdict alive. It is
// spelled the same way in the count and in the delete, so the dry run can
// never enumerate a population the delete does not match.
// COALESCE is belt-and-braces: the column is declared NOT NULL DEFAULT FALSE,
// but under SQL three-valued logic a NULL would make `NOT (is_malicious =
// TRUE)` evaluate to NULL, so such a row would be neither deleted nor counted
// in either bucket — it would silently disappear from the dry run.
const retainedClause = "COALESCE(is_malicious, FALSE) = TRUE"

// UnevaluableCoordinateCount is one ecosystem's bucket of the cleanup
// population: how many rows PurgeUnevaluableCoordinates would remove, and how
// many it would deliberately leave behind.
type UnevaluableCoordinateCount struct {
	Ecosystem string
	// Deletable is the number of unevaluable rows the purge would remove.
	Deletable int
	// Retained is the number of unevaluable rows the purge would KEEP
	// because they carry is_malicious = TRUE. Reported so the retention
	// decision is visible in the dry run rather than silent.
	Retained int
}

// UnevaluableCoordinateCounts is the READ-ONLY dry run. Run it before
// PurgeUnevaluableCoordinates to size the change and to see how many rows the
// purge will deliberately spare.
//
// It shares unevaluablePredicate and retainedClause with the DELETE, so an
// operator cannot count one population and then remove a different one.
//
// Deliberately not org-scoped: intelligence_reports is keyed on the coordinate
// alone and carries no tenant scope, and the operator running this is sizing
// the whole table. Ordered largest bucket first.
//
// A nil store (tests) returns (nil, nil), matching the rest of this package.
func (s *Store) UnevaluableCoordinateCounts(ctx context.Context, rule UnevaluableCoordinateRule) ([]UnevaluableCoordinateCount, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	norm, err := rule.normalized()
	if err != nil {
		return nil, err
	}
	pred, args := norm.unevaluablePredicate()

	query := fmt.Sprintf(`
		SELECT ecosystem,
		       count(*) FILTER (WHERE NOT (%[2]s)) AS deletable,
		       count(*) FILTER (WHERE %[2]s)       AS retained
		  FROM intelligence_reports
		 WHERE %[1]s
		 GROUP BY 1
		 ORDER BY 2 DESC, 1`, pred, retainedClause)

	rows, err := s.ReadDB().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("count unevaluable coordinates: %w", err)
	}
	defer rows.Close()

	var out []UnevaluableCoordinateCount
	for rows.Next() {
		var c UnevaluableCoordinateCount
		if err := rows.Scan(&c.Ecosystem, &c.Deletable, &c.Retained); err != nil {
			return nil, fmt.Errorf("scan unevaluable coordinate count: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate unevaluable coordinate counts: %w", err)
	}
	return out, nil
}

// PurgeUnevaluableCoordinates deletes intelligence_reports rows whose version
// can never be ordered against an advisory range, and returns how many it
// removed. Rows carrying is_malicious = TRUE are retained — see the file
// header.
//
// NOT called at boot, by design. Call it from an operator-triggered path
// after reading UnevaluableCoordinateCounts.
//
// Idempotent by construction rather than by a marker: the second run matches
// nothing because the first run removed everything the predicate selects, so
// it returns 0. That also means it is safe to re-run after a fresh batch of
// bad rows appears — it will remove exactly that batch.
//
// One statement, so atomicity needs no explicit transaction: either every
// matching row goes or none does.
func (s *Store) PurgeUnevaluableCoordinates(ctx context.Context, rule UnevaluableCoordinateRule) (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	norm, err := rule.normalized()
	if err != nil {
		return 0, err
	}
	pred, args := norm.unevaluablePredicate()

	query := fmt.Sprintf(`
		DELETE FROM intelligence_reports
		 WHERE %s
		   AND NOT (%s)`, pred, retainedClause)

	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("purge unevaluable coordinates: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected purging unevaluable coordinates: %w", err)
	}
	return n, nil
}
