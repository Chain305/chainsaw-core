package pgstore

// Opt-in cleanup: remove intelligence_reports rows keyed on the literal
// dist-tag NAME `latest` for the ecosystems where that string is now
// dereferenced to a concrete version before the scan runs (P8-45).
//
// WHY A CLEANUP IS NEEDED AT ALL, AND WHY THE EPOCH BUMP DOES NOT COVER IT.
// The matcher epoch retires a stale row the next time that coordinate is
// REQUESTED — Scan compares Report.Observation.MatcherEpoch against
// CurrentMatcherEpoch on the read path and treats a lower value as a miss.
// That works because the coordinate keeps being asked for. These rows are
// different: after the fix the public intel path resolves `latest` BEFORE
// calling Scan, so `(npm, lodash, "latest")` is never requested again on
// that path and the epoch check is never reached for it. The row is
// immortal by omission.
//
// It is not inert while it sits there. Three readers serve it verbatim:
// the public intelligence endpoint (a direct Get on the coordinate), admin
// inspect, and the inventory Search/Facets, which read the DENORMALIZED
// verdict and trust_score columns. All three render it as
// `NOT EVALUATED / 0 (F)` — the wrong answer for a package that is fine,
// on a coordinate a user typed because it is the most natural thing to
// type. Search additionally SORTS and FILTERS on trust_score, so a
// permanent 0 steers the list.
//
// WHAT IS EXCLUDED, AND WHY EACH EXCLUSION IS LOAD-BEARING.
//
//   - docker (and its `oci` spelling). `latest` is an ORDINARY TAG there.
//     Docker Hub serves a manifest for it, the registry-metadata provider
//     fetches it, and those rows carry a REAL evaluation of real bytes.
//     Deleting them would destroy answers and force a re-fetch of every
//     docker `latest` in the inventory.
//   - the Maven family (maven, gradle, and any alias the ingest gate
//     lists). `LATEST` is a Maven RESOLVER DIRECTIVE, not a version;
//     intelligence.UnevaluableVersionReason routes it to
//     version_not_evaluable and that is the correct, permanent answer. Those
//     rows belong to the sibling cleanup in
//     migrate_unevaluable_coordinates.go, which owns the maven_non_version
//     population and already scopes `latest` to the Maven family for exactly
//     this reason.
//
// Rather than enumerate what to skip, this rule enumerates what to MATCH:
// the ecosystems the resolver actually covers. An allowlist cannot
// accidentally widen — a rule that arrives empty deletes nothing, where a
// denylist that arrives empty deletes everything.
//
// RETAINED, DELIBERATELY: a row with is_malicious = TRUE is never deleted,
// the same rule and the same spelling as the sibling cleanup. A malware
// verdict is derived from the artifact's bytes, not from a version
// comparison, so it survives its coordinate being a moving label — and
// re-deriving it depends on the artifact still being fetchable, which is
// least likely for exactly the package that got flagged.
//
// NOT a boot-time migration, for the reason its neighbour spells out at
// length: this DELETEs, and a slightly-wrong predicate running unattended on
// every pod restart is a worse failure mode than the rows it removes.
//
// Intended use, from a caller holding the *pgstore.Store — the rule comes
// from core/intelligence so it cannot drift from the resolver's own
// definition of which ecosystems are resolvable:
//
//	rule := intelligence.LatestSentinelRule()
//	counts, err := store.LatestSentinelCounts(ctx, rule) // dry run
//	// ...operator reads the counts...
//	n, err := store.PurgeLatestSentinelCoordinates(ctx, rule)

import (
	"context"
	"fmt"
	"strings"
)

// LatestSentinelRule carries the predicate parameters for the cleanup. It
// is passed IN rather than declared here for the same reason
// UnevaluableCoordinateRule is: core/intelligence imports pgstore, so
// pgstore cannot import it back.
type LatestSentinelRule struct {
	// Sentinel is the literal version string to match, compared
	// case-insensitively against btrim(version). REQUIRED: an empty value
	// invalidates the whole rule rather than matching nothing, because a
	// blank sentinel would select every row whose version is blank — a
	// population this cleanup has no business touching.
	Sentinel string

	// Ecosystems is the ALLOWLIST of ecosystem names whose `latest` rows
	// may be removed: exactly the set the resolver can dereference.
	// Compared case-insensitively against btrim(ecosystem). An empty list
	// makes the rule match nothing, which is the safe direction.
	Ecosystems []string
}

func (r LatestSentinelRule) normalized() (LatestSentinelRule, error) {
	out := LatestSentinelRule{Sentinel: strings.ToLower(strings.TrimSpace(r.Sentinel))}
	if out.Sentinel == "" {
		return out, fmt.Errorf("pgstore: latest-sentinel rule has no Sentinel; " +
			"populate it from intelligence.LatestSentinelRule()")
	}
	for _, e := range r.Ecosystems {
		if s := strings.ToLower(strings.TrimSpace(e)); s != "" {
			out.Ecosystems = append(out.Ecosystems, s)
		}
	}
	return out, nil
}

// latestSentinelPredicate builds the WHERE fragment and its arguments.
//
// Both halves are conjunctive and both are required. The ecosystem
// allowlist is what keeps a docker tag named `latest` and a Maven `LATEST`
// directive out of the match; an empty allowlist yields `FALSE`, so an
// under-populated rule deletes nothing.
func (r LatestSentinelRule) latestSentinelPredicate() (string, []any) {
	if len(r.Ecosystems) == 0 {
		return "FALSE", nil
	}
	marks := make([]string, 0, len(r.Ecosystems))
	args := make([]any, 0, len(r.Ecosystems)+1)
	for _, e := range r.Ecosystems {
		marks = append(marks, "?")
		args = append(args, e)
	}
	args = append(args, r.Sentinel)
	return fmt.Sprintf(
		"(lower(btrim(ecosystem)) IN (%s) AND lower(btrim(version)) = ?)",
		strings.Join(marks, ", ")), args
}

// LatestSentinelCount is one ecosystem's bucket of the cleanup population.
type LatestSentinelCount struct {
	Ecosystem string
	// Deletable is the number of `latest` rows the purge would remove.
	Deletable int
	// Retained is the number it would KEEP because they carry
	// is_malicious = TRUE. Reported so the retention is visible in the
	// dry run rather than silent.
	Retained int
}

// LatestSentinelCounts is the READ-ONLY dry run. It shares the predicate
// and the retained clause with the DELETE, so an operator cannot count one
// population and remove a different one.
//
// Deliberately not org-scoped: intelligence_reports is keyed on the
// coordinate alone and carries no tenant scope (see L-02,
// docs/plan_intel_cache_tenancy.md). Ordered largest bucket first.
func (s *Store) LatestSentinelCounts(ctx context.Context, rule LatestSentinelRule) ([]LatestSentinelCount, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}
	norm, err := rule.normalized()
	if err != nil {
		return nil, err
	}
	pred, args := norm.latestSentinelPredicate()

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
		return nil, fmt.Errorf("count latest-sentinel coordinates: %w", err)
	}
	defer rows.Close()

	var out []LatestSentinelCount
	for rows.Next() {
		var c LatestSentinelCount
		if err := rows.Scan(&c.Ecosystem, &c.Deletable, &c.Retained); err != nil {
			return nil, fmt.Errorf("scan latest-sentinel count: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate latest-sentinel counts: %w", err)
	}
	return out, nil
}

// PurgeLatestSentinelCoordinates deletes the `latest`-keyed rows in the
// allowlisted ecosystems and returns how many it removed. Rows carrying
// is_malicious = TRUE are retained — see the file header.
//
// NOT called at boot, by design. Call it from an operator-triggered path
// after reading LatestSentinelCounts.
//
// Idempotent by construction rather than by a marker: after the fix the
// resolver runs before Scan, so no NEW `latest` row is written for an
// allowlisted ecosystem on the public intel path, and a second run matches
// nothing. One statement, so atomicity needs no explicit transaction.
func (s *Store) PurgeLatestSentinelCoordinates(ctx context.Context, rule LatestSentinelRule) (int64, error) {
	if s == nil || s.db == nil {
		return 0, nil
	}
	norm, err := rule.normalized()
	if err != nil {
		return 0, err
	}
	pred, args := norm.latestSentinelPredicate()

	query := fmt.Sprintf(`
		DELETE FROM intelligence_reports
		 WHERE %s
		   AND NOT (%s)`, pred, retainedClause)

	res, err := s.db.ExecContext(ctx, query, args...)
	if err != nil {
		return 0, fmt.Errorf("purge latest-sentinel coordinates: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("rows affected purging latest-sentinel coordinates: %w", err)
	}
	return n, nil
}
