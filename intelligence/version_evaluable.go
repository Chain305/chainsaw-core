package intelligence

// version_evaluable.go is the ingest choke point for coordinates whose
// `version` component can never be ordered against an advisory bound.
//
// THE PROBLEM, measured against production on 2026-08-23.
// intelligence_reports holds rows like these:
//
//	gradle | com.google.code.findbugs:jsr305  | ${jsr305.version}
//	maven  | org.apache.commons:commons-lang3 | ${commons.lang3.version}
//	maven  | (various)                        | ${slf4jVersion}
//	maven  | com.t_est.upload:t-est-maven-…   | metadata
//	gradle | (various)                        | metadata
//
// None of these names a point on a version line. `${…}` is an unresolved
// Maven/Gradle property that the build tool never substituted, and
// `metadata` is a synthetic marker the upload path stamps on
// maven-metadata.xml (internal/server/upload_parsers.go) so the file
// gets a coordinate at all.
//
// Why that matters more than "a junk row". The row is not inert — it is a
// SILENT BLIND SPOT. It appears in the inventory, it carries a
// collected_at, warning_count 0 and is_malicious false, and every surface
// that lists it reads it as *scanned and clean*. No advisory can ever
// attach to it, because no advisory range can be ordered against it, so
// it will report clean forever regardless of what the package actually
// ships. An operator counting coverage counts it as covered.
//
// Until 2026-08-23 it was worse than a blind spot: osv.compareVersions
// handed these strings to the Maven parser, which reads a non-numeric
// lead as a *qualifier* and sorts it BELOW every numeric version, so
// `${slf4jVersion}` was silently ordered against real advisory bounds and
// produced confident, wrong answers. requireNumericLead
// (core/intelligence/osv/bundle.go) now refuses them as undecidable, so
// matching is no longer corrupted. This file closes the other half: the
// data should not be ingested as if it were evaluable in the first place.
//
// This is deliberately the CHOKE POINT rather than a fix at the producer.
// The `metadata` marker has an owner and is being fixed there; `${…}`
// arrives from lockfile parsers, SBOM uploads, the CLI, and the proxy hot
// path. Any of them can reintroduce the class. Refusing it once, where a
// Report becomes a persisted row, is the only placement a future producer
// cannot route around.

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Reason codes attached to WarnVersionNotEvaluable, and mirrored by the
// CASE expression in unevaluableVersionCountSQL. Stable strings — a UI or
// an operator report may key on them.
const (
	// UnevaluableVersionEmpty — the version component is absent or is
	// whitespace only. Nothing to evaluate, in any ecosystem.
	UnevaluableVersionEmpty = "version_empty"

	// UnevaluableVersionUnresolvedProperty — the version still contains a
	// `${…}` build-tool property placeholder. Universally invalid: no
	// ecosystem in the tree permits `$` or `{` in a published version
	// string, so this can only ever be a manifest the build tool did not
	// interpolate. Detected by the `${` substring rather than a full
	// `${…}` shape so a truncated placeholder is caught too.
	UnevaluableVersionUnresolvedProperty = "version_unresolved_property"

	// UnevaluableVersionMavenNonVersion — a Maven-family coordinate whose
	// version names no concrete release: our own synthetic `metadata`
	// marker for maven-metadata.xml uploads, or Maven's built-in
	// meta-versions RELEASE and LATEST, which are resolver directives
	// rather than versions. osv.compareVersions already refuses all three
	// as undecidable; storing them is what creates the blind spot.
	UnevaluableVersionMavenNonVersion = "maven_non_version"
)

// unresolvedPropertyMarker is the substring that identifies an
// uninterpolated build-tool property. Maven, Gradle and Ant all spell it
// `${name}`.
const unresolvedPropertyMarker = "${"

// mavenFamilyEcosystems are the caller-facing ecosystem names that resolve
// to Maven coordinates, i.e. the ones osv.CanonicalEcosystem maps to
// "maven". The list is declared once and drives BOTH the Go predicate and
// the SQL IN-list in unevaluableVersionCountSQL, so the operator's count
// can never enumerate a different population than the ingest gate refuses.
//
// TestMavenFamilyMatchesOSVCanonicalEcosystem pins it against
// osv.CanonicalEcosystem so a future alias (sbt, say) cannot be added
// there and silently bypass this rule.
var mavenFamilyEcosystems = []string{"maven", "gradle", "maven-hosted"}

// "maven-hosted" is a REPOSITORY NAME, not an ecosystem — older code wrote
// repo.Name where repo.Format belongs, leaving 5 such rows in production on
// 2026-08-23 (two carrying the synthetic "metadata" marker). The fingerprint
// is that the same probe packages appear under BOTH "maven" and
// "maven-hosted". Both upload paths now write repo.Format
// (intelligence_upload_trigger.go, intelligence_publish_prerun.go), so it
// cannot recur; TestRepositoryNamesAreNotEcosystems guards that.
//
// It is listed HERE, and deliberately NOT taught to osv.CanonicalEcosystem,
// because the two answer different questions. This gate asks "does this
// version string name a concrete release?" — worth answering for the
// historical rows so they stop reading as scanned-and-clean. The
// canonicaliser asks "does OSV cover this ecosystem?", and answering yes for
// a repo-name leak would make the leak look supported instead of failing
// loudly.

// mavenNonVersions are the Maven-family version strings that name no
// concrete release. Compared case-insensitively against the trimmed
// version.
//
// "metadata" is OURS — internal/server/upload_parsers.go stamps it on a
// maven-metadata.xml upload. The other two are Maven's own: RELEASE and
// LATEST are resolver directives that the resolver replaces with a real
// version before anything is published.
//
// Scoped to the Maven family on purpose. "latest" is a perfectly ordinary
// docker tag, and refusing it globally would delete real inventory.
var mavenNonVersions = []string{"metadata", "release", "latest"}

// UnevaluableVersionReason reports WHY a coordinate's version can never be
// ordered against an advisory range, or "" when the version is evaluable.
//
// THE RULE IS DELIBERATELY SURGICAL, AND THIS IS THE PART TO NOT "IMPROVE".
// The tempting generalisation — refuse anything that does not parse as a
// version, or anything that does not begin with a digit — would be a
// catastrophe here, not a tightening. 76 of the 80 docker rows in
// production carry a `sha256-…` digest as their version, because that is
// what a docker content-addressed tag IS. A numeric-lead rule refuses
// every one of them and switches docker scanning off wholesale. Go's
// canonical versions are `v`-prefixed. Maven ships `1.0-SNAPSHOT` and
// `1.0.0.RELEASE`. Composer ships `swiftmailer-6.2.5`. All of those are
// real, published, resolvable coordinates that we want in the inventory
// even when a particular matcher cannot order them — an unorderable
// version is handled downstream as UNDECIDABLE (which never vetoes a real
// advisory); an unevaluable *coordinate* is a different thing, and only
// the three classes below qualify.
//
// Each class earns its place by being impossible rather than merely hard:
//
//	version_empty                — names nothing at all.
//	version_unresolved_property  — contains `${`, a character sequence no
//	                               registry in any supported ecosystem
//	                               accepts in a published version. Its
//	                               presence proves the manifest was read
//	                               before interpolation.
//	maven_non_version            — a Maven-family string that the Maven
//	                               resolver itself treats as a directive
//	                               or that we minted synthetically. Scoped
//	                               to the Maven family so no other
//	                               ecosystem's legitimate tags are caught.
//
// Anything not in that list is accepted, including versions this codebase
// cannot currently parse. "We cannot order it today" is a matcher
// property and may change; "it is not a version" is a property of the
// string.
func UnevaluableVersionReason(ecosystem, version string) string {
	v := strings.TrimSpace(version)
	if v == "" {
		return UnevaluableVersionEmpty
	}
	if strings.Contains(v, unresolvedPropertyMarker) {
		return UnevaluableVersionUnresolvedProperty
	}
	if isMavenFamily(ecosystem) {
		lower := strings.ToLower(v)
		for _, bad := range mavenNonVersions {
			if lower == bad {
				return UnevaluableVersionMavenNonVersion
			}
		}
	}
	return ""
}

// EvaluableVersion answers "is this coordinate's version evaluable?" — the
// predicate form of UnevaluableVersionReason. True means an advisory range
// could, in principle, be ordered against this version; it says nothing
// about whether any advisory actually matches.
func EvaluableVersion(ecosystem, version string) bool {
	return UnevaluableVersionReason(ecosystem, version) == ""
}

// isMavenFamily reports whether the caller-facing ecosystem name resolves
// to Maven coordinates.
func isMavenFamily(ecosystem string) bool {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	for _, m := range mavenFamilyEcosystems {
		if eco == m {
			return true
		}
	}
	return false
}

// unevaluableVersionWarningProvider is the Warning.Provider value used for
// the ingest-gate stamp. It is not a real provider — the finding is about
// the coordinate itself, before any provider is consulted — so it is named
// for what it describes rather than for a fan-out participant.
const unevaluableVersionWarningProvider = "coordinate"

// markUnevaluableVersion stamps WarnVersionNotEvaluable on a Report whose
// coordinate cannot be evaluated, and reports whether it did.
//
// STORE-WITH-A-MARKER, NOT REFUSE. The choice was between rejecting the
// scan (ErrInvalidKey, nothing persisted) and persisting a row that says
// out loud that it was not evaluated. This takes the second, for three
// reasons:
//
//  1. Refusal is invisible to the operator. The rows already in the table
//     are the actual problem, and a caller who gets an error writes a log
//     line nobody reads. A marked row is queryable — see
//     Store.UnevaluableVersionCounts — so the blind spot can be sized and
//     then fixed at its producer.
//  2. Refusal invites a retry loop. The proxy hot path, the refresher and
//     the dependency enqueuer all re-request a coordinate they failed to
//     get. A permanent error on a coordinate that will never become valid
//     is an infinite retry with an upstream fetch attached to each turn.
//     Persisting terminates the loop honestly: the next Scan reads the
//     cached row and stops.
//  3. The coordinate is real even when the version is not. `commons-lang3`
//     with an uninterpolated version is still a dependency someone
//     declared. Dropping it removes the evidence that a manifest was
//     ingested unresolved; keeping it, marked, is what lets somebody go
//     fix the manifest.
//
// What the marker buys (requirement: it must not read as scanned-and-clean).
// The stamp is a Warning, which is persisted inside the report JSONB AND
// denormalised into intelligence_reports.warning_count, so both the API
// (Observation.Warnings[].Code) and a SQL-level consumer can branch on it
// without decoding the blob. core/coverage classifies the code as
// not_applicable — no advisory source applies to a non-version — so it can
// never trip the opt-in fail-closed gate on its own.
//
// Idempotent: a Report that already carries the code is left alone, so
// re-marking on the Upsert path after the Scan path has already marked it
// does not accumulate duplicates across refresh ticks.
func markUnevaluableVersion(r *Report, at time.Time) bool {
	if r == nil {
		return false
	}
	reason := UnevaluableVersionReason(r.Identity.Ecosystem, r.Identity.Version)
	if reason == "" {
		return false
	}
	for _, w := range r.Observation.Warnings {
		if w.Code == WarnVersionNotEvaluable {
			return true
		}
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	r.Observation.Warnings = append(r.Observation.Warnings, Warning{
		Provider: unevaluableVersionWarningProvider,
		Code:     WarnVersionNotEvaluable,
		Message: fmt.Sprintf(
			"%s: version %q cannot be ordered against any advisory range; "+
				"this coordinate is recorded but NOT evaluated",
			reason, strings.TrimSpace(r.Identity.Version)),
		At: at,
	})
	return true
}

// UnevaluableVersionCount is one (ecosystem, reason) bucket of existing
// rows the ingest gate would now mark. Reason is one of the
// UnevaluableVersion* constants.
type UnevaluableVersionCount struct {
	Ecosystem string
	Reason    string
	Count     int
}

// sqlStringList renders a Go string slice as a SQL IN-list literal.
// Inputs are package-level constants, never user data; the quote doubling
// is belt-and-braces so this can never become an injection seam if the
// lists ever move to configuration.
func sqlStringList(vals []string) string {
	quoted := make([]string, 0, len(vals))
	for _, v := range vals {
		quoted = append(quoted, "'"+strings.ReplaceAll(v, "'", "''")+"'")
	}
	return strings.Join(quoted, ", ")
}

// unevaluableVersionCountSQL is the READ-ONLY dry run for the population
// this file's predicate refuses. It is built from the SAME lists the Go
// predicate walks (mavenFamilyEcosystems, mavenNonVersions) and labels
// each bucket with the SAME reason constants, so an operator cannot
// enumerate one population here and act on a different one.
//
// Predicate, clause by clause — each mirrors one branch of
// UnevaluableVersionReason, in the same order, so the CASE and the WHERE
// stay consistent:
//
//	version IS NULL OR btrim(version) = ''   → UnevaluableVersionEmpty.
//	                                           NULL is spelled out even
//	                                           though btrim(NULL) = '' is
//	                                           NULL and would be excluded
//	                                           by three-valued logic — a
//	                                           NULL version is exactly the
//	                                           row an operator most needs
//	                                           to see.
//	strpos(version, '${') > 0                → UnevaluableVersionUnresolved-
//	                                           Property. strpos rather than
//	                                           LIKE: no wildcard-escaping
//	                                           question about `$` or `{`.
//	lower(btrim(ecosystem)) IN (…)           → the Maven-family scope. The
//	  AND lower(btrim(version)) IN (…)         ecosystem test is what keeps
//	                                           a docker tag named "latest"
//	                                           out of the result.
//
// The CASE arms are ordered to match: a row that is BOTH `${…}` and in a
// Maven ecosystem is reported as unresolved_property, which is the more
// actionable of the two (it names a manifest to go fix).
//
// Deliberately NOT filtered by org: intelligence_reports is keyed on the
// coordinate alone and carries no tenant scope worth narrowing by here, and
// the operator running this is sizing the whole table.
var unevaluableVersionCountSQL = fmt.Sprintf(`
	SELECT ecosystem,
	       CASE
	         WHEN version IS NULL OR btrim(version) = '' THEN '%s'
	         WHEN strpos(version, '%s') > 0              THEN '%s'
	         ELSE '%s'
	       END AS reason,
	       count(*) AS n
	  FROM intelligence_reports
	 WHERE version IS NULL
	    OR btrim(version) = ''
	    OR strpos(version, '%s') > 0
	    OR (lower(btrim(ecosystem)) IN (%s)
	        AND lower(btrim(version)) IN (%s))
	 GROUP BY 1, 2
	 ORDER BY n DESC, 1, 2`,
	UnevaluableVersionEmpty,
	unresolvedPropertyMarker, UnevaluableVersionUnresolvedProperty,
	UnevaluableVersionMavenNonVersion,
	unresolvedPropertyMarker,
	sqlStringList(mavenFamilyEcosystems),
	sqlStringList(mavenNonVersions),
)

// UnevaluableVersionCounts reports how many rows already in
// intelligence_reports carry a version the ingest gate now refuses,
// bucketed by (ecosystem, reason) and ordered largest bucket first.
//
// READ-ONLY, AND THAT IS THE WHOLE POINT. There is deliberately no
// companion cleanup here. A DELETE would destroy the only evidence that a
// producer is emitting uninterpolated manifests, and the rows are not
// dangerous in themselves once they are marked — they are misleading, and
// the marker is what fixes the misleading part. Size the population first,
// find the producer, then decide. Modelled on
// pgstore.StaleRepositoryGuideCounts, which took the same
// count-before-you-mutate shape.
//
// Note the asymmetry with the ingest gate: rows written BEFORE this change
// carry no WarnVersionNotEvaluable stamp, so this query re-derives the
// predicate from the stored coordinate rather than looking for the marker.
// That is intentional — it makes the count valid for both the historical
// backlog and anything a future producer sneaks in around the marker.
//
// A nil store (tests) returns (nil, nil), matching every other method here.
func (s *Store) UnevaluableVersionCounts(ctx context.Context) ([]UnevaluableVersionCount, error) {
	if s == nil || s.sql == nil || s.sql.ReadDB() == nil {
		return nil, nil
	}
	rows, err := s.sql.ReadDB().QueryContext(ctx, unevaluableVersionCountSQL)
	if err != nil {
		return nil, fmt.Errorf("intelligence: count unevaluable versions: %w", err)
	}
	defer rows.Close()

	var out []UnevaluableVersionCount
	for rows.Next() {
		var c UnevaluableVersionCount
		if err := rows.Scan(&c.Ecosystem, &c.Reason, &c.Count); err != nil {
			return nil, fmt.Errorf("intelligence: scan unevaluable version count: %w", err)
		}
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("intelligence: iterate unevaluable version counts: %w", err)
	}
	return out, nil
}
