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
	"regexp"
	"strings"
	"time"
	"unicode"

	"golang.org/x/mod/module"

	"github.com/chain305/chainsaw-core/intelligence/osv"
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

// WarnCoordinateMalformed is the sibling of WarnVersionNotEvaluable for the
// NAME half of a coordinate: the package string is one no registry in that
// ecosystem can serve, so the row was recorded but NOT evaluated.
//
// Stamped by markMalformedCoordinate at the same two sites as its sibling
// (runFanout and Store.Upsert) with provider "coordinate", consumed by
// risk_projection.go as an unavailability arm (VerdictUnknown → Monitored),
// and classified not_applicable in core/coverage/status.go — it is a fact
// about the coordinate, not about any source, so it can never trip the
// opt-in fail-closed gate on its own.
//
// Why it exists (Phase 9 fresh QA, P9F-063): `intel package npm
// "<script>alert(1)</script>" 1.0.0` scored ALLOW 96 (A). registry.npmjs.org
// answers 405 for that name, provider_registrymetadata.go maps only 404 to
// not_found, so the http_405 warning was never read as "package absent" and
// the report was scored on an empty fact set. Names the registry 404s
// (`.hidden`, `a..b`) already reach package_not_found; the URL-unsafe class
// was the one still scored. The gate closes it without a registry call.
const WarnCoordinateMalformed = "coordinate_malformed"

// pypiNameRE is PEP 508's name grammar, applied to the RAW name — before
// A4's canonicalisation — so a non-canonical but legal spelling
// (`Django`, `typing_extensions`, `zope.interface`) passes.
var pypiNameRE = regexp.MustCompile(`(?i)^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// MalformedCoordinateReason reports WHY a package name can never be served
// by its ecosystem's registry, or "" when the name is syntactically
// possible. It is the name-side sibling of UnevaluableVersionReason and is
// held to the same discipline: each rule is the ecosystem's OWN grammar,
// not a tightening of it, so nothing a registry serves is rejected.
//
//	go / gomod     — golang.org/x/mod/module.CheckPath, the rule `go` itself
//	                 applies to a `require` line. Proxy keys pass by
//	                 construction: the gomod resolver decodes the `!x`
//	                 case escaping before building the coordinate, and
//	                 TestProxyResolverKeysAreNeverMalformed pins it.
//	maven / gradle — an empty or whitespace-only colon segment, or a
//	                 character outside Maven's own ID grammar
//	                 ([A-Za-z0-9_.-], DefaultModelValidator's ID_REGEX) in
//	                 the group or artifact. NO segment-count rule:
//	                 g:a:packaging:classifier:version is a valid five-part
//	                 form that splitMavenCoordinate scores today.
//	npm / yarn / bun — validate-npm-package-name's OLD-package rules, the
//	                 ones the registry applies to names that already exist:
//	                 non-empty, no surrounding or embedded whitespace, no
//	                 leading `.` or `_`, no `..`, not node_modules or
//	                 favicon.ico, and URL-friendly (encodeURIComponent(name)
//	                 == name) apart from the single `/` of an optional
//	                 `@scope/`. Uppercase is PERMITTED — the new-package
//	                 lowercase rule would flip every legacy mixed-case name
//	                 such as JSONStream — and there is no 214-char cap, which
//	                 is new-package-only.
//	pypi / pip     — PEP 508's name grammar on the raw name.
//	anything else  — "" (no rule). A new ecosystem cannot be gated by
//	                 accident.
//
// The returned text is operator-facing and lands in the warning message.
func MalformedCoordinateReason(ecosystem, pkg string) string {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	if isMavenFamily(eco) {
		return malformedMavenCoordinate(pkg)
	}
	switch osv.CanonicalEcosystem(eco) {
	case "go":
		return malformedGoModulePath(pkg)
	case "npm":
		return malformedNPMName(pkg)
	case "pypi":
		return malformedPyPIName(pkg)
	}
	return ""
}

func malformedGoModulePath(pkg string) string {
	if err := module.CheckPath(pkg); err != nil {
		return err.Error()
	}
	return ""
}

// mavenIDChar is Maven's own ID grammar for groupId and artifactId.
func mavenIDChar(r rune) bool {
	return r == '_' || r == '.' || r == '-' ||
		('0' <= r && r <= '9') || ('a' <= r && r <= 'z') || ('A' <= r && r <= 'Z')
}

func malformedMavenCoordinate(pkg string) string {
	segs := strings.Split(pkg, ":")
	for i, s := range segs {
		if strings.TrimSpace(s) == "" {
			return fmt.Sprintf("maven coordinate %q: segment %d is empty", pkg, i+1)
		}
	}
	// Group and artifact only. Packaging, classifier and version, when
	// present, are shape questions for splitMavenCoordinate.
	names := []string{"groupId", "artifactId"}
	for i := 0; i < len(segs) && i < len(names); i++ {
		for _, r := range segs[i] {
			if !mavenIDChar(r) {
				return fmt.Sprintf("maven coordinate %q: invalid char %q in %s", pkg, r, names[i])
			}
		}
	}
	return ""
}

// npmURLFriendly mirrors encodeURIComponent's unreserved set — the exact
// test validate-npm-package-name applies (`encodeURIComponent(name) !==
// name` is an error). Note this is NOT url.PathEscape: Go's path escaping
// leaves `$&+:=@` alone and escapes `!'()*`, which is backwards from
// npm's rule in both directions, and `!'()*` appear in legacy served names.
func npmURLFriendly(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == '-', c == '_', c == '.', c == '!', c == '~', c == '*', c == '\'', c == '(', c == ')':
		default:
			return false
		}
	}
	return true
}

func malformedNPMName(name string) string {
	if name == "" {
		return "npm name is empty"
	}
	if strings.TrimSpace(name) != name {
		return fmt.Sprintf("npm name %q has leading or trailing whitespace", name)
	}
	for _, r := range name {
		if unicode.IsSpace(r) {
			return fmt.Sprintf("npm name %q contains whitespace", name)
		}
	}
	if strings.Contains(name, "..") {
		return fmt.Sprintf("npm name %q contains \"..\"", name)
	}
	switch strings.ToLower(name) {
	case "node_modules", "favicon.ico":
		return fmt.Sprintf("npm name %q is reserved", name)
	}
	bare := name
	if strings.HasPrefix(name, "@") {
		i := strings.IndexByte(name, '/')
		if i < 0 {
			return fmt.Sprintf("npm name %q: scope without a package", name)
		}
		scope := name[1:i]
		if scope == "" {
			return fmt.Sprintf("npm name %q: empty scope", name)
		}
		if !npmURLFriendly(scope) {
			return fmt.Sprintf("npm name %q: scope is not URL-friendly", name)
		}
		bare = name[i+1:]
	}
	if bare == "" {
		return fmt.Sprintf("npm name %q: empty package name", name)
	}
	if bare[0] == '.' {
		return fmt.Sprintf("npm name %q: package name starts with a period", name)
	}
	if bare[0] == '_' {
		return fmt.Sprintf("npm name %q: package name starts with an underscore", name)
	}
	if !npmURLFriendly(bare) {
		return fmt.Sprintf("npm name %q: package name is not URL-friendly", name)
	}
	return ""
}

func malformedPyPIName(name string) string {
	if !pypiNameRE.MatchString(name) {
		return fmt.Sprintf("pypi name %q does not match the PEP 508 name grammar", name)
	}
	return ""
}

// markMalformedCoordinate stamps WarnCoordinateMalformed on a Report whose
// package name no registry can serve, and reports whether it did. Same
// store-with-a-marker doctrine, same two call sites, same idempotency as
// markUnevaluableVersion above — read that comment; nothing here is
// different except which half of the coordinate is being judged.
//
// A coordinate can carry both stamps (`:x` at `${v}`); neither hides the
// other, and the projection reads either as NOT EVALUATED.
func markMalformedCoordinate(r *Report, at time.Time) bool {
	if r == nil {
		return false
	}
	reason := MalformedCoordinateReason(r.Identity.Ecosystem, r.Identity.Package)
	if reason == "" {
		return false
	}
	for _, w := range r.Observation.Warnings {
		if w.Code == WarnCoordinateMalformed {
			return true
		}
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	r.Observation.Warnings = append(r.Observation.Warnings, Warning{
		Provider: unevaluableVersionWarningProvider,
		Code:     WarnCoordinateMalformed,
		Message: fmt.Sprintf(
			"%s; no registry can serve this name, so the coordinate is recorded but NOT evaluated",
			reason),
		At: at,
	})
	return true
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
// READ-ONLY, AND THAT IS THE WHOLE POINT — this function does not mutate,
// and it is the thing to run first. Size the population, find the producer,
// then decide. Modelled on pgstore.StaleRepositoryGuideCounts, which took
// the same count-before-you-mutate shape.
//
// A cleanup now exists as a SEPARATE, opt-in call —
// Store.PurgeUnevaluableCoordinates (version_evaluable_cleanup.go, backed by
// core/pgstore/migrate_unevaluable_coordinates.go). It was withheld while the
// rows were the only evidence that a producer was emitting uninterpolated
// manifests. That objection has been answered: the producer is fixed
// (resolveMavenVersion interpolates same-document POM properties), the ingest
// gate marks anything that still gets through, and THIS query re-derives its
// population from the stored coordinate rather than from a marker — so a
// future producer's rows show up here whether or not the cleanup has ever
// run. Deleting no longer costs the evidence. It is still opt-in, still not
// wired into boot, and still to be run only after reading this count.
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
