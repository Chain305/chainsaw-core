package intelligence

// Tests for the unevaluable-coordinate ingest gate.
//
// The refusal cases use the ACTUAL production strings observed in
// intelligence_reports on 2026-08-23. The acceptance cases are the more
// important half: this rule is only correct if it is surgical, and the
// docker `sha256-…` case in particular is how we prove a future
// "just refuse non-numeric versions" tightening would be caught here
// rather than in production, where it would switch docker scanning off.

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/coverage"
	"github.com/chain305/chainsaw-core/intelligence/osv"
	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/risk"
)

func TestUnevaluableVersionReason_RefusesProductionStrings(t *testing.T) {
	cases := []struct {
		name      string
		ecosystem string
		version   string
		want      string
	}{
		// Verbatim production rows.
		{"gradle jsr305 property", "gradle", "${jsr305.version}", UnevaluableVersionUnresolvedProperty},
		{"maven commons-lang3 property", "maven", "${commons.lang3.version}", UnevaluableVersionUnresolvedProperty},
		{"maven slf4j property", "maven", "${slf4jVersion}", UnevaluableVersionUnresolvedProperty},
		{"maven synthetic metadata marker", "maven", "metadata", UnevaluableVersionMavenNonVersion},
		{"gradle synthetic metadata marker", "gradle", "metadata", UnevaluableVersionMavenNonVersion},

		// `${` is universally invalid, so it is refused regardless of
		// ecosystem — a property placeholder is not a Maven-only failure.
		{"npm property leaks too", "npm", "${project.version}", UnevaluableVersionUnresolvedProperty},
		{"truncated placeholder", "maven", "${unterminated", UnevaluableVersionUnresolvedProperty},

		// Empty / whitespace.
		{"empty", "maven", "", UnevaluableVersionEmpty},
		{"whitespace only", "npm", "   ", UnevaluableVersionEmpty},

		// Maven's own meta-versions, case-insensitively.
		{"maven RELEASE", "maven", "RELEASE", UnevaluableVersionMavenNonVersion},
		{"maven LATEST", "maven", "LATEST", UnevaluableVersionMavenNonVersion},
		{"maven lowercase latest", "maven", "latest", UnevaluableVersionMavenNonVersion},
		{"ecosystem case and padding are normalised", "  Gradle ", " Metadata ", UnevaluableVersionMavenNonVersion},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := UnevaluableVersionReason(tc.ecosystem, tc.version)
			if got != tc.want {
				t.Fatalf("UnevaluableVersionReason(%q, %q) = %q, want %q",
					tc.ecosystem, tc.version, got, tc.want)
			}
			if EvaluableVersion(tc.ecosystem, tc.version) {
				t.Fatalf("EvaluableVersion(%q, %q) = true, want false",
					tc.ecosystem, tc.version)
			}
		})
	}
}

// TestUnevaluableVersionReason_AcceptsRealCoordinates is the negative test
// that proves the rule is surgical. Every string here is a version we
// legitimately store today; refusing any of them would delete real
// inventory rather than a blind spot.
//
// The docker rows are the load-bearing case: 76 of the 80 docker rows in
// production carry a `sha256-…` digest as their version. A rule phrased as
// "refuse versions that do not start with a digit" or "refuse versions
// that do not parse as semver" fails here, which is the point.
func TestUnevaluableVersionReason_AcceptsRealCoordinates(t *testing.T) {
	cases := []struct {
		name      string
		ecosystem string
		version   string
	}{
		{"plain semver", "npm", "4.17.21"},
		{"maven snapshot", "maven", "1.0-SNAPSHOT"},
		{"docker digest tag", "docker", "sha256-0104b33ec1a1a1b0e2f6f0a1c4e9a4f1b3d5c7e9a1b3d5c7e9a1b3d5c7e9a1b3"},
		{"docker digest tag, truncated real prefix", "docker", "sha256-0104b33"},

		// "latest" is an ordinary docker tag. The Maven scoping is the
		// only thing keeping it out of the refusal set.
		{"docker latest tag", "docker", "latest"},
		{"docker release tag", "docker", "release"},
		{"npm package named metadata version", "npm", "metadata"},

		{"go v-prefixed", "gomod", "v1.9.0"},
		{"maven qualifier release", "maven", "1.0.0.RELEASE"},
		{"maven RELEASE as a suffix, not the whole version", "maven", "5.3.20.RELEASE"},
		{"composer package-prefixed tag", "composer", "swiftmailer-6.2.5"},
		{"pypi epoch", "pypi", "1!2.0.0"},
		{"nuget four-segment", "nuget", "4.5.0.1"},
		{"npm prerelease with build metadata", "npm", "1.2.3-alpha+build.4"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if reason := UnevaluableVersionReason(tc.ecosystem, tc.version); reason != "" {
				t.Fatalf("UnevaluableVersionReason(%q, %q) = %q, want \"\" (accepted) — "+
					"the rule has stopped being surgical",
					tc.ecosystem, tc.version, reason)
			}
			if !EvaluableVersion(tc.ecosystem, tc.version) {
				t.Fatalf("EvaluableVersion(%q, %q) = false, want true",
					tc.ecosystem, tc.version)
			}
		})
	}
}

// TestMavenFamilyMatchesOSVCanonicalEcosystem pins the Maven-family scope
// against the canonicaliser it is derived from. If a future alias is added
// to osv.CanonicalEcosystem's maven branch, this fails and the alias has to
// be added here too — otherwise `metadata` under that alias would sail
// straight through the gate.
func TestMavenFamilyMatchesOSVCanonicalEcosystem(t *testing.T) {
	// Entries that osv.CanonicalEcosystem does NOT map to "maven" are
	// allowed only if they are listed here as a known deployment-local
	// repository-format alias, with a reason. Everything else must
	// canonicalise, so a typo cannot quietly widen the gate.
	knownNonCanonicalAliases := map[string]string{
		"maven-hosted": "repository-format alias for internally-hosted Maven repos; " +
			"present in intelligence_reports.ecosystem but unknown to the canonicaliser",
	}
	for _, eco := range mavenFamilyEcosystems {
		got := osv.CanonicalEcosystem(eco)
		if got == "maven" {
			continue
		}
		if _, known := knownNonCanonicalAliases[eco]; known {
			continue
		}
		t.Errorf("mavenFamilyEcosystems contains %q but osv.CanonicalEcosystem(%q) = %q, want \"maven\" "+
			"(or an entry in knownNonCanonicalAliases explaining why not)", eco, eco, got)
	}
	// The reverse direction, for the aliases we know about. A new alias
	// added to the maven branch upstream must be added to
	// mavenFamilyEcosystems as well.
	for _, eco := range []string{"maven", "gradle"} {
		if osv.CanonicalEcosystem(eco) == "maven" && !isMavenFamily(eco) {
			t.Errorf("%q canonicalises to maven but isMavenFamily(%q) = false", eco, eco)
		}
	}
}

// TestMarkUnevaluableVersion_StampsAndIsIdempotent covers the marker
// contract: a refused coordinate gets exactly one WarnVersionNotEvaluable
// warning no matter how many writers touch it, and an accepted one gets
// none.
func TestMarkUnevaluableVersion_StampsAndIsIdempotent(t *testing.T) {
	at := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

	bad := &Report{Identity: IdentitySection{
		Ecosystem: "gradle", Package: "com.google.code.findbugs:jsr305", Version: "${jsr305.version}",
	}}
	if !markUnevaluableVersion(bad, at) {
		t.Fatal("markUnevaluableVersion returned false for ${jsr305.version}")
	}
	if !markUnevaluableVersion(bad, at) {
		t.Fatal("second markUnevaluableVersion returned false — the marker must stay true")
	}
	n := 0
	for _, w := range bad.Observation.Warnings {
		if w.Code == WarnVersionNotEvaluable {
			n++
			if w.Message == "" {
				t.Error("warning carries no message; the reason code is unrecoverable")
			}
		}
	}
	if n != 1 {
		t.Fatalf("got %d WarnVersionNotEvaluable warnings, want exactly 1 (idempotency)", n)
	}

	good := &Report{Identity: IdentitySection{
		Ecosystem: "npm", Package: "lodash", Version: "4.17.21",
	}}
	if markUnevaluableVersion(good, at) {
		t.Fatal("markUnevaluableVersion stamped a valid coordinate")
	}
	if len(good.Observation.Warnings) != 0 {
		t.Fatalf("valid coordinate picked up %d warnings", len(good.Observation.Warnings))
	}
}

// TestVersionNotEvaluableIsClassifiedForCoverage pins the coverage
// classification. An unclassified code falls through to StatusError, which
// would report the source as having FAILED — the one thing that did not
// happen here.
func TestVersionNotEvaluableIsClassifiedForCoverage(t *testing.T) {
	if got := coverage.StatusForWarnCode(WarnVersionNotEvaluable); got != coverage.StatusNotApplicable {
		t.Fatalf("StatusForWarnCode(%q) = %q, want %q",
			WarnVersionNotEvaluable, got, coverage.StatusNotApplicable)
	}
}

// requireEvaluabilityDB gates the DB-backed cases below. Unlike a plain
// t.Skip, CHAINSAW_TEST_REQUIRE_DB turns the skip into a failure so a run
// that was supposed to exercise Postgres cannot report "ok" having tested
// nothing.
func requireEvaluabilityDB(t *testing.T) *pgstore.Store {
	t.Helper()
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CHAINSAW_TEST_REQUIRE_DB") != "" {
			t.Fatal("CHAINSAW_TEST_REQUIRE_DB is set but CHAINSAW_DATABASE_URL is empty — " +
				"this test was supposed to run against Postgres")
		}
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping unevaluable-version DB test")
	}
	pg, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = pg.Close() })
	return pg
}

// TestUpsert_MarksUnevaluableCoordinate proves the choke point holds for a
// Report that never went through Scan — i.e. that a future producer
// building a Report by hand still cannot land a row that reads as
// scanned-and-clean.
func TestUpsert_MarksUnevaluableCoordinate(t *testing.T) {
	pg := requireEvaluabilityDB(t)
	store := NewStore(pg)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Second)

	// Deliberately built by hand, bypassing runFanout's stamp.
	bad := &Report{Identity: IdentitySection{
		Ecosystem: "maven",
		Package:   "org.apache.commons:commons-lang3-evalgate-test",
		Version:   "${commons.lang3.version}",
	}}
	bad.Observation.CollectedAt = at
	bad.Observation.FreshUntil = at.Add(time.Hour)

	good := &Report{Identity: IdentitySection{
		Ecosystem: "docker",
		Package:   "library/nginx-evalgate-test",
		Version:   "sha256-0104b33ec1a1a1b0e2f6f0a1c4e9a4f1b3d5c7e9a1b3d5c7e9a1b3d5c7e9a1b3",
	}}
	good.Observation.CollectedAt = at
	good.Observation.FreshUntil = at.Add(time.Hour)

	cleanup := func() {
		for _, r := range []*Report{bad, good} {
			_, _ = pg.DB().ExecContext(ctx,
				`DELETE FROM intelligence_reports WHERE ecosystem=$1 AND package_name=$2 AND version=$3`,
				r.Identity.Ecosystem, r.Identity.Package, r.Identity.Version)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	if err := store.Upsert(ctx, "org-evalgate", bad); err != nil {
		t.Fatalf("upsert unevaluable report: %v", err)
	}
	if err := store.Upsert(ctx, "org-evalgate", good); err != nil {
		t.Fatalf("upsert docker digest report: %v", err)
	}

	// The unevaluable row must be marked, in the blob AND in the denorm
	// column a SQL consumer reads.
	got, err := store.Get(ctx, "org-evalgate", Key{
		Ecosystem: bad.Identity.Ecosystem, Package: bad.Identity.Package, Version: bad.Identity.Version,
	})
	if err != nil {
		t.Fatalf("get unevaluable report: %v", err)
	}
	found := false
	for _, w := range got.Observation.Warnings {
		if w.Code == WarnVersionNotEvaluable {
			found = true
		}
	}
	if !found {
		t.Fatalf("persisted row carries no %s warning — it reads as scanned-and-clean; warnings=%+v",
			WarnVersionNotEvaluable, got.Observation.Warnings)
	}
	var warnCount int
	if err := pg.DB().QueryRowContext(ctx,
		`SELECT warning_count FROM intelligence_reports WHERE ecosystem=$1 AND package_name=$2 AND version=$3`,
		bad.Identity.Ecosystem, bad.Identity.Package, bad.Identity.Version).Scan(&warnCount); err != nil {
		t.Fatalf("read warning_count: %v", err)
	}
	if warnCount < 1 {
		t.Fatalf("warning_count = %d, want >= 1 so a SQL consumer can branch without decoding the blob", warnCount)
	}

	// The docker digest row must be untouched.
	gotGood, err := store.Get(ctx, "org-evalgate", Key{
		Ecosystem: good.Identity.Ecosystem, Package: good.Identity.Package, Version: good.Identity.Version,
	})
	if err != nil {
		t.Fatalf("get docker report: %v", err)
	}
	for _, w := range gotGood.Observation.Warnings {
		if w.Code == WarnVersionNotEvaluable {
			t.Fatalf("docker sha256- digest row was marked unevaluable — the gate is no longer surgical")
		}
	}
}

// TestUnevaluableVersionCounts_ReadOnlyDryRun exercises the operator
// sizing helper against real rows, and asserts it is read-only: the rows it
// counts are still there afterwards.
func TestUnevaluableVersionCounts_ReadOnlyDryRun(t *testing.T) {
	pg := requireEvaluabilityDB(t)
	store := NewStore(pg)
	ctx := context.Background()
	at := time.Now().UTC().Truncate(time.Second)

	seed := []Key{
		{Ecosystem: "gradle", Package: "com.google.code.findbugs:jsr305-countstest", Version: "${jsr305.version}"},
		{Ecosystem: "maven", Package: "org.slf4j:slf4j-api-countstest", Version: "${slf4jVersion}"},
		{Ecosystem: "maven", Package: "com.t_est.upload:t-est-maven-countstest", Version: "metadata"},
		{Ecosystem: "docker", Package: "library/nginx-countstest", Version: "sha256-0104b33ec1a1a1b0e2f6f0a1c4e9a4f1b3d5c7e9a1b3d5c7e9a1b3d5c7e9a1b3"},
		{Ecosystem: "docker", Package: "library/redis-countstest", Version: "latest"},
		{Ecosystem: "npm", Package: "lodash-countstest", Version: "4.17.21"},
	}
	cleanup := func() {
		for _, k := range seed {
			_, _ = pg.DB().ExecContext(ctx,
				`DELETE FROM intelligence_reports WHERE ecosystem=$1 AND package_name=$2 AND version=$3`,
				k.Ecosystem, k.Package, k.Version)
		}
	}
	cleanup()
	t.Cleanup(cleanup)

	before, err := store.UnevaluableVersionCounts(ctx)
	if err != nil {
		t.Fatalf("baseline UnevaluableVersionCounts: %v", err)
	}
	baseline := map[string]int{}
	for _, c := range before {
		baseline[c.Ecosystem+"|"+c.Reason] = c.Count
	}

	for _, k := range seed {
		r := &Report{Identity: IdentitySection{Ecosystem: k.Ecosystem, Package: k.Package, Version: k.Version}}
		r.Observation.CollectedAt = at
		r.Observation.FreshUntil = at.Add(time.Hour)
		if err := store.Upsert(ctx, "org-evalgate", r); err != nil {
			t.Fatalf("seed upsert %+v: %v", k, err)
		}
	}

	after, err := store.UnevaluableVersionCounts(ctx)
	if err != nil {
		t.Fatalf("UnevaluableVersionCounts: %v", err)
	}
	got := map[string]int{}
	for _, c := range after {
		got[c.Ecosystem+"|"+c.Reason] = c.Count
	}

	delta := func(key string) int { return got[key] - baseline[key] }
	for key, want := range map[string]int{
		"gradle|" + UnevaluableVersionUnresolvedProperty: 1,
		"maven|" + UnevaluableVersionUnresolvedProperty:  1,
		"maven|" + UnevaluableVersionMavenNonVersion:     1,
	} {
		if d := delta(key); d != want {
			t.Errorf("bucket %q delta = %d, want %d (after=%+v)", key, d, want, after)
		}
	}
	// The two docker rows and the npm row must not appear at all — this
	// is the surgical-rule assertion at the SQL layer, where a mirrored
	// predicate could drift away from the Go one.
	for _, key := range []string{
		"docker|" + UnevaluableVersionMavenNonVersion,
		"docker|" + UnevaluableVersionUnresolvedProperty,
		"docker|" + UnevaluableVersionEmpty,
		"npm|" + UnevaluableVersionUnresolvedProperty,
	} {
		if d := delta(key); d != 0 {
			t.Errorf("bucket %q delta = %d, want 0 — the SQL predicate is catching real coordinates", key, d)
		}
	}

	// Read-only: every seeded row survives the count.
	for _, k := range seed {
		var n int
		if err := pg.DB().QueryRowContext(ctx,
			`SELECT count(*) FROM intelligence_reports WHERE ecosystem=$1 AND package_name=$2 AND version=$3`,
			k.Ecosystem, k.Package, k.Version).Scan(&n); err != nil {
			t.Fatalf("recount %+v: %v", k, err)
		}
		if n != 1 {
			t.Errorf("row %+v count = %d after UnevaluableVersionCounts, want 1 — the helper is not read-only", k, n)
		}
	}
}

// A coordinate whose version can never be matched must not resolve to a
// clean Allow. Task requirement: "a coordinate that cannot be matched
// should not read as clean."
//
// It routes through the same SignalsUnavailable machinery as a
// hallucinated version pin, so it lands on VerdictUnknown — which
// internal/decision maps to Monitored, NOT Blocked. That is deliberate:
// the point is to stop it rendering as safe, not to refuse an upload or
// an install.
func TestUnevaluableCoordinateResolvesToUnknownNotAllow(t *testing.T) {
	cases := []struct{ eco, pkg, ver string }{
		{"maven", "org.apache.commons:commons-lang3", "${commons.lang3.version}"},
		{"gradle", "com.google.code.findbugs:jsr305", "${jsr305.version}"},
		{"maven", "com.t_est.upload:t-est-maven-20260418122431", "metadata"},
	}
	for _, tc := range cases {
		t.Run(tc.eco+"/"+tc.ver, func(t *testing.T) {
			r := &Report{Identity: IdentitySection{
				Ecosystem: tc.eco, Package: tc.pkg, Version: tc.ver,
			}}
			if !markUnevaluableVersion(r, time.Now()) {
				t.Fatalf("precondition: %q was not stamped unevaluable", tc.ver)
			}
			in := ProjectToRiskInput(r)
			if !in.SignalsUnavailable {
				t.Fatalf("SignalsUnavailable = false — a coordinate that cannot be " +
					"matched must not be scored as though the facts were complete")
			}
			if in.UnavailableReason == "" {
				t.Error("UnavailableReason is empty; the UI renders this clause")
			}
			eval := risk.EvaluatePackage(in, risk.Options{})
			if eval == nil {
				t.Fatal("EvaluatePackage returned nil")
			}
			if eval.Verdict == risk.VerdictAllow {
				t.Errorf("verdict = allow for %q — the coordinate reads as scanned and "+
					"clean while no advisory could ever attach to it", tc.ver)
			}
			if eval.Verdict != risk.VerdictUnknown {
				t.Errorf("verdict = %q, want %q", eval.Verdict, risk.VerdictUnknown)
			}
		})
	}
}

// The counterpart: a normal coordinate is untouched by any of this.
func TestEvaluableCoordinateIsUnaffected(t *testing.T) {
	r := &Report{Identity: IdentitySection{
		Ecosystem: "npm", Package: "lodash", Version: "4.17.21",
	}}
	if markUnevaluableVersion(r, time.Now()) {
		t.Fatal("a normal version must not be stamped unevaluable")
	}
	if in := ProjectToRiskInput(r); in.SignalsUnavailable {
		t.Error("SignalsUnavailable = true for lodash@4.17.21 — the guard is over-broad")
	}
}
