package cli

// guard_established_version_test.go — the version gate on the established
// clear (2026-10-21). A clear used to skip the typosquat lane for ANY
// version, so a dormant lookalike that qualified years ago and then shipped a
// malicious release was cleared on its history. Now a clear lowers a block to
// a printed warning, and is silent only for an exact pin inside the row's
// build-time release set (the TSV's sixth column).
//
// Rows are injected as TSV through parseEstablishedTable, the production
// parser, so these tests exercise the column format end to end.

import (
	"context"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

// injectNPMTable parses an npm TSV and installs it as the npm table.
func injectNPMTable(t *testing.T, tsv string) {
	t.Helper()
	rows, skipped := parseEstablishedTable("npm", []byte(tsv))
	if skipped != 0 {
		t.Fatalf("fixture TSV skipped %d row(s) — the parser rejects the column format", skipped)
	}
	setEstablishedTablesForTest(t, map[string]map[string]risk.EstablishedRow{"npm": rows})
}

// lodahsWithReleases: `lodahs` BLOCKS without a table (d=1 transposition of
// lodash #101); the row gives it the downloads line and two build-time
// releases.
const lodahsWithReleases = "lodahs\t1277456\t2\t2015-01-01\t2016-01-01\t1.0.0,1.0.1\n"

func assertEstablishedWarn(t *testing.T, v guardVerdict, version string) {
	t.Helper()
	if v.Block {
		t.Fatalf("an established row must lower the block (version %q), got %+v", version, v)
	}
	if v.Severity != guardSeverityTyposquatDemoted {
		t.Fatalf("version %q: want a printed warning (severity %q, shown even under --quiet), got %+v",
			version, guardSeverityTyposquatDemoted, v)
	}
	if v.ClearedReason != "" {
		t.Errorf("version %q: a warning is not a silent clear, but ClearedReason = %q", version, v.ClearedReason)
	}
	for _, want := range []string{"lodash", "lodahs is established", "not a refusal"} {
		if !strings.Contains(v.Reason, want) {
			t.Errorf("version %q: warning %q lacks %q (it must name the lookalike target and why it is not a refusal)",
				version, v.Reason, want)
		}
	}
}

// TestEstablishedClearWarnsOnPostBuildVersion: a version the table never saw
// is the shape of a dormant lookalike shipping a new release — it warns.
func TestEstablishedClearWarnsOnPostBuildVersion(t *testing.T) {
	injectNPMTable(t, lodahsWithReleases)
	v := newSeedOnlyGuard(t).evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "lodahs", Version: "2.0.0"})
	assertEstablishedWarn(t, v, "2.0.0")
	if !strings.Contains(v.Reason, `"2.0.0"`) {
		t.Errorf("the warning must say which version fell outside the table: %q", v.Reason)
	}
}

// TestEstablishedClearWarnsOnUnpinnedInstall: `npm install jsonp`,
// `faiss-gpu>=1` and `x@^1.0.0` reach the guard with no exact version, which
// is why a version check alone could not close the fail-open.
func TestEstablishedClearWarnsOnUnpinnedInstall(t *testing.T) {
	injectNPMTable(t, lodahsWithReleases)
	g := newSeedOnlyGuard(t)
	for _, version := range []string{"", "^1.0.0", "latest", "1.0"} {
		v := g.evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "lodahs", Version: version})
		assertEstablishedWarn(t, v, version)
	}
}

// TestEstablishedClearSilentForPinnedBuildRelease: an exact pin the table
// recorded at build time is the one silent case (lockfile installs).
func TestEstablishedClearSilentForPinnedBuildRelease(t *testing.T) {
	injectNPMTable(t, lodahsWithReleases)
	g := newSeedOnlyGuard(t)
	for _, version := range []string{"1.0.1", "=1.0.0", "v1.0.0"} {
		v := g.evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "lodahs", Version: version})
		if v.Block || v.Severity != "" {
			t.Errorf("pinned build-time release %q must clear silently, got %+v", version, v)
		}
		if v.ClearedReason == "" {
			t.Errorf("pinned build-time release %q: the clear must still be recorded (ClearedReason)", version)
		}
	}
}

// TestEstablishedFiveColumnRowNeverSilent: a row without a release set (an
// older table, or a row the generator did not see as a lookalike) can only
// warn — unknown releases are never silent. This is the version-blind clear
// itself: the same five-column row used to clear every one of these requests.
func TestEstablishedFiveColumnRowNeverSilent(t *testing.T) {
	injectNPMTable(t, "lodahs\t1277456\t2\t2015-01-01\t2016-01-01\n")
	g := newSeedOnlyGuard(t)
	for _, version := range []string{"", "1.0.0", "99.0.0"} {
		v := g.evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "lodahs", Version: version})
		assertEstablishedWarn(t, v, version)
	}
}

// TestEstablishedWarnSurvivesQuiet: the warning is printed under --quiet.
// It is a block the table lowered, and an operator must be able to audit it.
func TestEstablishedWarnSurvivesQuiet(t *testing.T) {
	injectNPMTable(t, lodahsWithReleases)
	v := newSeedOnlyGuard(t).evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "lodahs"})
	out := printedLines(t, true, v)
	if !strings.Contains(out, "lodahs") || !strings.Contains(out, "lodash") {
		t.Fatalf("--quiet dropped the established warning:\n%s", out)
	}
}
