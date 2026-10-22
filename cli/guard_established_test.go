package cli

// guard_established_test.go — the offline guard's established-clear, hermetic
// end to end: the ladder invariants the adversarial review demanded, the TSV
// parser, the normalization keying, and the guard half of the guard≡server
// conformance (the server half lives in
// core/intelligence/typosquat_established_conformance_test.go and asserts the
// same rows through the server path).
//
// The embedded per-ecosystem tables (seeds/established_*.tsv) are generated
// by the seed pipeline and may not have landed; every behavioural test below
// therefore INJECTS its rows through setEstablishedTablesForTest, which swaps
// the process-local table cache — no files, no network, no env gating. The
// one test that reads the embedded tables skips with a message when only the
// placeholder is present.

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/risk"
	"github.com/chain305/chainsaw-core/typosquat"
)

// guardEstablishedNow is the same fixed clock the risk and intelligence
// conformance tables use, so a row that clears here clears there.
var guardEstablishedNow = time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC)

// setEstablishedTablesForTest swaps the process-local established-table cache
// for tables built from rows-by-ecosystem (names are normalized with the
// detector's own per-ecosystem normalizer, exactly as parseEstablishedTable
// does), and restores the empty cache on cleanup so no other test observes
// the injection.
func setEstablishedTablesForTest(t *testing.T, byEco map[string]map[string]risk.EstablishedRow) {
	t.Helper()
	prepared := make(map[string]map[string]risk.EstablishedRow, len(byEco))
	for eco, rows := range byEco {
		idx := make(map[string]risk.EstablishedRow, len(rows))
		for name, row := range rows {
			idx[typosquat.NormalizerForFormat(eco)(name)] = row
		}
		prepared[establishedTableEcosystem(eco)] = idx
	}
	establishedTableState.mu.Lock()
	establishedTableState.byEco = prepared
	establishedTableState.mu.Unlock()
	t.Cleanup(func() {
		establishedTableState.mu.Lock()
		establishedTableState.byEco = nil // forces a re-parse of the embedded seeds
		establishedTableState.mu.Unlock()
	})
}

// establishedNPMRow builds one npm-table fixture.
func establishedNPMRow(name string, weekly int64, versions int, first, last string) (string, risk.EstablishedRow) {
	row := risk.EstablishedRow{Name: name, WeeklyDownloads: weekly, VersionCount: versions}
	if first != "" {
		row.FirstPublished = mustDay(first)
	}
	if last != "" {
		row.LastPublished = mustDay(last)
	}
	return name, row
}

func mustDay(s string) time.Time {
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		panic(err)
	}
	return t
}

// ── the ladder invariants ───────────────────────────────────────────────────

// TestEstablishedClearSkipsTyposquatLaneNotTheRest: an established row turns
// a would-be d=1 BLOCK into a clean allow — no typosquat block, no
// typosquat warn, no policyWarn — while evaluate() FALLS THROUGH to the
// byte-scan step (scanAttempted advances) and records the clear on the
// verdict. Silence needs an exact pin inside the row's build-time release
// set (guard_established_version_test.go covers every other request).
//
// `lodahs` (transposition of lodash, #101) is a d=1 in-cutoff hit that BLOCKS
// without a table; the row gives it csrf-scale weekly downloads.
func TestEstablishedClearSkipsTyposquatLaneNotTheRest(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()

	// Control: without a table the hit blocks.
	if v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "lodahs"}); !v.Block || v.Severity != guardSeverityTyposquatHigh {
		t.Fatalf("fixture no longer blocks without a table: %+v — re-pick it", v)
	}

	setEstablishedTablesForTest(t, map[string]map[string]risk.EstablishedRow{
		"npm": func() map[string]risk.EstablishedRow {
			name, row := establishedNPMRow("lodahs", 1_277_456, 0, "", "")
			row.Releases = map[string]struct{}{"1.0.0": {}}
			return map[string]risk.EstablishedRow{name: row}
		}(),
	})

	g2 := newSeedOnlyGuard(t)
	before := GuardEstablishedClearsCount()
	v := g2.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "lodahs", Version: "1.0.0"})

	if v.Block {
		t.Fatalf("established candidate must not block: %+v", v)
	}
	if v.Severity != "" || v.Reason != "" {
		t.Fatalf("the typosquat lane must leave NO warn behind (pendingWarn/policyWarn untouched): %+v", v)
	}
	if v.ClearedReason == "" {
		t.Fatal("the clear must be recorded on the verdict (ClearedReason), not silent")
	}
	for _, want := range []string{"lodahs", "lodash", "established", "downloads per week"} {
		if !strings.Contains(v.ClearedReason, want) {
			t.Errorf("ClearedReason %q lacks %q", v.ClearedReason, want)
		}
	}
	if after := GuardEstablishedClearsCount(); after != before+1 {
		t.Errorf("package-level clear counter = %d after one clear, want %d", after, before+1)
	}
	// FALL-THROUGH, not early return: the spec reached the byte-acquisition
	// step, so a malicious staged artifact would still block behaviorally.
	if g2.scanAttempted != 1 {
		t.Errorf("scanAttempted = %d, want 1 — the cleared verdict must still run the byte-scan step", g2.scanAttempted)
	}
}

// TestEstablishedClearDoesNotTouchHomoglyph: byte-level evidence is above
// data clears. `nаn` (Cyrillic U+0430) against corpus `nan` has an
// established row keyed under its EXACT confusable name — the row would clear
// if consulted, and the test proves the homoglyph arm returns before the
// consult: still BLOCK, still Unwaivable, and no clear recorded.
func TestEstablishedClearDoesNotTouchHomoglyph(t *testing.T) {
	const cyrillicNan = "nаn" // U+0430 CYRILLIC SMALL LETTER A
	name, row := establishedNPMRow(cyrillicNan, 130_000_000, 0, "", "")
	setEstablishedTablesForTest(t, map[string]map[string]risk.EstablishedRow{
		"npm": {name: row},
	})

	// The row really would clear — through the very lookup evaluate() uses.
	if _, _, ok := establishedClears("npm", cyrillicNan, guardEstablishedNow); !ok {
		t.Fatal("fixture row does not clear — the test cannot prove the arm ordering without it")
	}

	g := newSeedOnlyGuard(t)
	v := g.evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: cyrillicNan})
	if !v.Block || v.Severity != guardSeverityTyposquatHigh || !v.Unwaivable {
		t.Fatalf("homoglyph hit must BLOCK unwaivably regardless of establishment data, got %+v", v)
	}
	if v.ClearedReason != "" {
		t.Errorf("a homoglyph block must carry NO clear (got %q) — byte-level evidence outranks data clears", v.ClearedReason)
	}
}

// TestEstablishedClearDoesNotTouchMalware: the known-malicious lane returns
// before the typosquat lane, established row or not. Uses the same synthetic
// malware-index fixture pattern as TestGuardRangeRefusal….
func TestEstablishedClearDoesNotTouchMalware(t *testing.T) {
	idx := malware.NewIndex(guardLogger)
	idx.Load([]*malware.OSVEntry{{
		ID: "MAL-TEST-ESTABLISHED",
		Affected: []malware.OSVAffected{{
			Package:  malware.OSVPackage{Ecosystem: "npm", Name: "lodahs"},
			Versions: []string{"1.0.0"},
		}},
	}})
	name, row := establishedNPMRow("lodahs", 5_000_000, 0, "", "")
	setEstablishedTablesForTest(t, map[string]map[string]risk.EstablishedRow{
		"npm": {name: row},
	})

	g := newSeedOnlyGuard(t)
	g.malware = idx
	v := g.evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "lodahs", Version: "1.0.0"})
	if !v.Block || v.Severity != "malicious" {
		t.Fatalf("known-malicious coordinate must BLOCK despite an established row, got %+v", v)
	}
	if v.ClearedReason != "" {
		t.Errorf("a malware block must carry NO clear (got %q)", v.ClearedReason)
	}
}

// TestEstablishedClearLeavesLowConfidenceCombosquatSilent: the deliberate
// silence at the bottom of the ladder (see evaluate) must survive an
// established row. Warning would leak the ~1-in-9 real-package population
// the silence protects; so would a "~ established" clear notice.
func TestEstablishedClearLeavesLowConfidenceCombosquatSilent(t *testing.T) {
	name, row := establishedNPMRow("express-toolkit", 5_000_000, 0, "", "")
	setEstablishedTablesForTest(t, map[string]map[string]risk.EstablishedRow{
		"npm": {name: row},
	})

	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	// Fixture check: express-toolkit is the low-confidence combosquat shape
	// the silence suite already pins.
	res := g.detector("npm").Check(ctx, "npm", "express-toolkit")
	if !res.IsSuspected || res.Confidence != "low" {
		t.Fatalf("fixture no longer exercises the silent combosquat branch: %+v — re-pick it", res)
	}
	before := GuardEstablishedClearsCount()
	v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "express-toolkit"})
	if v.Block || v.Severity != "" || v.Reason != "" || v.ClearedReason != "" {
		t.Fatalf("low-confidence combosquat on an established row must stay SILENT, got %+v", v)
	}
	if after := GuardEstablishedClearsCount(); after != before {
		t.Errorf("clear counter advanced (%d → %d) on a silent-class hit", before, after)
	}
}

// TestEstablishedClearFallsThroughToBehavioralBlock: an established row plus
// malicious STAGED BYTES must still block on the byte scan — the clear skips
// only the name lane. Stages a real hidden-unicode artifact through the same
// CHAINSAW_GUARD_ARTIFACT_DIR mechanism the byte-scan suite uses.
func TestEstablishedClearFallsThroughToBehavioralBlock(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "npm"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The hidden-unicode payload shape the parity suite blocks on: a run of
	// zero-width runes inside executable code (see
	// guard_artifact_hiddenunicode_test.go).
	tgz := makeTGZ(t, map[string]string{
		"package/package.json": `{"name":"lodahs","version":"1.0.0"}`,
		"package/index.js":     "var k = \"" + strings.Repeat("​", 8) + "\";\n",
	})
	if err := os.WriteFile(filepath.Join(dir, "npm", "lodahs-1.0.0.tgz"), tgz, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv(guardArtifactDirEnv, dir)
	// Hermetic: no `guard update` cache and no intelligence bundle — a
	// developer's real known_malicious.json carries the FULL OpenSSF feed,
	// which knows the historical lodahs squat and would turn this into a
	// malware-lane test instead.
	t.Setenv(guardDBEnv, filepath.Join(t.TempDir(), "absent.json"))
	t.Setenv(intelligence.BundleEnvVar, "")

	name, row := establishedNPMRow("lodahs", 5_000_000, 0, "", "")
	row.Releases = map[string]struct{}{"1.0.0": {}}
	setEstablishedTablesForTest(t, map[string]map[string]risk.EstablishedRow{
		"npm": {name: row},
	})

	g := newLocalGuard()
	v := g.evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "lodahs", Version: "1.0.0"})
	if !v.Block {
		t.Fatalf("established row must NOT mask a behavioral block, got %+v", v)
	}
	if v.Severity == guardSeverityTyposquatHigh || v.Severity == "malicious" {
		t.Fatalf("block came from the %q lane — the row should have cleared the name lane and no malware coordinate exists: %+v", v.Severity, v)
	}
	if v.ClearedReason == "" {
		t.Error("the clear must still be recorded beside the behavioral block (ClearedReason)")
	}
}

// ── guard ≡ server: one definition, asserted from the guard side ───────────

// TestGuardClearMatchesEstablishedClear is the guard half of the conformance
// pair (the server half: core/intelligence, TestServerClearMatches…). The
// guard's table lookup must decide exactly what risk.EstablishedClear — the
// same function the server path routes through — decides for the same row.
func TestGuardClearMatchesEstablishedClear(t *testing.T) {
	rows := []risk.EstablishedRow{
		{Name: "csrf", WeeklyDownloads: 1_277_456},
		{Name: "weekly-at-line", WeeklyDownloads: risk.EstablishedWeeklyDownloads},
		{Name: "weekly-one-below", WeeklyDownloads: risk.EstablishedWeeklyDownloads - 1},
		{Name: "expres", WeeklyDownloads: 8_167},
		{Name: "dbsp", VersionCount: 299, FirstPublished: mustDay("2023-08-23")},
		{Name: "versions-at-line", VersionCount: risk.EstablishedMinVersions, FirstPublished: mustDay("2024-10-19")},
		{Name: "jamespath", FirstPublished: mustDay("2013-11-27"), LastPublished: mustDay("2013-11-27")},
		{Name: "long-lived-last-unknown", FirstPublished: mustDay("2010-01-01")},
		{Name: "sleeper", FirstPublished: mustDay("2015-01-01"), LastPublished: mustDay("2026-06-01")},
		{Name: "no-data"},
	}
	table := make(map[string]risk.EstablishedRow, len(rows))
	for _, r := range rows {
		table[r.Name] = r
	}
	setEstablishedTablesForTest(t, map[string]map[string]risk.EstablishedRow{"npm": table})

	for _, r := range rows {
		wantReason, wantCleared := risk.EstablishedClear(r, guardEstablishedNow)
		gotReason, gotRow, ok := establishedClears("npm", r.Name, guardEstablishedNow)
		if ok != wantCleared {
			t.Errorf("%s: establishedClears ok=%v, risk.EstablishedClear cleared=%v (%q) — the guard and the server disagree",
				r.Name, ok, wantCleared, wantReason)
			continue
		}
		if !ok {
			continue
		}
		if gotRow.Name != r.Name {
			t.Errorf("%s: lookup returned the wrong row (%q)", r.Name, gotRow.Name)
		}
		if gotReason != wantReason {
			t.Errorf("%s: reason %q, want the shared definition's %q", r.Name, gotReason, wantReason)
		}
	}
}

// ── lookup: normalization and ecosystem aliasing ───────────────────────────

// TestEstablishedClearsKeysByDetectorNormalization: a PyPI table row keyed by
// any PEP 503 spelling answers lookups in every other spelling — the SAME
// normalizer the detector keys its corpus with, so a name the detector
// suspects is a name the table can clear.
func TestEstablishedClearsKeysByDetectorNormalization(t *testing.T) {
	name, row := establishedNPMRow("django-filter", 2_000_000, 0, "", "")
	setEstablishedTablesForTest(t, map[string]map[string]risk.EstablishedRow{
		"pypi": {name: row}, // table keyed by the REGISTRY spelling…
	})
	for _, eco := range []string{"pip", "pypi", "python"} { // …looked up by the guard's verb and its aliases
		for _, spelling := range []string{"django-filter", "Django_Filter", "django.filter", "DJANGO__FILTER"} {
			reason, gotRow, ok := establishedClears(eco, spelling, guardEstablishedNow)
			if !ok {
				t.Errorf("establishedClears(%q, %q) missed the row — normalization keying is broken", eco, spelling)
				continue
			}
			if gotRow.Name != "django-filter" || !strings.Contains(reason, "downloads per week") {
				t.Errorf("establishedClears(%q, %q) = (%q, %+v): wrong row or reason", eco, spelling, reason, gotRow)
			}
		}
	}
	// npm's normalizer does NOT fold delimiters: a pip row never answers an
	// npm lookup, and vice versa a pip-spelled npm name is a different key.
	if _, _, ok := establishedClears("npm", "django-filter", guardEstablishedNow); ok {
		t.Error("an npm lookup must not consult the pypi table (per-ecosystem keying)")
	}
	if _, _, ok := establishedClears("pip", "django", guardEstablishedNow); ok {
		t.Error("a different name must not match")
	}
}

// ── the TSV parser ──────────────────────────────────────────────────────────

// captureSlog installs a buffer-backed default slog handler for one test and
// returns the buffer, so "malformed rows are skipped LOUDLY" is asserted
// against what was actually logged rather than against a count alone.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestParseEstablishedTable covers the whole row grammar: '#' headers,
// blank lines, empty date fields (unknown), malformed rows skipped with a
// LOUD log, negative counts kept (a failed fetch is below every line, not a
// parse error), and first-occurrence-wins duplicates.
func TestParseEstablishedTable(t *testing.T) {
	logs := captureSlog(t)
	input := "" +
		"# established_npm.tsv — generated, do not edit\n" +
		"# columns: name, weekly_downloads, version_count, first_published, last_published\n" +
		"pug\t5000000\t142\t2016-07-01\t\n" + // last unknown: valid, zero time
		"jsdoc\t99000\t60\t2012-05-01\t2026-01-01\n" + // version line, weekly below
		"Django_Filter\t200000\t\t\t\n\n" + // empty counts and dates: unknown, weekly carries it
		"no-data\t0\t0\t\t\n" +
		"neg\t-1\t5\t2020-01-01\t2025-01-01\n" + // failed fetch marker: kept, clears nothing
		"baddate\t1000\t5\t2020-13-01\t\n" + // month 13: skipped
		"onlyname\n" + // 1 field: skipped
		"dup\t1000\t5\t\t\n" +
		"dup\t9999000\t5\t\t\n" + // duplicate key: FIRST wins (1000/week does not clear)
		"pug2\tnotanumber\t5\t\t\n" // non-numeric weekly: skipped

	rows, skipped := parseEstablishedTable("pip", []byte(input))
	if skipped != 3 {
		t.Fatalf("skipped = %d, want 3 (baddate, onlyname, bad weekly); rows: %v", skipped, rows)
	}
	for _, want := range []string{"pug", "django-filter", "no-data", "neg", "dup", "jsdoc"} {
		if _, ok := rows[want]; !ok {
			t.Errorf("row %q missing from %v", want, rows)
		}
	}
	// Empty date fields mean unknown, and unknown last fails long-lived —
	// pug clears on the WEEKLY line, not on age.
	if rows["pug"].LastPublished != (time.Time{}) || rows["pug"].FirstPublished != mustDay("2016-07-01") {
		t.Errorf("pug dates parsed wrong: %+v", rows["pug"])
	}
	if rows["jsdoc"].VersionCount != 60 {
		t.Errorf("jsdoc version count parsed wrong: %+v", rows["jsdoc"])
	}
	if rows["django-filter"].WeeklyDownloads != 200000 {
		t.Errorf("PEP 503 keying inside the parser is broken: %+v", rows)
	}
	if rows["dup"].WeeklyDownloads != 1000 {
		t.Errorf("duplicate rows must keep the FIRST occurrence, got %+v", rows["dup"])
	}
	// LOUD: every skip is logged with what was wrong.
	out := logs.String()
	for _, want := range []string{"malformed row", "malformed date", "malformed weekly_downloads"} {
		if !strings.Contains(out, want) {
			t.Errorf("skip was not logged loudly — wanted %q in:\n%s", want, out)
		}
	}
}

// TestParseEstablishedTableDecisions: rows that parse still have to CLEAR
// through the shared definition — the parser's job is faithful rows, the
// decision's job belongs to risk.EstablishedClear.
func TestParseEstablishedTableDecisions(t *testing.T) {
	rows, _ := parseEstablishedTable("pip", []byte(""+
		"clears-weekly\t500000\t0\t\t\n"+
		"clears-history\t100\t50\t2020-01-01\t\n"+
		"clears-longlived\t0\t0\t2015-01-01\t2025-06-01\n"+
		"stays\t99999\t49\t2020-01-01\t\n"))
	table := "pip"
	for _, name := range []string{"clears-weekly", "clears-history", "clears-longlived"} {
		setEstablishedTablesForTest(t, map[string]map[string]risk.EstablishedRow{table: rows})
		if _, _, ok := establishedClears("pip", name, guardEstablishedNow); !ok {
			t.Errorf("%s should clear through the shared definition", name)
		}
	}
	setEstablishedTablesForTest(t, map[string]map[string]risk.EstablishedRow{table: rows})
	if _, _, ok := establishedClears("pip", "stays", guardEstablishedNow); ok {
		t.Error("a row below every line must not clear")
	}
}

// TestEstablishedClearPrintsInformationalLine: the clear renders as a
// "~ established" line beside whatever the rest of the ladder said,
// suppressed under --quiet (context, not a verdict — dozens can fire on one
// lockfile install), and never as a block.
func TestEstablishedClearPrintsInformationalLine(t *testing.T) {
	v := guardVerdict{
		Spec:          packageSpec{Ecosystem: "npm", Name: "pug"},
		ClearedReason: `looks like a typosquat of "pg" (distance 1, edit-distance, target rank #1434) — cleared, pug is established (5000000 downloads per week)`,
	}
	out := printedLines(t, false, v)
	for _, want := range []string{"~ established", "pug", "downloads per week", "malware and byte checks still ran"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
	if quiet := printedLines(t, true, v); strings.Contains(quiet, "established") {
		t.Errorf("--quiet must suppress the informational clear line (INVARIANT D), got:\n%s", quiet)
	}
}

// ── the embedded side ──────────────────────────────────────────────────────

// TestEstablishedPlaceholderCarriesNoRows: the comment-only build-support
// file must parse to zero rows, whatever else lands beside it.
func TestEstablishedPlaceholderCarriesNoRows(t *testing.T) {
	data, err := establishedSeedFS.ReadFile("seeds/established_placeholder.tsv")
	if err != nil {
		t.Fatalf("placeholder missing — the go:embed pattern no longer compiles for everyone: %v", err)
	}
	rows, skipped := parseEstablishedTable("placeholder", data)
	if len(rows) != 0 || skipped != 0 {
		t.Fatalf("placeholder must carry zero rows and skip nothing, got %d rows / %d skipped", len(rows), skipped)
	}
}

// TestEmbeddedEstablishedTablesAreSelfConsistent runs over whatever real
// tables are embedded TODAY: every parsed row must be retrievable through
// establishedClears under its own name and must agree with the shared
// definition. Skips with a clear message while only the placeholder exists —
// the seed pipeline lands seeds/established_*.tsv separately — and runs for
// real the moment they do.
func TestEmbeddedEstablishedTablesAreSelfConsistent(t *testing.T) {
	resetEstablishedTables := func() {
		establishedTableState.mu.Lock()
		establishedTableState.byEco = nil // forces a re-parse of the embedded seeds
		establishedTableState.mu.Unlock()
	}
	resetEstablishedTables()
	t.Cleanup(resetEstablishedTables)

	tables := loadEstablishedTables()
	total := 0
	for _, rows := range tables {
		total += len(rows)
	}
	if total == 0 {
		t.Skip("no embedded established tables yet (only the build-support placeholder) — " +
			"the loader, parser, keying and ladder behaviour are covered above with injected rows; " +
			"this test exercises the real generated tables once seeds/established_*.tsv land")
	}
	for eco, rows := range tables {
		for key, row := range rows {
			wantReason, wantCleared := risk.EstablishedClear(row, guardEstablishedNow)
			gotReason, _, ok := establishedClears(eco, row.Name, guardEstablishedNow)
			if ok != wantCleared {
				t.Errorf("%s:%s (key %q): lookup ok=%v, shared definition cleared=%v — keying or decision diverged",
					eco, row.Name, key, ok, wantCleared)
				continue
			}
			if ok && gotReason != wantReason {
				t.Errorf("%s:%s: reason %q, want %q", eco, row.Name, gotReason, wantReason)
			}
		}
		t.Logf("embedded established table %-10s %d rows", eco, len(rows))
	}
}
