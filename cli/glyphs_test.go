package cli

// glyphs_test.go — the Windows-codepage glyph fallback (output.go, glyphSet).
//
// THE BUG. The CLI printed status markers — ✓ U+2713, ✗ U+2717, ↻ U+21BB,
// ⚠ U+26A0, ℹ U+2139 — that are NOT in CP437, the legacy Windows console
// codepage. Such a console renders each as the SAME replacement box, so two
// `chainsaw features` rows became visually identical when one capability was
// on and one was off, the `doctor --offline` matrix collapsed five states into
// one, and a blocked malicious install read as "▯ refused at the install
// path". (○ U+25CB IS in CP437 and survived, which is what pinned the
// diagnosis.)
//
// TESTING A WINDOWS-ONLY BUG WITHOUT A WINDOWS RUNNER. The platform probe is
// isolated behind the package var consoleSupportsUnicode (output.go), whose
// real implementations live in unicode_windows.go / unicode_other.go.
// forceASCIIGlyphs overrides that var, so a CP437 console is reproduced on
// macOS and Linux and every assertion below runs on every CI job. A test that
// only runs on a runner we do not have is a test that does not run.

import (
	"bytes"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/chain305/chainsaw-core/doctor"
	"github.com/spf13/cobra"
)

// forceASCIIGlyphs simulates a console that cannot encode the Unicode set
// (e.g. Windows CP437) without touching CHAINSAW_NO_UNICODE, so tests can tell
// the two independent triggers apart.
func forceASCIIGlyphs(t *testing.T) {
	t.Helper()
	prev := consoleSupportsUnicode
	consoleSupportsUnicode = func() bool { return false }
	t.Cleanup(func() { consoleSupportsUnicode = prev })
}

// forceUnicodeConsole pins the platform probe to "capable", so a test can
// isolate the env-var trigger from the console trigger.
func forceUnicodeConsole(t *testing.T) {
	t.Helper()
	prev := consoleSupportsUnicode
	consoleSupportsUnicode = func() bool { return true }
	t.Cleanup(func() { consoleSupportsUnicode = prev })
}

// asciiOnly reports whether every byte of s is in the 7-bit ASCII range, which
// is the property that makes a string renderable in CP437, CP850, CP1252 and
// every other OEM codepage alike.
func asciiOnly(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7f {
			return false
		}
	}
	return true
}

// noUnicodeMarkers reports whether s is free of every marker in the Unicode
// glyph set, and names the first one it finds.
//
// SCOPE, stated precisely. This is the property the fix actually establishes:
// no STATUS MARKER is emitted that a legacy codepage cannot encode. It is
// deliberately NOT "s is pure ASCII", because the surrounding PROSE still
// contains em dashes (— U+2014), which are equally absent from CP437.
//
// The distinction is not a cop-out, it is the severity boundary. A boxed em
// dash mid-sentence is ugly and the sentence still reads. A boxed STATUS
// MARKER destroys information: it makes five states one state, and makes an
// active capability indistinguishable from an inactive one. The markers are
// what this change fixes; the prose punctuation is a separate, far larger
// sweep spanning files this change does not own, and is recorded as follow-up
// rather than half-done here.
//
// UPDATE: that follow-up sweep has since landed for the files listed in
// asciiOutputRenderers below, and those are held to the stricter asciiOnly
// bar instead. This predicate stays the right one for output that this
// package renders but that sweep did not reach (the wrapped guard, features,
// status, and any prose that arrives as JSON payload rather than as a
// renderer's own template).
func noUnicodeMarkers(s string) (string, bool) {
	for _, m := range []string{
		unicodeGlyphs.ok, unicodeGlyphs.fail, unicodeGlyphs.warn,
		unicodeGlyphs.refresh, unicodeGlyphs.none, unicodeGlyphs.info,
	} {
		if strings.Contains(s, m) {
			return m, false
		}
	}
	return "", true
}

// ── the predicate ──────────────────────────────────────────────────────────

func TestUnicodeEnabled_EnvVarSelectsASCII(t *testing.T) {
	forceUnicodeConsole(t) // isolate: only the env var may decide here

	cases := []struct {
		name        string
		value       string
		wantUnicode bool
	}{
		// "Set to anything meaningful" disables Unicode...
		{"one", "1", false},
		{"true", "true", false},
		{"yes", "yes", false},
		{"arbitrary", "please", false},
		// ...including the bare-set/empty form, which an operator writing
		// `export CHAINSAW_NO_UNICODE=` plainly means as "on".
		{"empty", "", false},
		// ...but an EXPLICIT off is honoured. R7 (see verboseEnabled in
		// output.go) recorded that presence-only tests on CHAINSAW_* vars make
		// `FOO=0` mean ON — the opposite of the operator's intent.
		{"zero", "0", true},
		{"false", "false", true},
		{"off", "off", true},
		{"no", "no", true},
		{"padded-false", "  FALSE  ", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CHAINSAW_NO_UNICODE", tc.value)
			if got := unicodeEnabled(); got != tc.wantUnicode {
				t.Fatalf("CHAINSAW_NO_UNICODE=%q: unicodeEnabled()=%v, want %v", tc.value, got, tc.wantUnicode)
			}
		})
	}
}

// CHAINSAW_NO_UNICODE=0 declines to be the REASON Unicode is off; it must not
// override a console that genuinely cannot encode the glyphs. Otherwise an
// operator who set =0 once in a profile would permanently re-break every
// CP437 console they later used.
func TestUnicodeEnabled_ExplicitOffDoesNotOverrideConsoleProbe(t *testing.T) {
	forceASCIIGlyphs(t)
	t.Setenv("CHAINSAW_NO_UNICODE", "0")
	if unicodeEnabled() {
		t.Fatal("CHAINSAW_NO_UNICODE=0 must not force Unicode on a console that cannot encode it")
	}
}

func TestGlyphs_ASCIIFallbackSelected(t *testing.T) {
	forceUnicodeConsole(t)
	t.Setenv("CHAINSAW_NO_UNICODE", "1")

	g := glyphs()
	if g != asciiGlyphs {
		t.Fatalf("CHAINSAW_NO_UNICODE=1 must select the ASCII set; got %+v", g)
	}
	for name, s := range map[string]string{
		"ok": g.ok, "fail": g.fail, "warn": g.warn,
		"refresh": g.refresh, "none": g.none, "info": g.info,
	} {
		if !asciiOnly(s) {
			t.Errorf("fallback glyph %s = %q is not 7-bit ASCII", name, s)
		}
	}
}

func TestGlyphs_UnicodeIsTheDefault(t *testing.T) {
	forceUnicodeConsole(t)
	if g := glyphs(); g != unicodeGlyphs {
		t.Fatalf("a capable console with no opt-out must keep the Unicode set; got %+v", g)
	}
}

// The glyph decision is a CONSOLE-ENCODING decision, not a color decision.
// ansi_windows.go's ENABLE_VIRTUAL_TERMINAL_PROCESSING governs escape
// sequences and does nothing for the codepage, and empirically
// `NO_COLOR=1 TERM=dumb chainsaw doctor --offline` still emitted the full
// Unicode legend. A user may legitimately want color without Unicode, or
// Unicode without color, so the two predicates must not be wired together.
func TestUnicodeEnabled_IndependentOfColorSignals(t *testing.T) {
	forceUnicodeConsole(t)
	t.Setenv("NO_COLOR", "1")
	t.Setenv("TERM", "dumb")
	if !unicodeEnabled() {
		t.Fatal("color opt-outs must not disable Unicode glyphs — different concerns")
	}
}

// ── alignment ──────────────────────────────────────────────────────────────

// The doctor --offline matrix is 25 rows wide and tabwriter measures each cell
// in runes. Both sets must therefore be one rune per marker, or switching
// alphabets would re-flow the STATUS column — and re-flow it by a different
// amount per row, which is worse than the bug being fixed.
func TestGlyphSets_AreSingleRuneAndDistinct(t *testing.T) {
	for setName, set := range map[string]glyphSet{"unicode": unicodeGlyphs, "ascii": asciiGlyphs} {
		markers := map[string]string{
			"ok": set.ok, "fail": set.fail, "warn": set.warn,
			"refresh": set.refresh, "none": set.none, "info": set.info,
		}
		seen := map[string]string{}
		for name, s := range markers {
			if n := utf8.RuneCountInString(s); n != 1 {
				t.Errorf("%s set: %s = %q is %d runes, want exactly 1 (column alignment)", setName, name, s, n)
			}
			if other, dup := seen[s]; dup {
				t.Errorf("%s set: %s and %s both render as %q — the states become indistinguishable", setName, name, other, s)
			}
			seen[s] = name
		}
		if len(seen) != 6 {
			t.Errorf("%s set: want 6 mutually distinct markers, got %d", setName, len(seen))
		}
	}
}

// ── the block message (guard_install.go) ───────────────────────────────────

// THE headline moment. A refusal is the whole product; on a CP437 console it
// read as "▯ refused at the install path".
func TestGuardRefusalLine_ASCIIInFallbackMode(t *testing.T) {
	forceASCIIGlyphs(t)

	line := guardRefusalLine(glyphs())
	if m, ok := noUnicodeMarkers(line); !ok {
		t.Fatalf("the block message still carries the unrenderable marker %q: %q", m, line)
	}
	if !strings.HasPrefix(line, asciiGlyphs.fail+" refused at the install path") {
		t.Fatalf("block message lost its marker or its wording: %q", line)
	}
	// The MARKER itself — the load-bearing character — must be 7-bit ASCII.
	if !asciiOnly(asciiGlyphs.fail) {
		t.Fatalf("fallback block marker %q is not ASCII", asciiGlyphs.fail)
	}
	// This ONE line is held to a stricter bar than the rest of the CLI: fully
	// 7-bit, em dash included. Elsewhere a boxed prose dash is merely ugly, but
	// the refusal is the only output some users will ever read closely, and it
	// must not contain a single character a CP437 console cannot render. The
	// general em-dash sweep is separate; this assertion pins the headline.
	if !asciiOnly(line) {
		t.Fatalf("the block message is not fully ASCII in fallback mode: %q", line)
	}

	// And the Unicode default is preserved byte-for-byte for everyone else.
	forceUnicodeConsole(t)
	if want := "✗ refused at the install path — nothing was installed"; guardRefusalLine(glyphs()) != want {
		t.Fatalf("Unicode block message changed:\n got %q\nwant %q", guardRefusalLine(glyphs()), want)
	}
}

// The per-verdict "blocked" line carries the same marker and the same
// obligation: never suppressed by --quiet, and it must survive a codepage that
// cannot encode ✗.
func TestPrintGuardVerdicts_BlockLineASCIIInFallbackMode(t *testing.T) {
	forceASCIIGlyphs(t)
	// Keep ANSI out of the captured bytes so the assertion is about glyphs.
	t.Setenv("NO_COLOR", "1")

	var out bytes.Buffer
	printGuardVerdicts(&out, "chainsaw", []guardVerdict{{
		Spec:     packageSpec{Ecosystem: "npm", Name: "evil-pkg", Version: "1.0.0"},
		Block:    true,
		Severity: "malicious",
		Reason:   "known malware",
	}}, true /* isQuiet — a block is never chatter */)

	got := out.String()
	if m, ok := noUnicodeMarkers(got); !ok {
		t.Fatalf("guard block verdict still carries the unrenderable marker %q; got %q", m, got)
	}
	if !strings.Contains(got, asciiGlyphs.fail+" blocked") {
		t.Fatalf("block verdict lost its marker: %q", got)
	}
	if !strings.Contains(got, "evil-pkg") || !strings.Contains(got, "known malware") {
		t.Fatalf("block verdict lost its substance: %q", got)
	}
}

// ── doctor --offline (doctor_offline.go) ───────────────────────────────────

// runDoctorOfflineText renders the command into a string.
func runDoctorOfflineText(t *testing.T) string {
	t.Helper()
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := runDoctorOffline(cmd, nil); err != nil {
		t.Fatalf("runDoctorOffline: %v", err)
	}
	return out.String()
}

// statusColumn extracts the STATUS cell of every provider row. The header is
// "PROVIDER CATEGORY STATUS DETAIL" and tabwriter pads with spaces, so
// splitting on whitespace and taking field 3 is exact for these rows (provider
// names and categories never contain spaces).
func statusColumn(t *testing.T, text string) []string {
	t.Helper()
	categories := map[string]bool{"local": true, "refreshable": true, "remote-only": true}
	var got []string
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		// Match on the CATEGORY being field 2 exactly, not on the line merely
		// containing the word: the header's "(not loaded — refreshable
		// providers will run with empty data)" also mentions a category.
		if len(f) < 4 || !categories[f[1]] {
			continue
		}
		got = append(got, f[2])
	}
	if len(got) == 0 {
		t.Fatalf("no provider rows parsed out of:\n%s", text)
	}
	return got
}

// The point of the whole fix, asserted end-to-end: in ASCII mode the 25-row
// matrix must still tell its states apart. Under fail-open the table exercises
// ok / no-coverage / fail / info simultaneously.
func TestDoctorOffline_StatesRemainDistinguishableInASCII(t *testing.T) {
	forceASCIIGlyphs(t)
	t.Setenv("CHAINSAW_OFFLINE_FAIL_MODE", "open")

	text := runDoctorOfflineText(t)

	// Not one Unicode marker survives anywhere in the rendered command —
	// header note, 25 matrix rows, and legend alike.
	for _, line := range strings.Split(text, "\n") {
		if m, ok := noUnicodeMarkers(line); !ok {
			t.Errorf("unrenderable marker %q survived in fallback mode: %q", m, line)
		}
	}

	statuses := statusColumn(t, text)

	// Every rendered marker is a single ASCII rune drawn from the fallback set.
	valid := map[string]bool{
		asciiGlyphs.ok: true, asciiGlyphs.fail: true, asciiGlyphs.warn: true,
		asciiGlyphs.refresh: true, asciiGlyphs.none: true, asciiGlyphs.info: true,
	}
	distinct := map[string]int{}
	for _, s := range statuses {
		if !valid[s] {
			t.Errorf("STATUS cell %q is not a fallback-set marker", s)
		}
		distinct[s]++
	}

	// The regression this guards is STATE COLLAPSE: on CP437 every marker
	// became the same box, so a 25-row diagnostic said exactly one thing. At
	// least three states must remain separable under fail-open.
	if len(distinct) < 3 {
		t.Fatalf("fallback matrix collapsed to %d distinct state(s) %v — the states must stay separable:\n%s",
			len(distinct), distinct, text)
	}
	// Specifically: "runs offline" and "no coverage" must never coincide. One
	// says the signal protects you; the other says it does nothing.
	if asciiGlyphs.ok == asciiGlyphs.none {
		t.Fatal("ok and no-coverage markers are identical — the fallback reintroduces the bug")
	}
	if distinct[asciiGlyphs.ok] == 0 || distinct[asciiGlyphs.none] == 0 || distinct[asciiGlyphs.info] == 0 {
		t.Errorf("expected ok, no-coverage and info rows under fail-open; saw %v", distinct)
	}
}

// The legend must speak the same alphabet the table just used. It was a
// hard-coded Unicode string, so in fallback mode it would have described
// markers that appear nowhere in the output.
func TestDoctorOffline_LegendMatchesRenderedAlphabet(t *testing.T) {
	forceASCIIGlyphs(t)
	t.Setenv("CHAINSAW_OFFLINE_FAIL_MODE", "open")

	text := runDoctorOfflineText(t)

	var legend string
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "Legend:") {
			legend = line
		}
	}
	if legend == "" {
		t.Fatalf("no legend line in:\n%s", text)
	}
	if m, ok := noUnicodeMarkers(legend); !ok {
		t.Fatalf("legend still carries the unrenderable marker %q in fallback mode: %q", m, legend)
	}
	for _, pair := range []struct{ marker, phrase string }{
		{asciiGlyphs.ok, "runs offline"},
		{asciiGlyphs.refresh, "refresh recommended"},
		{asciiGlyphs.none, "no coverage"},
		{asciiGlyphs.warn, "degraded"},
		{asciiGlyphs.fail, "requires bundle refresh"},
		{asciiGlyphs.info, "informational"},
	} {
		if !strings.Contains(legend, pair.marker+" "+pair.phrase) {
			t.Errorf("legend missing %q %s; got %q", pair.marker, pair.phrase, legend)
		}
	}
}

// The default path is unchanged for the overwhelming majority of users: a
// UTF-8 terminal still gets the exact Unicode legend it always got.
func TestDoctorOffline_UnicodeLegendUnchangedByDefault(t *testing.T) {
	forceUnicodeConsole(t)
	t.Setenv("CHAINSAW_OFFLINE_FAIL_MODE", "open")

	text := runDoctorOfflineText(t)
	const want = "Legend:  ✓ runs offline   ↻ refresh recommended   ○ no coverage (signal off, installs allowed)   ⚠ degraded   ✗ requires bundle refresh   ℹ informational (not graded — see detail)"
	if !strings.Contains(text, want) {
		t.Fatalf("default Unicode legend changed; want it to contain:\n%s\ngot:\n%s", want, text)
	}
}

// ── chainsaw features (features.go) ────────────────────────────────────────

// The reported symptom: two capability rows rendered IDENTICALLY on a CP437
// console even though --json reported one active and one inactive, so a
// Windows user could not tell which capabilities were on.
func TestFeatures_ActiveAndInactiveMarkersDifferInASCII(t *testing.T) {
	forceASCIIGlyphs(t)

	cmd := &cobra.Command{RunE: runFeatures}
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("format", "", "")
	cmd.Flags().String("output", "", "")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(nil)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("features: %v", err)
	}

	text := out.String()
	if !strings.Contains(text, "Local capabilities") {
		t.Fatalf("features output missing the local section:\n%s", text)
	}

	// Collect the marker of every local-capability row. Whatever the local
	// build reports, no row may carry a non-ASCII marker in fallback mode.
	var markers []string
	inLocal := false
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(line, "Local capabilities") {
			inLocal = true
			continue
		}
		if inLocal && strings.TrimSpace(line) == "" {
			break
		}
		if inLocal {
			f := strings.Fields(line)
			if len(f) > 0 {
				markers = append(markers, f[0])
			}
		}
	}
	if len(markers) == 0 {
		t.Fatalf("no local capability rows parsed out of:\n%s", text)
	}
	for _, m := range markers {
		if m != asciiGlyphs.ok && m != asciiGlyphs.fail {
			t.Errorf("capability marker %q is not a fallback-set active/inactive marker", m)
		}
	}
	if asciiGlyphs.ok == asciiGlyphs.fail {
		t.Fatal("active and inactive markers are identical — this IS the reported bug")
	}
}

// ── the punctuation fields ─────────────────────────────────────────────────

// dash, ellipsis, arrow, bullet and the two tree connectors are not markers,
// so constraint 1 (exactly one rune) does not bind them — but constraint 2
// (pure ASCII) is the one that makes the fallback safe and it binds all of
// them. This pins each field's shape against the reasoning recorded beside it
// in output.go, so a later edit cannot quietly reintroduce a multi-byte
// "fallback" or unbalance the tree.
func TestGlyphSets_PunctuationFields(t *testing.T) {
	for name, s := range map[string]string{
		"dash": asciiGlyphs.dash, "ellipsis": asciiGlyphs.ellipsis,
		"arrow": asciiGlyphs.arrow, "bullet": asciiGlyphs.bullet,
		"treeTee": asciiGlyphs.treeTee, "treeEnd": asciiGlyphs.treeEnd,
	} {
		if s == "" {
			t.Errorf("fallback %s is empty — the character would silently vanish", name)
		}
		if !asciiOnly(s) {
			t.Errorf("fallback %s = %q is not 7-bit ASCII", name, s)
		}
	}
	// bullet is the one punctuation field that also occupies a MARKER slot
	// (the dim "telemetry off" line, printed directly opposite a green ok in
	// the consent prompt), so it inherits the single-rune rule.
	for setName, set := range map[string]glyphSet{"unicode": unicodeGlyphs, "ascii": asciiGlyphs} {
		if n := utf8.RuneCountInString(set.bullet); n != 1 {
			t.Errorf("%s set: bullet = %q is %d runes, want 1 (it doubles as a marker)", setName, set.bullet, n)
		}
	}
	// The tree connectors must be the SAME width in both sets, or every peer
	// line in `deps tree` would shift horizontally under the fallback and the
	// two branches would no longer line up with each other.
	for _, pair := range []struct{ name, u, a string }{
		{"treeTee", unicodeGlyphs.treeTee, asciiGlyphs.treeTee},
		{"treeEnd", unicodeGlyphs.treeEnd, asciiGlyphs.treeEnd},
	} {
		if utf8.RuneCountInString(pair.u) != utf8.RuneCountInString(pair.a) {
			t.Errorf("%s: unicode %q is %d runes but ascii %q is %d — the tree would re-indent",
				pair.name, pair.u, utf8.RuneCountInString(pair.u), pair.a, utf8.RuneCountInString(pair.a))
		}
	}
	if unicodeGlyphs.treeTee == unicodeGlyphs.treeEnd || asciiGlyphs.treeTee == asciiGlyphs.treeEnd {
		t.Error("the branch and last-branch connectors are identical — the tree loses its shape")
	}
}

// ── the pure renderers ─────────────────────────────────────────────────────

// Every status string these files build is produced by a pure glyphSet ->
// string function, precisely so both alphabets can be rendered in one test
// without touching process state. Each row pins TWO properties at once:
//
//   - the ASCII rendering is 7-bit, which is the fix; and
//   - the Unicode rendering is byte-for-byte what shipped before, which is
//     the promise to the 99% of users who were never affected. That second
//     half is why the table carries literal expected strings rather than
//     something computed from unicodeGlyphs — a computed expectation would
//     happily follow a typo in the glyph set itself.
func TestGlyphRenderers_ASCIIFallbackAndUnicodeUnchanged(t *testing.T) {
	cases := []struct {
		name        string
		render      func(glyphSet) string
		wantUnicode string
	}{
		// bundle.go — bundleVerificationStatus. Reached by BOTH `bundle
		// verify` and `doctor --offline`; the offline matrix was already
		// ASCII-aware, so this shared helper was the one row of that table
		// still emitting a boxed marker.
		{"bundle/skipped", func(g glyphSet) string {
			s, txt := bundleVerificationStatus(g, false, false)
			return s + " " + txt
		}, "⚠ skipped — signature not checked (CHAINSAW_INTEL_BUNDLE_SKIP_VERIFY=1)"},
		{"bundle/integrity-only", func(g glyphSet) string {
			s, txt := bundleVerificationStatus(g, true, false)
			return s + " " + txt
		}, "✓ integrity only — digest-bound; authenticity not checked (run with --strict or set CHAINSAW_INTEL_BUNDLE_STRICT_VERIFY=1)"},
		{"bundle/authenticated", func(g glyphSet) string {
			s, txt := bundleVerificationStatus(g, true, true)
			return s + " " + txt
		}, "✓ authenticated — full Sigstore: Fulcio cert chain + Rekor inclusion + OIDC issuer + signer identity"},

		// pr_scan.go — the emoji trio. These deliberately do NOT collapse into
		// the shared markers on a capable console: a GitHub Actions log is
		// where they earn their keep.
		{"pr-scan/allow", func(g glyphSet) string { return prScanVerdictIcon(g, "allow") }, "✅"},
		{"pr-scan/warn", func(g glyphSet) string { return prScanVerdictIcon(g, "warn") }, "⚠️"},
		{"pr-scan/block", func(g glyphSet) string { return prScanVerdictIcon(g, "block") }, "🚫"},

		// doctor_upgrade.go — the console-aware replacement for
		// doctor.Severity.Mark(), which cannot be made console-aware in place
		// (core/cli imports core/doctor; the accessor would close a cycle).
		{"upgrade/ok", func(g glyphSet) string { return upgradeSeverityMark(g, doctor.SeverityOK) }, "✓"},
		{"upgrade/warn", func(g glyphSet) string { return upgradeSeverityMark(g, doctor.SeverityWarn) }, "⚠"},
		{"upgrade/breaking", func(g glyphSet) string { return upgradeSeverityMark(g, doctor.SeverityBreaking) }, "✗"},
		{"upgrade/unknown", func(g glyphSet) string { return upgradeSeverityMark(g, doctor.Severity(99)) }, "?"},

		// deps.go — tree connectors and the CVE annotation.
		{"deps/clean-peer", func(g glyphSet) string {
			return depsTreeLine(g, sbomComponent{Name: "left-pad", Version: "1.3.0"}, false)
		}, "├── left-pad@1.3.0"},
		{"deps/last-vulnerable-peer", func(g glyphSet) string {
			return depsTreeLine(g, sbomComponent{
				Name: "lodash", Version: "4.17.20",
				Properties: []sbomProperty{{Name: "chainsaw:vuln:cves", Value: "CVE-2021-23337"}},
			}, true)
		}, "└── lodash@4.17.20  ⚠  CVE-2021-23337"},
		{"deps/no-cve-suffix", func(g glyphSet) string { return "|" + depsCVESuffix(g, "") + "|" }, "||"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.render(unicodeGlyphs); got != tc.wantUnicode {
				t.Errorf("Unicode rendering changed — every UTF-8 terminal sees this:\n got %q\nwant %q", got, tc.wantUnicode)
			}
			got := tc.render(asciiGlyphs)
			if !asciiOnly(got) {
				t.Errorf("fallback rendering is not 7-bit ASCII: %q", got)
			}
			if got == "" {
				t.Error("fallback rendering is empty")
			}
		})
	}
}

// The verdict markers of a single command must stay mutually distinguishable
// in the fallback, or pr-scan's CI log reports every dependency the same way.
// This is the state-collapse regression, restated for the emoji surface.
func TestPRScanVerdictIcon_StatesStaySeparable(t *testing.T) {
	for setName, set := range map[string]glyphSet{"unicode": unicodeGlyphs, "ascii": asciiGlyphs} {
		seen := map[string]string{}
		for _, v := range []string{"allow", "warn", "block"} {
			icon := prScanVerdictIcon(set, v)
			if other, dup := seen[icon]; dup {
				t.Errorf("%s set: %q and %q both render as %q", setName, v, other, icon)
			}
			seen[icon] = v
		}
	}
}

// ── whole-command renderings ───────────────────────────────────────────────

// asciiOutputRenderers is the generalised assertion the pure-function table
// cannot make on its own: drive each command's REAL text path end to end and
// require that not one byte above 0x7F survives.
//
// WHAT IS IN SCOPE, and why the boundary is where it is. Every string here is
// the RENDERER'S OWN template — its markers, separators, headings and verdict
// lines. Data that merely flows through is deliberately excluded, and the
// fixtures below therefore supply ASCII-only data. That is not the test
// dodging the hard cases; it is the same distinction the product has to make.
// doctor.Finding.Message and prScanSignal.Reason are `json:"..."` payload:
// they are emitted verbatim into --json and into SARIF, so making them depend
// on the operator's console codepage would make a machine-readable artifact
// machine-DEPENDENT — a strictly worse bug than the one being fixed. Their
// punctuation is a copy question for whoever owns that wording, not a
// codepage question, and it is left alone here.
//
// Help text (Short, Long, flag usage) is excluded for a different reason:
// see TestDoctorOfflineFlagHelp_NamesTheRenderedAlphabet.
var asciiOutputRenderers = []struct {
	name   string
	render func(t *testing.T) string
}{
	{"pr-scan/entry-group", func(t *testing.T) string {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		prev := "4.17.20"
		printEntryGroup(cmd, "Upgraded dependencies", []prScanEntry{
			{Ecosystem: "npm", Name: "lodash", Version: "4.17.21", PreviousVersion: &prev, Verdict: "allow"},
			{Ecosystem: "npm", Name: "shady", Version: "0.0.1", Verdict: "warn",
				Signals: []prScanSignal{{ID: "typosquat", Severity: "warn", Reason: "close to lodash"}}},
			{Ecosystem: "pypi", Name: "evil", Version: "9.9.9", Verdict: "block",
				Signals: []prScanSignal{{ID: "malware", Severity: "block", Reason: "known malware"}}},
		})
		return out.String()
	}},
	{"doctor/upgrade-report", func(t *testing.T) string {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		printUpgradeReport(cmd, &doctor.Report{
			Version: "0.20.2", Platform: "windows/amd64",
			Findings: []doctor.Finding{
				{Check: "tls", Severity: doctor.SeverityOK, SeverityName: "ok", Message: "cert and key parse"},
				{Check: "flags", Severity: doctor.SeverityWarn, SeverityName: "warn", Message: "deprecated flag", Remediation: "drop it"},
				{Check: "schema", Severity: doctor.SeverityBreaking, SeverityName: "breaking", Message: "schema is newer than this binary", Remediation: "upgrade the binary"},
			},
		})
		return out.String()
	}},
	{"doctor/onboarding", func(t *testing.T) string {
		var out bytes.Buffer
		printDoctorOnboarding(&out, &doctorOnboardingState{
			Steps: map[string]bool{"client_created": true, "policy_applied": true},
		})
		return out.String()
	}},
	{"doctor/strict-report-inconclusive-egress", func(t *testing.T) string {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		printStrictReport(cmd, doctorStrictReport{
			DeviceID: "dev", User: "u", Platform: "windows/amd64", ChainsawVersion: "0.20.2",
			Ecosystems:           map[string]ecosystemState{"npm": {Status: "wired"}},
			DirectRegistryEgress: "unknown",
		}, 1)
		return out.String()
	}},
	{"doctor/path-warning", func(t *testing.T) string {
		// An empty PATH cannot contain the test binary's directory, so the
		// warning branch is the deterministic one.
		t.Setenv("PATH", "")
		return chainsawPathWarning()
	}},
	{"policy/preflight-table", func(t *testing.T) string {
		cmd := &cobra.Command{}
		var out bytes.Buffer
		cmd.SetOut(&out)
		printPreflightTable(cmd, []supportMatrixRowDTO{
			{Ecosystem: "npm", Conditions: map[string]string{"malware": "full"}},
			{Ecosystem: "cargo", Conditions: map[string]string{"malware": "none"}},
		}, []string{"malware"})
		return out.String()
	}},
	{"guard/post-block-nudge", func(t *testing.T) string {
		t.Setenv("CHAINSAW_NO_NUDGE", "0")
		t.Setenv("CI", "")
		return captureStderr(t, func() { nudgePostBlock(2, consentGranted) })
	}},
	{"guard/periodic-nudge", func(t *testing.T) string {
		t.Setenv("CHAINSAW_NO_NUDGE", "0")
		t.Setenv("CI", "")
		st := &guardState{InstallsChecked: periodicNudgeEveryNInstalls, Blocks: 3}
		return captureStderr(t, func() { maybePeriodicNudge(st, time.Now(), consentGranted) })
	}},
}

func TestCommandOutput_IsPureASCIIInFallbackMode(t *testing.T) {
	for _, tc := range asciiOutputRenderers {
		t.Run(tc.name, func(t *testing.T) {
			forceASCIIGlyphs(t)
			t.Setenv("NO_COLOR", "1") // keep ANSI bytes out of the assertion

			got := tc.render(t)
			if strings.TrimSpace(got) == "" {
				t.Fatal("renderer produced no output — the assertion below would pass vacuously")
			}
			for i := 0; i < len(got); i++ {
				if got[i] > 0x7f {
					// Report the offending RUNE, not the byte, or the message
					// is a hex value nobody can act on.
					r, _ := utf8.DecodeRuneInString(got[i:])
					t.Fatalf("byte %d is %q (U+%04X), outside 7-bit ASCII, in fallback output:\n%s", i, r, r, got)
				}
			}
		})
	}
}

// The other half of the guarantee, at the command level: turning the fallback
// OFF must leave every one of those renderings carrying its glyphs. The
// fallback is for a minority of consoles; it must cost the majority nothing.
func TestCommandOutput_UnicodeDefaultStillCarriesItsGlyphs(t *testing.T) {
	for _, tc := range asciiOutputRenderers {
		t.Run(tc.name, func(t *testing.T) {
			forceUnicodeConsole(t)
			t.Setenv("NO_COLOR", "1")
			if got := tc.render(t); asciiOnly(got) {
				// Every renderer in this table carries at least one non-ASCII
				// character on a capable console. If one stops doing so, the
				// ASCII assertion above has quietly become vacuous for it.
				t.Errorf("Unicode rendering is now pure ASCII — the fallback assertion for %q no longer proves anything:\n%s", tc.name, got)
			}
		})
	}
}

// ── the consent prompt (guard_nudge.go) ────────────────────────────────────

// The first-run consent prompt is a conversion surface and, for many users,
// the first thing Chainsaw ever prints. It carried seven non-ASCII characters
// — two ticks, three middle dots, two em dashes — so on a fresh Windows box
// the one screen that has to read as trustworthy read as mojibake instead.
func TestGuardConsentPrompt_ASCIIInFallbackMode(t *testing.T) {
	forceASCIIGlyphs(t)
	t.Setenv("NO_COLOR", "1")
	// Nothing may pre-empt the prompt: an env-level opt-out returns "declined"
	// before a single line is printed.
	for _, k := range []string{"CHAINSAW_TELEMETRY_DISABLED", "CHAINSAW_OFFLINE", "DO_NOT_TRACK"} {
		t.Setenv(k, "0")
	}
	prevStdin := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	t.Cleanup(func() { stdinIsTerminal = prevStdin })

	st := &guardState{}
	out := captureStderr(t, func() { ensureGuardConsent(st, true) })
	if !strings.Contains(out, "help improve malware detection") {
		t.Fatalf("the consent prompt did not render; got %q", out)
	}
	if !asciiOnly(out) {
		t.Fatalf("the consent prompt is not 7-bit ASCII in fallback mode:\n%s", out)
	}
	// It must still SAY something — a prompt stripped to punctuation would
	// pass an ASCII test and fail the user.
	for _, want := range []string{"Your clean installs are never sent", "chain305.com/legal/privacy"} {
		if !strings.Contains(out, want) {
			t.Errorf("consent prompt lost %q:\n%s", want, out)
		}
	}
}

// ── help text: the deliberate exception ────────────────────────────────────

// THE RULE APPLIED TO --help. Em dashes in Short, Long and flag usage are NOT
// swept. Help is documentation: multi-paragraph raw-string prose where a boxed
// dash mid-sentence is merely ugly and the sentence still reads, and
// converting it would mean breaking those literals into glyph concatenations
// — trading real source legibility for a cosmetic gain on a minority console.
// gen-cli-docs also renders these strings into the docs site, where they must
// not vary with the generating host's codepage.
//
// MARKERS inside help are the exception to the exception, and this is the one
// place they occur: doctor's --offline usage NAMES the exact three glyphs the
// matrix is about to print. Leave it hard-coded and a CP437 user is told to
// look for symbols that appear nowhere in the table they just ran — the same
// defect TestDoctorOffline_LegendMatchesRenderedAlphabet pins for the legend.
func TestDoctorOfflineFlagHelp_NamesTheRenderedAlphabet(t *testing.T) {
	// The usage string is built when the command is constructed, so build a
	// fresh command under each console.
	usage := func() string {
		f := newDoctorCmd().Flags().Lookup("offline")
		if f == nil {
			t.Fatal("doctor has no --offline flag")
		}
		return f.Usage
	}

	forceASCIIGlyphs(t)
	got := usage()
	for _, want := range []string{
		"(" + asciiGlyphs.ok + ")", "(" + asciiGlyphs.warn + ")", "(" + asciiGlyphs.fail + ")",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("--offline help does not name %s in fallback mode: %q", want, got)
		}
	}
	if m, ok := noUnicodeMarkers(got); !ok {
		t.Errorf("--offline help still advertises the unrenderable marker %q: %q", m, got)
	}

	forceUnicodeConsole(t)
	const wantUnicode = "Air-gap diagnostics (W4): walk every intelligence condition and report whether it runs offline (✓), is degraded (⚠), or requires a refreshed bundle (✗). Reads CHAINSAW_INTEL_BUNDLE_PATH and CHAINSAW_OFFLINE_FAIL_MODE."
	if got := usage(); got != wantUnicode {
		t.Errorf("default --offline help changed:\n got %q\nwant %q", got, wantUnicode)
	}
}

// ── strings that are BOTH payload and prose ────────────────────────────────

// serverFeatures.Error and statusReport.*.Error carry `json:"error"` AND are
// printed by the human renderer. Building them from glyphs() would make the
// JSON output depend on the terminal that produced it — a machine-readable
// artifact changing shape with the console is strictly worse than a boxed
// dash, so the payload keeps its Unicode form and the RENDERER folds instead.
//
// This pins both halves of that split: the fold is total on the console side,
// and a no-op when Unicode is available so the default path is untouched.
func TestFoldPunctuationForConsole(t *testing.T) {
	// The real string that exposed the gap: features/status print it, and it
	// also ships as JSON.
	const payload = "server URL not configured — run 'chainsaw setup' or 'chainsaw auth login'"

	t.Run("folds on a console that cannot encode it", func(t *testing.T) {
		forceASCIIGlyphs(t)
		got := foldPunctuationForConsole(payload)
		if !asciiOnly(got) {
			t.Errorf("fold left non-ASCII in a rendered payload: %q", got)
		}
		if !strings.Contains(got, asciiGlyphs.dash) {
			t.Errorf("fold dropped the separator instead of replacing it: %q", got)
		}
		// The words must survive — this is a punctuation swap, not a rewrite.
		if !strings.Contains(got, "server URL not configured") ||
			!strings.Contains(got, "chainsaw auth login") {
			t.Errorf("fold altered the message text: %q", got)
		}
	})

	t.Run("is a no-op on a capable console", func(t *testing.T) {
		forceUnicodeConsole(t)
		t.Setenv("CHAINSAW_NO_UNICODE", "0")
		if got := foldPunctuationForConsole(payload); got != payload {
			t.Errorf("fold must not touch output on a Unicode console:\n got %q\nwant %q", got, payload)
		}
	})

	t.Run("covers every punctuation field", func(t *testing.T) {
		forceASCIIGlyphs(t)
		in := unicodeGlyphs.dash + unicodeGlyphs.ellipsis +
			unicodeGlyphs.arrow + unicodeGlyphs.bullet
		if got := foldPunctuationForConsole(in); !asciiOnly(got) {
			t.Errorf("a punctuation field is missing from the replacer: %q", got)
		}
	})
}
