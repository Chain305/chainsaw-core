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
	"unicode/utf8"

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
