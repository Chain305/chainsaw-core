package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

const (
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiReset  = "\033[0m"
)

// ansiSGRRe matches ANSI SGR (color/style) escape sequences like "\033[33m"
// and "\033[0m". Used to compute the on-screen display width of a cell that
// may carry color codes — tabwriter counts raw bytes, which inflates a
// colored cell's measured width by the length of the escape sequence and
// pushes every following column out of alignment.
var ansiSGRRe = regexp.MustCompile("\\x1b\\[[0-9;]*m")

// stripANSI removes ANSI SGR escape sequences, leaving the visible text.
func stripANSI(s string) string { return ansiSGRRe.ReplaceAllString(s, "") }

// sanitizeForTerminal neutralizes terminal control-sequence injection in an
// untrusted single-line field before it is echoed (package names and block
// reasons can originate from a crafted install arg or a lockfile). It drops
// every C0 control char (0x00–0x1F, which includes ESC — so no CSI/OSC/SGR
// escape can begin), DEL (0x7F), and every C1 control char (0x80–0x9F, some
// terminals treat these as single-byte CSI introducers). Printable text,
// including Unicode, is preserved; the residue of a stripped ESC (e.g. "[2J")
// is left as inert literal text. This is the security-grade counterpart to
// stripANSI, which only removes color codes.
func sanitizeForTerminal(s string) string {
	return strings.Map(func(r rune) rune {
		// RuneError catches invalid UTF-8 bytes — including a lone 0x9B, the raw
		// single-byte C1 CSI introducer an attacker could inject outside UTF-8.
		if r == utf8.RuneError || r < 0x20 || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			return -1 // drop
		}
		return r
	}, s)
}

// displayWidth returns the number of visible (printable) columns a string
// occupies once ANSI escape sequences are stripped. All current table cells
// are ASCII, so this equals len() on the stripped string, but counting runes
// keeps it correct for any future non-ASCII content.
func displayWidth(s string) int { return utf8.RuneCountInString(stripANSI(s)) }

// stdoutIsTerminal reports whether stdout is attached to a terminal. Overridable
// in tests; the production default inspects os.Stdout via x/term.
var stdoutIsTerminal = func() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// stderrIsTerminal reports whether stderr is attached to a terminal. The guard
// nudges are stderr-only, so their color gating checks stderr (not stdout).
// Overridable in tests.
var stderrIsTerminal = func() bool {
	return term.IsTerminal(int(os.Stderr.Fd()))
}

// PrintJSON writes v as indented JSON to stdout.
//
// Kept for callers that print JSON unconditionally without a *cobra.Command in
// hand. Command-aware callers should prefer PrintJSONTo(cmd, v) so the result
// honors --output (file redirection) and JSON purity stays intact.
func PrintJSON(v any) error {
	return encodeJSON(os.Stdout, v)
}

// PrintJSONTo writes v as indented JSON to the command's RESULT sink — a file
// when --output is set, else os.Stdout. This is the JSON-purity path: in json
// mode ONLY the JSON object reaches stdout, while logs/progress are emitted to
// stderr by the helpers below.
func PrintJSONTo(cmd *cobra.Command, v any) error {
	return encodeJSON(outWriter(cmd), v)
}

// encodeJSON is the shared indented-JSON encoder. Byte-compatible with the
// previous inline PrintJSON body (two-space indent, trailing newline from
// Encode) so existing --json output stays unchanged.
func encodeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// emitAndGate renders v in the resolved result format, then ALWAYS applies
// gate. Choosing a machine-readable format is a rendering decision; it must
// never weaken a verdict.
//
// This exists because four commands (scan-remote, bundle verify, admission
// soak clear, doctor) each grew the same bug independently: `if useJSON(cmd)
// { return PrintJSONTo(cmd, v) }` returns BEFORE the exit-code gate, so
// adding --json to a CI invocation silently turned a failing gate green.
// Four structural properties make that class unreintroducible here:
//
//  1. gate is the LAST statement and is reached on every non-error path.
//     There is no `return` between rendering and gating to re-introduce.
//  2. gate returns an error — it never calls os.Exit. Three of the four
//     original sites exited directly, which also skipped telemetry flush
//     and the update notice in Execute().
//  3. A RENDER error aborts before the gate. An unwritable --output file is
//     an operational failure and must surface as one; emitting a verdict
//     computed against a result nobody received would be worse than either
//     outcome alone.
//  4. The gate PREDICATE stays at the call site. Every command's verdict
//     differs (critical/high counts, attestation presence, Cleared, check
//     outcomes) — this centralizes the SHAPE, not the predicate.
//
// human may be nil (nothing to print outside JSON mode); gate may be nil
// (the command has no verdict).
func emitAndGate(cmd *cobra.Command, v any, human func() error, gate func() error) error {
	if useJSON(cmd) {
		if err := PrintJSONTo(cmd, v); err != nil {
			return err
		}
	} else if human != nil {
		if err := human(); err != nil {
			return err
		}
	}
	if gate == nil {
		return nil
	}
	return gate()
}

// PrintTable writes a plain-text table with aligned columns to stdout.
// headers and each row must have the same length.
//
// Columns are left-justified and separated by a 2-space gutter, with the
// header row underlined by a dashed separator. Alignment is computed on each
// cell's display width (ANSI escape sequences stripped), so a colorized cell
// stays aligned with its plain neighbours — text/tabwriter measured raw bytes
// and silently broke alignment for any cell carrying color codes. Plain
// (no-ANSI) input produces the same layout as before.
func PrintTable(headers []string, rows [][]string) {
	sep := make([]string, len(headers))
	for i, h := range headers {
		sep[i] = strings.Repeat("-", len(h))
	}

	// Compute the max display width per column across the header, the dashed
	// separator, and every data row.
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = displayWidth(h)
		if w := displayWidth(sep[i]); w > widths[i] {
			widths[i] = w
		}
	}
	for _, row := range rows {
		for i, cell := range row {
			if i >= len(widths) {
				break
			}
			if w := displayWidth(cell); w > widths[i] {
				widths[i] = w
			}
		}
	}

	printRow := func(cells []string) {
		var b strings.Builder
		for i, cell := range cells {
			b.WriteString(cell)
			// Left-justify by padding to the column width; the last column
			// is never padded (matching tabwriter's trailing behaviour).
			if i < len(cells)-1 {
				if pad := widths[i] - displayWidth(cell); pad > 0 {
					b.WriteString(strings.Repeat(" ", pad))
				}
				b.WriteString("  ")
			}
		}
		b.WriteByte('\n')
		fmt.Fprint(os.Stdout, b.String())
	}

	printRow(headers)
	printRow(sep)
	for _, row := range rows {
		printRow(row)
	}
}

// R13 — the exported Fatalf was DELETED here, deliberately.
//
// It printed "error: …" to stderr and called os.Exit(1). exitcodes.go
// reserves 1 for ExitBlocked, "the EXPECTED enforcement outcome", so any
// future caller would have made a CI block-gate (`if [ $? -eq 1 ]`) fire on
// a plain operational error — the exact confusion the 0–4 contract exists to
// prevent. It had zero callers repo-wide (verified before removal), so this
// is an unused-API removal, not a behaviour change; it is noted as such in
// the release notes because core/cli is a PUBLIC open-core module.
//
// Errors belong in a RunE return: Execute() classifies them and picks the
// right code. A command that needs a specific one returns &ExitCodeError{}.
//
// NOT changed, and not a defect: doctorExitDrift = 10 (doctor_strict.go) and
// the other >=10 constants. exitcodes.go explicitly reserves codes >=10 for
// per-command outcomes, so those live outside the shared block by design.

func noColor(cmd *cobra.Command) bool {
	b, _ := cmd.Flags().GetBool("no-color")
	// P1.8 — TERM=dumb is the conventional "this terminal cannot render escape
	// sequences" signal (emacs shell, dumb pipes, some CI shells). Treat it the
	// same as an explicit opt-out so we never emit ANSI into a stream that will
	// show it as garbage. The guard-side stderr color path (guardColorEnabled)
	// stays separate and untouched by design.
	// no-color.org: color is suppressed when NO_COLOR is PRESENT "regardless of
	// its value" — including the empty string. Use LookupEnv (presence), not a
	// non-empty value test, so `NO_COLOR=` also opts out.
	if _, noColorSet := os.LookupEnv("NO_COLOR"); b || viper.GetBool("no_color") || noColorSet || os.Getenv("TERM") == "dumb" {
		return true
	}
	return !stdoutIsTerminal()
}

// IsColorEnabled reports whether callers may emit ANSI escape sequences.
// Color is enabled only when the user hasn't opted out (via --no-color,
// viper's no_color, or the NO_COLOR env var) AND stdout is a terminal.
func IsColorEnabled(cmd *cobra.Command) bool {
	return !noColor(cmd)
}

// glyphSet is the CLI's status-marker vocabulary. Every human-facing status
// marker must come from here rather than a string literal, so a terminal that
// cannot render the Unicode set degrades to a legible ASCII one instead of a
// column of identical replacement boxes.
//
// WHY THIS EXISTS. The Unicode markers we print — ✓ U+2713, ✗ U+2717,
// ↻ U+21BB, ⚠ U+26A0, ℹ U+2139 — are NOT in CP437, the legacy Windows console
// codepage. A console still on CP437 renders each of them as the same
// replacement box, so `chainsaw features` showed two capability rows as
// visually IDENTICAL when one was active and one was not, and the
// `doctor --offline` matrix collapsed five distinct states into one. ○ U+25CB
// IS in CP437 (0x09) and rendered correctly, which is what pinned the
// diagnosis: a tester's screenshot boxed every marker EXCEPT ○.
//
// This is a CODEPAGE problem, not a color problem. ansi_windows.go enables
// ENABLE_VIRTUAL_TERMINAL_PROCESSING, which makes ANSI ESCAPES work and does
// nothing whatsoever for glyph encoding; and NO_COLOR / TERM=dumb still
// emitted the full Unicode legend. Hence a predicate of its own
// (unicodeEnabled) rather than a branch off noColor — a user can legitimately
// want color without Unicode, and vice versa.
type glyphSet struct {
	ok      string // success / present / runs offline
	fail    string // refusal / blocked / absent
	warn    string // degraded, still running
	refresh string // stale, refresh recommended
	none    string // inert: no coverage at all
	info    string // reported, deliberately not graded

	// ── punctuation ────────────────────────────────────────────────────────
	//
	// These are not markers; they are the non-ASCII punctuation the CLI prints
	// inside prose. Each is absent from CP437 (unlike ○, and unlike the box
	// drawing below), so each boxes on a legacy console.
	//
	// The original set carried `dash` alone and scoped it BY COMMENT to
	// guardRefusalLine, on the reasoning that a boxed dash mid-sentence merely
	// looks wrong while a boxed marker destroys information. That severity
	// ordering still holds — it is why markers came first — but it was an
	// argument for SEQUENCING the work, not for stopping. The scoping comment
	// is therefore gone: dash is now the general separator for printed status
	// prose. The line it must NOT be used on is drawn elsewhere (see the
	// package rule recorded in glyphs_test.go): never in `Short`/`Long`/flag
	// help, and never in a string that is also JSON or SARIF payload.
	dash     string // em dash: clause separator in status prose
	ellipsis string // "work in progress" suffix on a chatter line
	arrow    string // "go here next": CTA and transition prose
	bullet   string // dim separator, and the inert twin of ok in the consent prompt

	// ── tree drawing ───────────────────────────────────────────────────────
	//
	// `deps tree` connectors. These are the one part of this set that is NOT
	// broken on CP437: U+2500/U+251C/U+2514 are codepage 437's own box-drawing
	// range (0xC4/0xC3/0xC0) and render correctly there. They are carried
	// anyway so the fallback's guarantee can be stated without an exception
	// list — "no byte above 0x7F" is a property a test can enforce forever,
	// whereas "no byte above 0x7F except the six that happen to survive CP437"
	// is a property that rots the first time someone adds a seventh. The ASCII
	// forms are `tree -A`'s, which is the convention users already know.
	treeTee string // a peer with siblings after it
	treeEnd string // the last peer
}

// foldPunctuationForConsole rewrites the non-ASCII punctuation in an ALREADY
// BUILT string to the current console's alphabet.
//
// It exists for the one case the field-by-field approach above cannot reach:
// a string that is simultaneously JSON payload and human output. serverFeatures
// .Error and statusReport.Auth.Error are both — they carry `json:"error"` AND
// are printed by the human renderer. Building them from glyphs() would make the
// JSON codepage-dependent, which is strictly worse than a boxed dash: a
// machine-readable artifact must not change shape with the terminal that
// happened to produce it.
//
// So the payload keeps its Unicode form and the RENDERER folds. Presentation is
// the only layer that knows about the console, which is where a console
// decision belongs. Callers apply this at the Fprintf, never at assignment.
//
// No-op when Unicode is enabled, so the default path is byte-for-byte unchanged.
func foldPunctuationForConsole(s string) string {
	if unicodeEnabled() {
		return s
	}
	g := asciiGlyphs
	return strings.NewReplacer(
		unicodeGlyphs.dash, g.dash,
		unicodeGlyphs.ellipsis, g.ellipsis,
		unicodeGlyphs.arrow, g.arrow,
		unicodeGlyphs.bullet, g.bullet,
	).Replace(s)
}

// unicodeGlyphs is the default set — unchanged from the literals these
// replaced, so every existing terminal renders byte-for-byte what it did
// before.
var unicodeGlyphs = glyphSet{
	ok:      "✓",
	fail:    "✗",
	warn:    "⚠",
	refresh: "↻",
	none:    "○",
	info:    "ℹ",

	dash:     "—",
	ellipsis: "…",
	arrow:    "→",
	bullet:   "·",

	treeTee: "├──",
	treeEnd: "└──",
}

// asciiGlyphs is the fallback. Three constraints drove the choices:
//
//  1. EVERY marker is exactly ONE rune AND one byte. The doctor --offline
//     matrix is a 25-row tabwriter table and PrintTable measures display width
//     in runes, so a same-width swap keeps every column aligned in both modes.
//     Multi-character markers ("[OK]", "OK", "WARN") would have re-flowed the
//     STATUS column and, worse, re-flowed it by a DIFFERENT amount per row.
//  2. Pure ASCII (0x20–0x7E), which is present in CP437, CP850, CP1252, every
//     other OEM codepage, and UTF-8 alike — so the fallback cannot itself
//     become an unrenderable glyph on some codepage we did not anticipate.
//  3. Mutually distinguishable at a glance and semantically suggestive:
//     + present, X refused, ! degraded-but-running, ~ stale/approximate,
//     - inert/nothing there, i informational. X is upper-case deliberately:
//     it is the block marker, it leads the product's headline refusal line
//     ("X refused at the install path"), and a lower-case x there reads as
//     the first letter of a word rather than as a mark.
var asciiGlyphs = glyphSet{
	ok:      "+",
	fail:    "X",
	warn:    "!",
	refresh: "~",
	none:    "-",
	info:    "i",

	// The punctuation fields are NOT bound by constraint 1. That rule exists
	// because the markers sit in a column-aligned table; the em dash, the
	// ellipsis and the arrow appear mid-sentence in free-flowing prose where
	// nothing is measured, so the legible ASCII spelling wins over a
	// same-width one. Each is still pure ASCII (constraint 2), which is the
	// constraint that actually makes the fallback safe.
	//
	// Two hyphens for dash, not one: a lone "-" is already the `none` marker,
	// and the refusal line would otherwise read "X refused ... - nothing was
	// installed", where the separator is indistinguishable from a status glyph.
	dash:     "--",
	ellipsis: "...",
	arrow:    "->",
	// bullet, by contrast, IS held to one rune: it is the only punctuation
	// field that also occupies a marker slot (the dim "telemetry off" line in
	// the consent prompt, printed directly opposite a green ok). Its collision
	// with `none` is deliberate rather than tolerated — in that slot "nothing
	// is being sent" is precisely what `none` means — and in its other, purely
	// decorative use a hyphen separates two clauses without being mistaken for
	// the pipe that already appears in "telemetry on|off".
	bullet: "-",

	// Three runes in BOTH sets, so `deps tree` indents identically either way
	// and a peer line never shifts under the fallback. These are `tree -A`'s
	// connectors.
	treeTee: "|--",
	treeEnd: "`--",
}

// glyphs returns the status-marker set appropriate for the current terminal.
//
// Deliberately takes no *cobra.Command: the guard wrappers run with
// DisableFlagParsing and have no bound flag set to consult, and this decision
// is a property of the CONSOLE, not of the invocation. Cheap enough to call
// per line, but call sites hoist it out of loops out of habit.
func glyphs() glyphSet {
	if unicodeEnabled() {
		return unicodeGlyphs
	}
	return asciiGlyphs
}

// unicodeEnabled reports whether the terminal can render the Unicode glyph set.
//
// False when either:
//   - CHAINSAW_NO_UNICODE is set to anything but an explicit falsey value, or
//   - the platform probe says the console cannot encode them (on Windows: the
//     console output codepage is not 65001/UTF-8; everywhere else: always
//     capable, since modern Unix terminals are UTF-8).
//
// The env var is checked as "set, unless explicitly turned off" rather than as
// bare presence. R7 (see verboseEnabled) recorded that presence tests on
// CHAINSAW_* vars make `FOO=0` mean ON, the opposite of what an operator
// writing =0 intends. NO_COLOR's presence-only rule is a cross-vendor spec for
// a var we do not own; this is our own var, so it follows our own convention.
// Note that CHAINSAW_NO_UNICODE=0 does not FORCE Unicode on — it only declines
// to be the reason it is off; the console probe still has the final say.
func unicodeEnabled() bool {
	if v, ok := os.LookupEnv("CHAINSAW_NO_UNICODE"); ok && !envFalsey(v) {
		return false
	}
	return consoleSupportsUnicode()
}

// envFalsey reports whether v is an explicit "off". Mirrors envTruthy's
// vocabulary (guard_nudge.go) from the other side.
func envFalsey(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no", "off":
		return true
	}
	return false
}

// consoleSupportsUnicode probes the platform for glyph-encoding capability.
// It is a var, not a plain func, for exactly one reason: the failure it guards
// is Windows-only, and a bug that can only be tested on a runner we do not
// have is a bug that stops being tested. Overriding this in a test reproduces
// a CP437 console on macOS/Linux, so the ASCII path is exercised on every CI
// run rather than never. See unicode_windows.go / unicode_other.go for the
// real probes.
var consoleSupportsUnicode = func() bool { return nativeConsoleSupportsUnicode() }

// resolveFormat returns the active result format, honoring --format with --json
// as sugar for "json". Precedence: an explicit --json (or --format=json) wins
// and yields "json"; otherwise the --format value is returned (defaulting to
// "table"). Unknown --format values are returned verbatim so callers can decide
// how strict to be — the only special-cased value is "json".
func resolveFormat(cmd *cobra.Command) string {
	if j, _ := cmd.Flags().GetBool("json"); j {
		return "json"
	}
	f, _ := cmd.Flags().GetString("format")
	if strings.EqualFold(f, "json") {
		return "json"
	}
	if f == "" {
		return "table"
	}
	return f
}

// useJSON reports whether the resolved result format is JSON. Existing callers
// that only ever set --json keep working unchanged; callers that pass
// --format=json now also get JSON output.
func useJSON(cmd *cobra.Command) bool {
	return resolveFormat(cmd) == "json"
}

// outWriter returns the RESULT sink for a command: the file named by --output
// when set, else os.Stdout. RESULTS ONLY — logs, progress, and diagnostics
// belong on stderr regardless of --output, so a redirected result file stays
// machine-parseable. If --output is set but the file can't be opened we fall
// back to os.Stdout (the result is never silently dropped); the open error is
// surfaced on stderr only under --verbose to avoid polluting normal runs.
func outWriter(cmd *cobra.Command) io.Writer {
	return outWriterOr(cmd, os.Stdout)
}

// outWriterOr is outWriter with an explicit fallback sink for the no-`--output`
// case. Most result-printing paths want os.Stdout (via outWriter); the
// command-writer-aware helpers (writeJSON) pass cmd.OutOrStdout() so cobra's
// SetOut redirection is honored. Both honor --output identically: the file wins
// when set.
func outWriterOr(cmd *cobra.Command, fallback io.Writer) io.Writer {
	path, _ := cmd.Flags().GetString("output")
	if path == "" {
		return fallback
	}
	f, err := os.Create(path)
	if err != nil {
		// R4: this warning used to be gated on --verbose, so
		// `chainsaw status --json -o /nonexistent-dir/x` exited 0 with NO
		// indication at all that the file the user asked for was never
		// created. "The path you named is unwritable" is not diagnostic
		// chatter; it is the outcome of an explicit instruction. Always
		// print it — on stderr, so a redirected result stays parseable.
		fmt.Fprintf(os.Stderr, "chainsaw: cannot open --output %q (%v); writing results to stdout\n", path, err)
		return fallback
	}
	return f
}

// quiet reports whether chatter/progress should be suppressed. Flag beats env:
// --quiet (plumbed through viper via BindPFlag) wins, then CHAINSAW_QUIET.
// INVARIANT: quiet only gates chatter — it must NEVER suppress a block reason
// or change an exit code.
func quiet(cmd *cobra.Command) bool {
	if b, _ := cmd.Flags().GetBool("quiet"); b {
		return true
	}
	return viper.GetBool("quiet") || envTruthy(os.Getenv("CHAINSAW_QUIET"))
}

// verbose reports whether extra diagnostic detail should be emitted (to
// stderr). Flag beats env: --verbose wins, then CHAINSAW_VERBOSE.
func verbose(cmd *cobra.Command) bool {
	if b, _ := cmd.Flags().GetBool("verbose"); b {
		return true
	}
	return verboseEnabled()
}

// verboseEnabled is the command-less form of verbose(), for the support
// diagnostics that run outside a cobra RunE (initConfig, the keychain
// migration, the legacy-config move).
//
// R7: those five sites tested `os.Getenv("CHAINSAW_VERBOSE") != ""`, which
// had two consequences. (a) The --verbose FLAG could not reach them at all,
// leaving the flag with exactly one observable behaviour in the whole CLI —
// so `chainsaw --verbose --token X status` stayed silent while
// `CHAINSAW_VERBOSE=1 chainsaw --token X status` printed the diagnostic.
// (b) It is a PRESENCE test, so `CHAINSAW_VERBOSE=0` and
// `CHAINSAW_VERBOSE=false` both ENABLED verbose — the opposite of what an
// operator writing =0 means.
//
// viper.GetBool("verbose") covers the flag (BindPFlag), the config file,
// and the CHAINSAW_QUIET-style BindEnv; envTruthy re-reads the env var with
// the same 1/true/yes/on vocabulary the rest of the CLI uses, so =0 and
// =false correctly mean OFF.
func verboseEnabled() bool {
	return viper.GetBool("verbose") || envTruthy(os.Getenv("CHAINSAW_VERBOSE"))
}

// chatter writes a progress/status line to stderr unless --quiet (or
// CHAINSAW_QUIET) is in effect.
//
// R14: --quiet is documented as a global chatter switch but had two
// consumers outside the guard, so `chainsaw --quiet audit export …` still
// printed "Fetching audit events…". Route progress through here instead of
// a bare Fprintln so the flag means what it says.
//
// INVARIANT (guard_quiet_invariant_test.go): --quiet suppresses CHATTER
// only. A block verdict, the refusal summary, and the exit code are NEVER
// routed through this helper — they must print under --quiet.
func chatter(cmd *cobra.Command, format string, args ...any) {
	if cmd == nil || quiet(cmd) {
		return
	}
	if !strings.HasSuffix(format, "\n") {
		format += "\n"
	}
	fmt.Fprintf(cmd.ErrOrStderr(), format, args...)
}

// noColorFlagInArgs reports whether chainsaw's own --no-color global
// appears in argv before a guard subcommand.
//
// R6: the guard wrappers run with DisableFlagParsing, so cobra never parses
// (and therefore never binds) --no-color on that path. Mirrors
// quietFlagInArgs in guard_install.go, including its fail-safe scoping: the
// scan stops at the guard subcommand name or `--`, so a wrapped tool's own
// --no-color (`chainsaw npm install --no-color`) is NOT read as chainsaw's.
// Only the long form is matched — there is no short alias for --no-color,
// and claiming one from a wrapped tool's short bundle would be wrong.
func noColorFlagInArgs(argv []string) bool {
	guardSubcmds := map[string]bool{"npm": true, "pip": true, "go": true, "cargo": true, "gem": true}
	for i := 1; i < len(argv); i++ {
		tok := argv[i]
		if tok == "--" || guardSubcmds[tok] {
			return false
		}
		if tok == "--no-color" || tok == "--no-color=true" {
			return true
		}
	}
	return false
}

// printSuccess is the precedent this whole glyph mechanism generalizes: it
// already degraded to "OK: " when color was off. The remaining gap was the
// COLORED branch, whose ✓ was a literal — so a Windows console with VT
// processing on but a CP437 codepage (a real and common combination) got a
// green replacement box. The glyph now comes from glyphs(); the no-color
// branch is unchanged, since "OK: " is strictly clearer than any marker and
// several tests pin that exact prefix.
func printSuccess(w io.Writer, cmd *cobra.Command, msg string) {
	if noColor(cmd) {
		fmt.Fprintln(w, "OK: "+msg)
	} else {
		fmt.Fprintf(w, "%s%s%s %s\n", ansiGreen, glyphs().ok, ansiReset, msg)
	}
}

func printKV(w io.Writer, cmd *cobra.Command, key, value string) {
	if noColor(cmd) {
		fmt.Fprintf(w, "  %s: %s\n", key, value)
	} else {
		fmt.Fprintf(w, "  %s%s%s: %s\n", ansiBold, key, ansiReset, value)
	}
}
