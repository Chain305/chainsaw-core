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

// Fatalf prints msg to stderr and exits 1.
func Fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

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
		if verbose(cmd) {
			fmt.Fprintf(os.Stderr, "chainsaw: cannot open --output %q (%v); writing results to stdout\n", path, err)
		}
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
// stderr). Flag beats env: --verbose wins, then CHAINSAW_VERBOSE. Mirrors the
// many existing os.Getenv("CHAINSAW_VERBOSE") gates so behaviour is consistent.
func verbose(cmd *cobra.Command) bool {
	if b, _ := cmd.Flags().GetBool("verbose"); b {
		return true
	}
	return viper.GetBool("verbose") || os.Getenv("CHAINSAW_VERBOSE") != ""
}

func printSuccess(w io.Writer, cmd *cobra.Command, msg string) {
	if noColor(cmd) {
		fmt.Fprintln(w, "OK: "+msg)
	} else {
		fmt.Fprintf(w, "%s✓%s %s\n", ansiGreen, ansiReset, msg)
	}
}

func printKV(w io.Writer, cmd *cobra.Command, key, value string) {
	if noColor(cmd) {
		fmt.Fprintf(w, "  %s: %s\n", key, value)
	} else {
		fmt.Fprintf(w, "  %s%s%s: %s\n", ansiBold, key, ansiReset, value)
	}
}
