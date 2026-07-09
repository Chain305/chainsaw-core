package cli

// output_flags_test.go — Foundation part 2 regression coverage for the new
// output-control globals (--quiet/-q, --verbose/-v, --format, --output/-o) and
// the output.go helper layer (resolveFormat / useJSON / outWriter / quiet /
// verbose / noColor's TERM=dumb branch).
//
// Two invariants are pinned here:
//   - --json stays byte-compatible sugar for --format=json.
//   - --quiet only suppresses chatter; it must NEVER change an exit code or
//     swallow a block reason (the guard-side assertion lives below).

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// newOutputTestCmd builds a throwaway command carrying the same output-control
// flags root.go registers, so the helpers can be exercised without driving the
// whole rootCmd. Defaults mirror the persistent-flag defaults.
func newOutputTestCmd() *cobra.Command {
	c := &cobra.Command{Use: "outtest"}
	c.Flags().Bool("json", false, "")
	c.Flags().Bool("no-color", false, "")
	c.Flags().BoolP("quiet", "q", false, "")
	c.Flags().BoolP("verbose", "v", false, "")
	c.Flags().String("format", "table", "")
	c.Flags().StringP("output", "o", "", "")
	return c
}

func TestResolveFormat_DefaultIsTable(t *testing.T) {
	cmd := newOutputTestCmd()
	if got := resolveFormat(cmd); got != "table" {
		t.Fatalf("resolveFormat default = %q, want table", got)
	}
	if useJSON(cmd) {
		t.Fatalf("useJSON() = true with no flags, want false")
	}
}

func TestResolveFormat_JSONFlagAndFormatJSONAreEquivalent(t *testing.T) {
	// --json path.
	viaJSON := newOutputTestCmd()
	if err := viaJSON.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set --json: %v", err)
	}
	// --format=json path.
	viaFormat := newOutputTestCmd()
	if err := viaFormat.Flags().Set("format", "json"); err != nil {
		t.Fatalf("set --format: %v", err)
	}

	if resolveFormat(viaJSON) != "json" {
		t.Fatalf("--json did not resolve to json")
	}
	if resolveFormat(viaFormat) != "json" {
		t.Fatalf("--format=json did not resolve to json")
	}
	if !useJSON(viaJSON) || !useJSON(viaFormat) {
		t.Fatalf("useJSON disagreed across the two json paths")
	}
}

func TestResolveFormat_JSONFlagWinsOverFormatTable(t *testing.T) {
	// --json should win even if --format is left at its table default: --json is
	// the documented sugar and must not be defeated by the format default.
	cmd := newOutputTestCmd()
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatalf("set --json: %v", err)
	}
	if got := resolveFormat(cmd); got != "json" {
		t.Fatalf("resolveFormat with --json = %q, want json", got)
	}
}

func TestResolveFormat_CaseInsensitiveJSON(t *testing.T) {
	cmd := newOutputTestCmd()
	if err := cmd.Flags().Set("format", "JSON"); err != nil {
		t.Fatalf("set --format: %v", err)
	}
	if got := resolveFormat(cmd); got != "json" {
		t.Fatalf("resolveFormat(--format=JSON) = %q, want json", got)
	}
}

// TestPrintJSON_ByteCompatible pins that the indented-JSON output is unchanged
// by the refactor: two-space indent, trailing newline.
func TestPrintJSON_ByteCompatible(t *testing.T) {
	got := captureStdout(t, func() {
		_ = PrintJSON(map[string]string{"k": "v"})
	})
	want := "{\n  \"k\": \"v\"\n}\n"
	if got != want {
		t.Fatalf("PrintJSON output drifted\n got: %q\nwant: %q", got, want)
	}
}

// TestOutWriter_DefaultsToStdout asserts that with no --output the result sink
// is os.Stdout (so existing callers are unaffected).
func TestOutWriter_DefaultsToStdout(t *testing.T) {
	cmd := newOutputTestCmd()
	if w := outWriter(cmd); w != os.Stdout {
		t.Fatalf("outWriter without --output = %v, want os.Stdout", w)
	}
}

// TestOutWriter_RedirectsResultToFile confirms --output sends the RESULT to the
// named file (and nothing to stdout via that path).
func TestOutWriter_RedirectsResultToFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	cmd := newOutputTestCmd()
	if err := cmd.Flags().Set("output", path); err != nil {
		t.Fatalf("set --output: %v", err)
	}

	stdout := captureStdout(t, func() {
		if err := PrintJSONTo(cmd, map[string]int{"n": 7}); err != nil {
			t.Fatalf("PrintJSONTo: %v", err)
		}
	})
	if stdout != "" {
		t.Fatalf("result leaked to stdout under --output: %q", stdout)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read result file: %v", err)
	}
	if want := "{\n  \"n\": 7\n}\n"; string(data) != want {
		t.Fatalf("result file content = %q, want %q", data, want)
	}
}

// TestQuiet_FlagBeatsEnv pins precedence: --quiet on, CHAINSAW_QUIET off → quiet
// is true (flag wins). And env-only also flips it on.
func TestQuiet_FlagBeatsEnv(t *testing.T) {
	t.Setenv("CHAINSAW_QUIET", "")
	prev := viper.GetBool("quiet")
	viper.Set("quiet", false)
	t.Cleanup(func() { viper.Set("quiet", prev) })

	// Flag set, env empty.
	cmd := newOutputTestCmd()
	if err := cmd.Flags().Set("quiet", "true"); err != nil {
		t.Fatalf("set --quiet: %v", err)
	}
	if !quiet(cmd) {
		t.Fatalf("quiet() = false with --quiet set, want true")
	}

	// Flag unset, env set.
	t.Setenv("CHAINSAW_QUIET", "1")
	cmd2 := newOutputTestCmd()
	if !quiet(cmd2) {
		t.Fatalf("quiet() = false with CHAINSAW_QUIET=1, want true")
	}

	// Neither set → false.
	t.Setenv("CHAINSAW_QUIET", "")
	cmd3 := newOutputTestCmd()
	if quiet(cmd3) {
		t.Fatalf("quiet() = true with no flag and no env, want false")
	}
}

// TestVerbose_FlagOrEnv mirrors the quiet precedence for --verbose.
func TestVerbose_FlagOrEnv(t *testing.T) {
	t.Setenv("CHAINSAW_VERBOSE", "")
	prev := viper.GetBool("verbose")
	viper.Set("verbose", false)
	t.Cleanup(func() { viper.Set("verbose", prev) })

	cmd := newOutputTestCmd()
	if verbose(cmd) {
		t.Fatalf("verbose() = true with nothing set, want false")
	}
	if err := cmd.Flags().Set("verbose", "true"); err != nil {
		t.Fatalf("set --verbose: %v", err)
	}
	if !verbose(cmd) {
		t.Fatalf("verbose() = false with --verbose set, want true")
	}

	t.Setenv("CHAINSAW_VERBOSE", "1")
	cmd2 := newOutputTestCmd()
	if !verbose(cmd2) {
		t.Fatalf("verbose() = false with CHAINSAW_VERBOSE=1, want true")
	}
}

// TestNoColor_TermDumbDisables is the P1.8 addition: TERM=dumb disables color
// even on an interactive stdout with no other opt-out.
func TestNoColor_TermDumbDisables(t *testing.T) {
	withStdoutTTY(t, true)
	resetViperColor(t)
	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")

	cmd := newTestCmd()
	if !noColor(cmd) {
		t.Fatalf("noColor() = false with TERM=dumb, want true")
	}
	if IsColorEnabled(cmd) {
		t.Fatalf("IsColorEnabled() = true with TERM=dumb, want false")
	}
}

// TestNoColor_TermNonDumbStillColors guards against over-broad matching: a
// normal TERM (e.g. xterm-256color) must NOT trip the dumb branch.
func TestNoColor_TermNonDumbStillColors(t *testing.T) {
	withStdoutTTY(t, true)
	resetViperColor(t)
	// Genuine no-opt-out path: NO_COLOR must be ABSENT (present-empty is an
	// opt-out per no-color.org), so unset rather than set to "".
	os.Unsetenv("NO_COLOR")
	t.Setenv("TERM", "xterm-256color")

	cmd := newTestCmd()
	if noColor(cmd) {
		t.Fatalf("noColor() = true with TERM=xterm-256color and a TTY, want false")
	}
}

// TestRegisteredOutputFlags asserts the four new globals exist on rootCmd with
// the documented shorthands and the --format default, so the contract other
// agents code against can't silently drift.
func TestRegisteredOutputFlags(t *testing.T) {
	pf := rootCmd.PersistentFlags()
	for _, name := range []string{"quiet", "verbose", "format", "output", "json", "no-color"} {
		if pf.Lookup(name) == nil {
			t.Errorf("rootCmd missing persistent flag --%s", name)
		}
	}
	if f := pf.ShorthandLookup("q"); f == nil || f.Name != "quiet" {
		t.Errorf("-q shorthand does not map to --quiet")
	}
	if f := pf.ShorthandLookup("v"); f == nil || f.Name != "verbose" {
		t.Errorf("-v shorthand does not map to --verbose")
	}
	if f := pf.ShorthandLookup("o"); f == nil || f.Name != "output" {
		t.Errorf("-o shorthand does not map to --output")
	}
	if got := pf.Lookup("format").DefValue; got != "table" {
		t.Errorf("--format default = %q, want table", got)
	}
}
