package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// Note: the TTY-based disable branch (stdout not a terminal) is not covered
// here because it requires a real PTY to exercise reliably. All tests below
// force stdoutIsTerminal to true so the user-opt-out signals are isolated.

func newTestCmd() *cobra.Command {
	c := &cobra.Command{Use: "test"}
	c.Flags().Bool("no-color", false, "")
	return c
}

func withStdoutTTY(t *testing.T, isTTY bool) {
	t.Helper()
	prev := stdoutIsTerminal
	stdoutIsTerminal = func() bool { return isTTY }
	t.Cleanup(func() { stdoutIsTerminal = prev })
}

func resetViperColor(t *testing.T) {
	t.Helper()
	prev := viper.GetBool("no_color")
	viper.Set("no_color", false)
	t.Cleanup(func() { viper.Set("no_color", prev) })
}

func TestNoColor_EnvVarDisables(t *testing.T) {
	withStdoutTTY(t, true)
	resetViperColor(t)
	t.Setenv("NO_COLOR", "1")

	cmd := newTestCmd()
	if !noColor(cmd) {
		t.Fatalf("noColor() = false with NO_COLOR=1, want true")
	}
	if IsColorEnabled(cmd) {
		t.Fatalf("IsColorEnabled() = true with NO_COLOR=1, want false")
	}
}

func TestNoColor_FlagDisables(t *testing.T) {
	withStdoutTTY(t, true)
	resetViperColor(t)
	t.Setenv("NO_COLOR", "")

	cmd := newTestCmd()
	if err := cmd.Flags().Set("no-color", "true"); err != nil {
		t.Fatalf("set --no-color: %v", err)
	}
	if !noColor(cmd) {
		t.Fatalf("noColor() = false with --no-color, want true")
	}
	if IsColorEnabled(cmd) {
		t.Fatalf("IsColorEnabled() = true with --no-color, want false")
	}
}

func TestNoColor_ViperDisables(t *testing.T) {
	withStdoutTTY(t, true)
	resetViperColor(t)
	t.Setenv("NO_COLOR", "")

	viper.Set("no_color", true)
	cmd := newTestCmd()
	if !noColor(cmd) {
		t.Fatalf("noColor() = false with viper no_color=true, want true")
	}
	if IsColorEnabled(cmd) {
		t.Fatalf("IsColorEnabled() = true with viper no_color=true, want false")
	}
}

func TestIsColorEnabled_AllowsWhenTTYAndNoOptOut(t *testing.T) {
	withStdoutTTY(t, true)
	resetViperColor(t)
	// "No opt-out" means NO_COLOR is ABSENT. Per no-color.org, NO_COLOR present
	// with ANY value (including "") is an opt-out, so unset it here to exercise
	// the genuine no-opt-out path (the empty-string case is asserted separately
	// in TestIsColorEnabled_NoColorEmptyStringDisables).
	os.Unsetenv("NO_COLOR")

	cmd := newTestCmd()
	if !IsColorEnabled(cmd) {
		t.Fatalf("IsColorEnabled() = false on TTY with no opt-out, want true")
	}
}

// TestIsColorEnabled_NoColorEmptyStringDisables pins the no-color.org rule that
// NO_COLOR opts out when PRESENT regardless of value — NO_COLOR="" disables
// color even on a TTY.
func TestIsColorEnabled_NoColorEmptyStringDisables(t *testing.T) {
	withStdoutTTY(t, true)
	resetViperColor(t)
	t.Setenv("NO_COLOR", "")

	cmd := newTestCmd()
	if IsColorEnabled(cmd) {
		t.Fatalf("IsColorEnabled() = true with NO_COLOR=\"\" present, want false (no-color.org)")
	}
}

func TestStripANSI(t *testing.T) {
	cases := map[string]string{
		"\033[33mHIGH\033[0m":      "HIGH",
		"plain":                    "plain",
		"\033[1m\033[32mOK\033[0m": "OK",
		"":                         "",
	}
	for in, want := range cases {
		if got := stripANSI(in); got != want {
			t.Errorf("stripANSI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestDisplayWidth(t *testing.T) {
	if got := displayWidth("\033[33mHIGH\033[0m"); got != 4 {
		t.Errorf("displayWidth(colored HIGH) = %d, want 4", got)
	}
	if got := displayWidth("plain"); got != 5 {
		t.Errorf("displayWidth(plain) = %d, want 5", got)
	}
	if got := displayWidth(""); got != 0 {
		t.Errorf("displayWidth(empty) = %d, want 0", got)
	}
}

// TestPrintTable_PlainLayout pins the exact byte layout for plain (no-ANSI)
// input: left-justified columns, a 2-space gutter, header + dashed separator,
// and no trailing pad on the last column. This is the regression guard that
// the manual padding reproduces the old tabwriter output.
func TestPrintTable_PlainLayout(t *testing.T) {
	headers := []string{"NAME", "SEVERITY", "X"}
	rows := [][]string{
		{"left-pad", "HIGH", "1"},
		{"a", "LOW", "22"},
	}
	got := captureStdout(t, func() { PrintTable(headers, rows) })

	want := "NAME      SEVERITY  X\n" +
		"----      --------  -\n" +
		"left-pad  HIGH      1\n" +
		"a         LOW       22\n"
	if got != want {
		t.Fatalf("plain table layout mismatch\n got: %q\nwant: %q", got, want)
	}
}

// TestPrintTable_ColoredCellAligns asserts that a row whose cell carries ANSI
// color codes aligns identically to the same row in plain form — the bug was
// that tabwriter counted the escape bytes and shoved later columns right.
func TestPrintTable_ColoredCellAligns(t *testing.T) {
	headers := []string{"PKG", "VERDICT", "TAIL"}

	plain := captureStdout(t, func() {
		PrintTable(headers, [][]string{{"libfoo", "HIGH", "end"}})
	})
	colored := captureStdout(t, func() {
		PrintTable(headers, [][]string{{"libfoo", "\033[33mHIGH\033[0m", "end"}})
	})

	// Stripping ANSI from the colored output must yield byte-identical layout
	// to the plain output: same column positions, same gutter.
	if stripANSI(colored) != plain {
		t.Fatalf("colored table misaligned vs plain\nplain:   %q\ncolored: %q (stripped: %q)", plain, colored, stripANSI(colored))
	}
	// The TAIL column must start at the same offset in both renders.
	plainTail := strings.Index(plain, "end")
	coloredTail := strings.Index(stripANSI(colored), "end")
	if plainTail != coloredTail {
		t.Fatalf("TAIL column offset drifted: plain=%d colored=%d", plainTail, coloredTail)
	}
}

// TestPrintTable_EmptyRows confirms the header + separator still print when no
// data rows are supplied.
func TestPrintTable_EmptyRows(t *testing.T) {
	got := captureStdout(t, func() { PrintTable([]string{"A", "BB"}, nil) })
	want := "A  BB\n" +
		"-  --\n"
	if got != want {
		t.Fatalf("empty-rows table mismatch\n got: %q\nwant: %q", got, want)
	}
}
