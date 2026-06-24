package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"
)

const (
	ansiGreen = "\033[32m"
	ansiBold  = "\033[1m"
	ansiReset = "\033[0m"
)

// stdoutIsTerminal reports whether stdout is attached to a terminal. Overridable
// in tests; the production default inspects os.Stdout via x/term.
var stdoutIsTerminal = func() bool {
	return term.IsTerminal(int(os.Stdout.Fd()))
}

// PrintJSON writes v as indented JSON to stdout.
func PrintJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// PrintTable writes a plain-text table with aligned columns to stdout.
// headers and each row must have the same length.
func PrintTable(headers []string, rows [][]string) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, strings.Join(headers, "\t"))
	sep := make([]string, len(headers))
	for i, h := range headers {
		sep[i] = strings.Repeat("-", len(h))
	}
	fmt.Fprintln(w, strings.Join(sep, "\t"))
	for _, row := range rows {
		fmt.Fprintln(w, strings.Join(row, "\t"))
	}
	w.Flush()
}

// Fatalf prints msg to stderr and exits 1.
func Fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "error: "+format+"\n", args...)
	os.Exit(1)
}

func noColor(cmd *cobra.Command) bool {
	b, _ := cmd.Flags().GetBool("no-color")
	if b || viper.GetBool("no_color") || os.Getenv("NO_COLOR") != "" {
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

func useJSON(cmd *cobra.Command) bool {
	b, _ := cmd.Flags().GetBool("json")
	return b
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
