package cli

// `chainsaw doctor logs --severity warn+` (Wave AH gap 3) wraps
// `kubectl logs deploy/chainsaw-proxy --since=<dur>` with a severity
// filter and a human-friendly renderer. Operators without a log
// aggregator can run this on a control node to see only the lines that
// matter (WARN + ERROR) for a recent window.
//
// Scope discipline:
//   - No daemon. This is a one-shot wrapper, not a background process.
//   - No new logger. We read stdout from kubectl, classify each line,
//     and render. kubectl emits slog JSON lines today (text fallback is
//     supported for older deployments that still log text).
//   - kubectl is invoked as a subprocess. If it's not on PATH or the
//     deployment isn't reachable, the error surfaces cleanly to the
//     operator — the wrapper does NOT silently no-op.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// severityFilter is the parsed form of the --severity flag.
// Accepts "warn+" (>=WARN), "error" (only ERROR), "warn", "info+".
type severityFilter struct {
	minLevel logLevel
	exact    bool // when true, only the exact level passes
}

type logLevel int

const (
	levelUnknown logLevel = iota
	levelDebug
	levelInfo
	levelWarn
	levelError
)

func (l logLevel) String() string {
	switch l {
	case levelDebug:
		return "DEBUG"
	case levelInfo:
		return "INFO"
	case levelWarn:
		return "WARN"
	case levelError:
		return "ERROR"
	default:
		return "?"
	}
}

// parseSeverityFilter accepts the operator-friendly shorthand the gap-3
// audit calls out: "warn+", "error", "warn", "info+", "debug+".
//
// Default: warn+ (WARN and ERROR pass).
func parseSeverityFilter(raw string) (severityFilter, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return severityFilter{minLevel: levelWarn}, nil
	}
	exact := !strings.HasSuffix(raw, "+")
	raw = strings.TrimSuffix(raw, "+")
	var lvl logLevel
	switch raw {
	case "debug":
		lvl = levelDebug
	case "info":
		lvl = levelInfo
	case "warn", "warning":
		lvl = levelWarn
	case "error", "err":
		lvl = levelError
	default:
		return severityFilter{}, fmt.Errorf("unknown severity %q (expected: debug, info, warn, error; optional '+' suffix for ≥)", raw)
	}
	return severityFilter{minLevel: lvl, exact: exact}, nil
}

// pass reports whether a log line at lvl should be emitted by the filter.
func (f severityFilter) pass(lvl logLevel) bool {
	if lvl == levelUnknown {
		// Unparseable lines: surface them at WARN+ severity selections so
		// the operator doesn't lose visibility on text-formatted lines an
		// older deployment is still emitting.
		return f.minLevel <= levelWarn
	}
	if f.exact {
		return lvl == f.minLevel
	}
	return lvl >= f.minLevel
}

// logEntry is one rendered log line. We capture timestamp+level+message
// from the JSON envelope and dump the remaining fields as sorted
// key=value pairs so the rendered output is stable across reruns.
type logEntry struct {
	Time    string
	Level   logLevel
	Message string
	Fields  map[string]any
	Raw     string // fallback for text lines
}

// parseLogLine attempts JSON first (the slog.NewJSONHandler shape).
// Text-formatted lines fall through to a heuristic that scrapes
// `level=<LVL>` and `msg=<…>` tokens.
func parseLogLine(line string) logEntry {
	line = strings.TrimSpace(line)
	if line == "" {
		return logEntry{Level: levelUnknown}
	}
	if strings.HasPrefix(line, "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err == nil {
			lvl := levelUnknown
			if v, ok := obj["level"].(string); ok {
				lvl = parseLevelToken(v)
			}
			msg, _ := obj["msg"].(string)
			ts, _ := obj["time"].(string)
			// Strip the well-known fields so Fields holds only the
			// extras (repository, package, version, error, ...).
			delete(obj, "level")
			delete(obj, "msg")
			delete(obj, "time")
			return logEntry{Time: ts, Level: lvl, Message: msg, Fields: obj}
		}
	}
	// Text fallback: look for `level=WARN` and `msg="..."`.
	lvl := levelUnknown
	if idx := strings.Index(line, "level="); idx >= 0 {
		tok := line[idx+len("level="):]
		if sp := strings.IndexAny(tok, " \t"); sp >= 0 {
			tok = tok[:sp]
		}
		lvl = parseLevelToken(tok)
	}
	return logEntry{Level: lvl, Raw: line}
}

func parseLevelToken(s string) logLevel {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "DEBUG":
		return levelDebug
	case "INFO":
		return levelInfo
	case "WARN", "WARNING":
		return levelWarn
	case "ERROR", "ERR":
		return levelError
	default:
		return levelUnknown
	}
}

// renderEntry returns the human-friendly single-line form. Fields are
// sorted alphabetically so consecutive runs against the same window
// produce diff-able output.
func renderEntry(e logEntry) string {
	if len(e.Fields) == 0 && e.Raw != "" {
		// Text-format fallback: pass the line through verbatim,
		// prepended with the parsed level for consistency.
		return fmt.Sprintf("%-5s %s", e.Level, e.Raw)
	}
	var b strings.Builder
	if e.Time != "" {
		b.WriteString(e.Time)
		b.WriteString(" ")
	}
	b.WriteString(fmt.Sprintf("%-5s ", e.Level))
	b.WriteString(e.Message)
	if len(e.Fields) == 0 {
		return b.String()
	}
	keys := make([]string, 0, len(e.Fields))
	for k := range e.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, " %s=%v", k, e.Fields[k])
	}
	return b.String()
}

// filterLogStream reads JSON-or-text log lines from r, applies the
// severity filter, renders each kept entry, and writes the result to w.
// Returns the number of kept lines so the CLI can exit non-zero when
// nothing matched (useful in CI: a "no WARN/ERROR in the last hour" run
// is a real signal, but a "couldn't read any lines at all" run is not).
func filterLogStream(r io.Reader, w io.Writer, filter severityFilter) (int, int, error) {
	scanner := bufio.NewScanner(r)
	// Increase the line buffer — slog JSON lines with stack traces can
	// blow past the default 64 KiB ceiling.
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var read, kept int
	for scanner.Scan() {
		read++
		entry := parseLogLine(scanner.Text())
		if !filter.pass(entry.Level) {
			continue
		}
		fmt.Fprintln(w, renderEntry(entry))
		kept++
	}
	if err := scanner.Err(); err != nil {
		return read, kept, fmt.Errorf("scan logs: %w", err)
	}
	return read, kept, nil
}

// newLogsTailCmd builds the `chainsaw logs tail` subcommand. Defaults
// match the gap-3 audit recommendation: warn+ severity and a 1-hour
// window against deploy/chainsaw-proxy in the current namespace.
func newLogsTailCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tail",
		Short: "Tail and filter chainsaw-proxy logs by severity (kubectl wrapper)",
		Long: `Read recent chainsaw-proxy logs via kubectl and emit only the lines
matching --severity. Use --severity warn+ (default) to see exactly the
operator-actionable signal: every layer-scan degrade, every multi-arch
refusal, every MANIFEST_UNKNOWN.

Defaults: --since=1h, --deployment=deploy/chainsaw-proxy. Use --stdin
to pipe in an existing log stream instead of invoking kubectl (handy in
tests and air-gapped runs).`,
		RunE: runDoctorLogs,
	}
	cmd.Flags().String("severity", "warn+", "Minimum severity to surface: debug, info, warn, error; append '+' for '>='. Default warn+ (WARN + ERROR).")
	cmd.Flags().String("since", "1h", "kubectl --since duration window (e.g. 15m, 1h, 24h).")
	cmd.Flags().String("deployment", "deploy/chainsaw-proxy", "kubectl target (e.g. deploy/chainsaw-proxy, pod/foo, ds/bar).")
	cmd.Flags().String("namespace", "", "Kubernetes namespace. Empty -> the current context's default namespace.")
	cmd.Flags().Bool("stdin", false, "Read log lines from stdin instead of invoking kubectl.")
	return cmd
}

func init() {
	// `chainsaw logs tail --severity warn+` — the gap-3 audit's
	// recommended surface for operators without a log aggregator.
	logs := &cobra.Command{
		Use:   "logs",
		Short: "Inspect chainsaw-proxy logs",
	}
	logs.AddCommand(newLogsTailCmd())
	rootCmd.AddCommand(logs)
}

func runDoctorLogs(cmd *cobra.Command, _ []string) error {
	sevRaw, _ := cmd.Flags().GetString("severity")
	filter, err := parseSeverityFilter(sevRaw)
	if err != nil {
		return err
	}
	useStdin, _ := cmd.Flags().GetBool("stdin")
	if useStdin {
		_, _, err := filterLogStream(os.Stdin, cmd.OutOrStdout(), filter)
		return err
	}
	since, _ := cmd.Flags().GetString("since")
	deployment, _ := cmd.Flags().GetString("deployment")
	namespace, _ := cmd.Flags().GetString("namespace")

	args := []string{"logs", deployment, "--since=" + since}
	if namespace != "" {
		args = append(args, "-n", namespace)
	}
	kubectl := exec.Command("kubectl", args...)
	stdout, err := kubectl.StdoutPipe()
	if err != nil {
		return fmt.Errorf("kubectl stdout pipe: %w", err)
	}
	kubectl.Stderr = cmd.ErrOrStderr()
	if err := kubectl.Start(); err != nil {
		return fmt.Errorf("invoke kubectl (is it on PATH?): %w", err)
	}
	// Stream-process so very long windows don't buffer the whole output
	// in memory before rendering.
	_, _, ferr := filterLogStream(stdout, cmd.OutOrStdout(), filter)
	werr := kubectl.Wait()
	if ferr != nil {
		return ferr
	}
	if werr != nil {
		return fmt.Errorf("kubectl logs: %w", werr)
	}
	return nil
}

// shortTime returns the time formatted to seconds, useful when the
// upstream emits RFC3339Nano which is noisy. Currently unused — kept for
// the future audit-event-API tail that mints its own timestamps. Marked
// nolint to satisfy unused linters during the gap-3 landing.
//
//nolint:unused
func shortTime(t time.Time) string {
	return t.UTC().Format("15:04:05Z")
}
