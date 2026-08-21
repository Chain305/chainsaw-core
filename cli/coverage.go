package cli

// `chainsaw coverage` subcommands — opt-in coverage reporting CLI.
//
// Hard contract (mirrored from internal/coverage):
//   - The feature is ON by default (core/config: CoverageConfig.IsEnabled
//     returns true when `coverage.enabled` is unset). A server that has
//     it switched off — or that predates the coverage API, or booted
//     without a database — answers every /api/coverage/* request with
//     404. The CLI surfaces that as a plain description of what the
//     server said rather than dumping a stack trace, so an operator
//     running these commands against a dark deployment gets a clear
//     signal.
//   - The CLI is read + admin-CRUD only. Nothing here ever causes the
//     server to block an install or change a policy decision. The
//     `expected` subcommand mutates the coverage_expected metadata
//     table — pure declarative state, no enforcement side-effects.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var coverageCmd = &cobra.Command{
	Use:     "coverage",
	GroupID: GrpDebug,
	Short:   "Inspect install-coverage measurements (opt-in)",
	Long: `View tracked install sources, ecosystem breakdown, and clients that have
gone silent. Coverage is an opt-in measurement feature — it is purely
informational and never blocks installs.

The coverage gate applies to summary, silent and expected: those read
/api/coverage/*, so when the server has not enabled coverage they print
"coverage is not enabled" and stop. "coverage bypass" is NOT behind that gate —
it reads /api/bypass/*, which is always served, so bypass triage works on a
deployment with coverage switched off.`,
	SilenceUsage: true,
}

var coverageSummaryCmd = &cobra.Command{
	Use:   "summary",
	Short: "Show tracked install sources for a window (default 7d)",
	Long: "Reads /api/coverage/summary: the install sources seen in the window " +
		"and their ecosystem breakdown. Subject to the coverage gate — prints " +
		"\"coverage is not enabled\" when the server has coverage off.",
	SilenceUsage: true,
	RunE:         runCoverageSummary,
}

var coverageSilentCmd = &cobra.Command{
	Use:   "silent",
	Short: "List declared sources with no traffic in the window",
	Long: "Reads /api/coverage/silent: declared expected sources that sent no " +
		"traffic inside the window. Subject to the coverage gate — prints " +
		"\"coverage is not enabled\" when the server has coverage off.",
	SilenceUsage: true,
	RunE:         runCoverageSilent,
}

var coverageExpectedCmd = &cobra.Command{
	Use:   "expected",
	Short: "Manage the admin-declared expected install surface",
	Long: "Reads and writes /api/coverage/expected, the admin-declared list of " +
		"client patterns that SHOULD be installing through chainsaw. Declarative " +
		"metadata only: nothing here blocks an install. Subject to the coverage " +
		"gate — prints \"coverage is not enabled\" when the server has coverage off.",
	SilenceUsage: true,
}

var coverageExpectedListCmd = &cobra.Command{
	Use:   "list",
	Short: "List declared expected install sources",
	Long: "Reads /api/coverage/expected. Subject to the coverage gate — prints " +
		"\"coverage is not enabled\" when the server has coverage off.",
	SilenceUsage: true,
	RunE:         runCoverageExpectedList,
}

var coverageExpectedAddCmd = &cobra.Command{
	Use:   "add <client-pattern>",
	Short: "Declare a client as part of the expected install surface",
	Long: "Writes to /api/coverage/expected so the pattern can be reported " +
		"silent when it stops sending traffic. Subject to the coverage gate — " +
		"prints \"coverage is not enabled\" when the server has coverage off.",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runCoverageExpectedAdd,
}

var coverageExpectedRemoveCmd = &cobra.Command{
	Use:   "remove <id>",
	Short: "Remove a declared expected source by id",
	Long: "Removes a declared expected install source. Coverage stops counting " +
		"it as expected, so it can no longer be reported silent. Prompts for " +
		"confirmation (naming the client pattern, which is what `coverage " +
		"expected add` needs to restore it); use --yes to skip the prompt. " +
		"Subject to the coverage gate — prints \"coverage is not enabled\" when " +
		"the server has coverage off.",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runCoverageExpectedRemove,
}

// D.12 — bypass-report triage subcommands.
//
// `chainsaw coverage bypass list` shows the ingested rows above a
// confidence threshold (default 0.7 — matches the UI slider). `confirm`
// flips a row to status=confirmed, recording the operator's intent so
// the (deferred) decision-engine gate has a query surface. `dismiss`
// silences a row for 30d.
var coverageBypassCmd = &cobra.Command{
	Use:   "bypass",
	Short: "Triage ingested bypass-detection reports",
	Long: "Reads and writes /api/bypass/*, which sits OUTSIDE the coverage gate: " +
		"bypass triage works even when the server has coverage disabled. Grouped " +
		"under `coverage` because a detected bypass is the sharpest form of a " +
		"coverage hole, not because it shares the gate.",
	SilenceUsage: true,
}

var coverageBypassListCmd = &cobra.Command{
	Use:   "list",
	Short: "List bypass reports above the confidence threshold",
	Long: "Reads /api/bypass/reports. Not subject to the coverage gate — this " +
		"works on a server with coverage disabled.",
	SilenceUsage: true,
	RunE:         runCoverageBypassList,
}

var coverageBypassConfirmCmd = &cobra.Command{
	Use:   "confirm <id>",
	Short: "Confirm a bypass report (records intent; quarantine on confirm)",
	Long: "Posts to /api/bypass/reports/{id}/confirm. Not subject to the " +
		"coverage gate — this works on a server with coverage disabled.",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runCoverageBypassConfirm,
}

var coverageBypassDismissCmd = &cobra.Command{
	Use:   "dismiss <id>",
	Short: "Dismiss a bypass report as a false alarm (30d suppression)",
	Long: "Posts to /api/bypass/reports/{id}/dismiss. Not subject to the " +
		"coverage gate — this works on a server with coverage disabled.",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runCoverageBypassDismiss,
}

func init() {
	coverageSummaryCmd.Flags().String("window", "7d", "Window: 7d or 30d")
	coverageSummaryCmd.Flags().Bool("json", false, "Output as JSON")
	coverageSilentCmd.Flags().String("window", "7d", "Window: 7d or 30d")
	coverageSilentCmd.Flags().Bool("json", false, "Output as JSON")
	coverageExpectedListCmd.Flags().Bool("json", false, "Output as JSON")
	coverageExpectedAddCmd.Flags().Int("active-within-days", 7, "Expected active window for this source")
	coverageExpectedRemoveCmd.Flags().Bool("yes", false, "Skip confirmation prompt (required on non-TTY)")
	coverageBypassListCmd.Flags().Float64("min-confidence", 0.7, "Confidence threshold (0..1)")
	coverageBypassListCmd.Flags().Bool("include-dismissed", false, "Include dismissed-and-still-suppressed rows")
	coverageBypassListCmd.Flags().Bool("json", false, "Output as JSON")

	coverageCmd.AddCommand(coverageSummaryCmd)
	coverageCmd.AddCommand(coverageSilentCmd)
	coverageExpectedCmd.AddCommand(coverageExpectedListCmd)
	coverageExpectedCmd.AddCommand(coverageExpectedAddCmd)
	coverageExpectedCmd.AddCommand(coverageExpectedRemoveCmd)
	coverageCmd.AddCommand(coverageExpectedCmd)
	coverageBypassCmd.AddCommand(coverageBypassListCmd)
	coverageBypassCmd.AddCommand(coverageBypassConfirmCmd)
	coverageBypassCmd.AddCommand(coverageBypassDismissCmd)
	coverageCmd.AddCommand(coverageBypassCmd)
	rootCmd.AddCommand(coverageCmd)
}

// coverageNotAvailableMessage is what the CLI prints when the server
// answers a /api/coverage/* collection request with 404.
//
// It deliberately does NOT tell the operator to set `coverage.enabled:
// true`. That key defaults to true (core/config/config.go —
// CoverageConfig.IsEnabled) and is documented in
// docs/CONFIG_REFERENCE.md, so the previous wording sent operators off
// to change a setting that was already correct. A 404 has three real
// causes and the response body cannot tell them apart, so the message
// reports what the server said and names the causes instead of
// guessing one.
const coverageNotAvailableMessage = "the server returned 404 for the coverage endpoint.\n" +
	"Coverage is on by default, so this is not a missing `coverage.enabled` setting. Usual causes:\n" +
	"  - the server predates the coverage API — compare `chainsaw version` with the server build\n" +
	"  - coverage is switched off for this org via the `coverage_default_on` feature flag\n" +
	"  - the server booted without a database, so coverage is in dark mode — check the server logs\n" +
	"An org with no install traffic yet is not one of these: that returns an empty summary, not a 404."

func runCoverageSummary(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	window, _ := cmd.Flags().GetString("window")
	asJSON := useJSON(cmd)
	var resp coverageSummary
	// C13: --window is a user flag; encode it instead of concatenating, or
	// `--window '7d&export=true'` silently sends a second parameter the flag
	// never named.
	path := "/api/coverage/summary" + coverageWindowQuery(window)
	if err := client.Get(path, &resp); err != nil {
		return translateCoverageCollectionErr(err)
	}
	out := cmd.OutOrStdout()
	if asJSON {
		enc := json.NewEncoder(outWriterOr(cmd, cmd.OutOrStdout()))
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	}
	fmt.Fprintf(out, "Tracked install sources (%s):\n", resp.Window)
	fmt.Fprintf(out, "  %d clients · %d repos · %d installs\n", resp.TrackedClients, resp.TrackedRepos, resp.TotalInstalls)
	if len(resp.EcosystemBreakdown) > 0 {
		fmt.Fprintln(out, "\nBy ecosystem:")
		rows := make([][]string, len(resp.EcosystemBreakdown))
		for i, e := range resp.EcosystemBreakdown {
			rows[i] = []string{e.Format, strconv.FormatInt(e.Installs, 10)}
		}
		PrintTable([]string{"FORMAT", "INSTALLS"}, rows)
	}
	if len(resp.Clients) > 0 {
		fmt.Fprintln(out, "\nClients:")
		rows := make([][]string, len(resp.Clients))
		for i, c := range resp.Clients {
			rows[i] = []string{c.ClientID, strconv.FormatInt(c.Installs, 10), c.LastSeen.Format(time.RFC3339)}
		}
		PrintTable([]string{"CLIENT", "INSTALLS", "LAST SEEN"}, rows)
	}
	return nil
}

func runCoverageSilent(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	window, _ := cmd.Flags().GetString("window")
	asJSON := useJSON(cmd)
	var resp struct {
		Window string                `json:"window"`
		Silent []coverageSilentEntry `json:"silent"`
	}
	path := "/api/coverage/silent" + coverageWindowQuery(window)
	if err := client.Get(path, &resp); err != nil {
		return translateCoverageCollectionErr(err)
	}
	out := cmd.OutOrStdout()
	if asJSON {
		enc := json.NewEncoder(outWriterOr(cmd, cmd.OutOrStdout()))
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	}
	if len(resp.Silent) == 0 {
		fmt.Fprintf(out, "All declared sources have been active in the last %s.\n", resp.Window)
		return nil
	}
	fmt.Fprintf(out, "Silent sources (no traffic in last %s):\n", resp.Window)
	rows := make([][]string, len(resp.Silent))
	for i, s := range resp.Silent {
		last := "never observed"
		if !s.LastSeen.IsZero() {
			last = s.LastSeen.Format(time.RFC3339)
		}
		rows[i] = []string{strconv.FormatInt(s.ID, 10), s.ClientPattern, last}
	}
	PrintTable([]string{"ID", "PATTERN", "LAST SEEN"}, rows)
	return nil
}

func runCoverageExpectedList(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	asJSON := useJSON(cmd)
	var resp struct {
		Expected []coverageExpected `json:"expected"`
	}
	if err := client.Get("/api/coverage/expected", &resp); err != nil {
		return translateCoverageCollectionErr(err)
	}
	out := cmd.OutOrStdout()
	if asJSON {
		enc := json.NewEncoder(outWriterOr(cmd, cmd.OutOrStdout()))
		enc.SetIndent("", "  ")
		return enc.Encode(jsonArray(resp.Expected))
	}
	if len(resp.Expected) == 0 {
		fmt.Fprintln(out, "No expected sources declared.")
		return nil
	}
	rows := make([][]string, len(resp.Expected))
	for i, e := range resp.Expected {
		rows[i] = []string{strconv.FormatInt(e.ID, 10), e.ClientPattern, strconv.Itoa(e.ExpectedActiveWithinDays), e.AddedAt.Format(time.RFC3339), e.AddedBy}
	}
	PrintTable([]string{"ID", "PATTERN", "ACTIVE WITHIN DAYS", "ADDED AT", "ADDED BY"}, rows)
	return nil
}

func runCoverageExpectedAdd(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	pattern := strings.TrimSpace(args[0])
	if pattern == "" {
		return fmt.Errorf("client pattern required")
	}
	days, _ := cmd.Flags().GetInt("active-within-days")
	body := map[string]any{
		"client_pattern":              pattern,
		"expected_active_within_days": days,
	}
	var resp coverageExpected
	// Collection path: a 404 here really does mean the feature is off.
	if err := client.Post("/api/coverage/expected", body, &resp); err != nil {
		return translateCoverageCollectionErr(err)
	}
	printSuccess(cmd.OutOrStdout(), cmd, fmt.Sprintf("Declared %q (id=%d)", resp.ClientPattern, resp.ID))
	return nil
}

func runCoverageExpectedRemove(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	// Auth BEFORE the confirmation prompt (see requireAuth, root.go).
	if err := requireAuth(cmd); err != nil {
		return err
	}
	id, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("invalid id %q", args[0])
	}

	// Z3: this deleted a declared expected-source row with no prompt and no
	// --yes at all. It was classified exempt on the grounds that `coverage
	// expected add` restores the row, but the restoring verb takes a CLIENT
	// PATTERN while this one takes an opaque numeric ID — so the argument the
	// operator would need in order to undo the removal is precisely the field
	// the removal destroys, and nothing in the transcript records it. Resolve
	// the row and name it in the prompt, which makes the confirmation itself
	// the record of what to re-add.
	//
	// The lookup runs only on the confirm path, so --yes stays one round trip.
	// If the lookup fails we ABORT rather than prompt: confirming the deletion
	// of a row we could not describe is the same defect Z1 fixed in `undo`.
	yes, _ := cmd.Flags().GetBool("yes")
	if !yes {
		var listResp struct {
			Expected []coverageExpected `json:"expected"`
		}
		if lerr := client.Get("/api/coverage/expected", &listResp); lerr != nil {
			return translateCoverageCollectionErr(lerr)
		}
		var target *coverageExpected
		for i := range listResp.Expected {
			if listResp.Expected[i].ID == id {
				target = &listResp.Expected[i]
				break
			}
		}
		if target == nil {
			return fmt.Errorf("no expected source with id=%d — run `chainsaw coverage expected list` to see declared sources", id)
		}
		if !stdinIsTerminal() {
			return fmt.Errorf("refusing to remove expected source %d (%s) without --yes (stdin is not a TTY, so there is no confirmation prompt to display). Re-run with --yes to confirm.", id, target.ClientPattern)
		}
		if !PromptConfirm(fmt.Sprintf("Remove expected source %q (id=%d)? Coverage will stop counting it as declared; re-add with `chainsaw coverage expected add %s`.", target.ClientPattern, id, target.ClientPattern)) {
			fmt.Fprintln(cmd.OutOrStdout(), "Aborted.")
			return nil
		}
	}

	// C11: per-id endpoint — a 404 here means THIS id does not exist, not that
	// the feature is disabled. Pass it through untranslated.
	if err := client.Delete(fmt.Sprintf("/api/coverage/expected/%d", id)); err != nil {
		return err
	}
	printSuccess(cmd.OutOrStdout(), cmd, fmt.Sprintf("Removed expected source id=%d", id))
	return nil
}

// --- bypass-report triage runners ---

type coverageBypassReport struct {
	ID              int64     `json:"id"`
	ClientHint      string    `json:"client_hint"`
	Evidence        string    `json:"evidence,omitempty"`
	ConfidenceScore float64   `json:"confidence_score"`
	Source          string    `json:"source"`
	Status          string    `json:"status"`
	SeenAt          time.Time `json:"seen_at"`
	CreatedAt       time.Time `json:"created_at"`
	ConfirmedAt     time.Time `json:"confirmed_at,omitempty"`
	ConfirmedBy     string    `json:"confirmed_by,omitempty"`
}

type coverageBypassListResponse struct {
	Reports       []coverageBypassReport `json:"reports"`
	MinConfidence float64                `json:"min_confidence"`
}

func runCoverageBypassList(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	minConf, _ := cmd.Flags().GetFloat64("min-confidence")
	incDismissed, _ := cmd.Flags().GetBool("include-dismissed")
	asJSON := useJSON(cmd)
	path := fmt.Sprintf("/api/bypass/reports?min_confidence=%g", minConf)
	if incDismissed {
		path += "&include_dismissed=1"
	}
	var resp coverageBypassListResponse
	if err := client.Get(path, &resp); err != nil {
		return translateCoverageCollectionErr(err)
	}
	out := cmd.OutOrStdout()
	if asJSON {
		enc := json.NewEncoder(outWriterOr(cmd, cmd.OutOrStdout()))
		enc.SetIndent("", "  ")
		return enc.Encode(resp)
	}
	if len(resp.Reports) == 0 {
		fmt.Fprintf(out, "No bypass reports above confidence %.2f.\n", resp.MinConfidence)
		return nil
	}
	fmt.Fprintf(out, "Bypass reports (confidence >= %.2f):\n", resp.MinConfidence)
	rows := make([][]string, len(resp.Reports))
	for i, r := range resp.Reports {
		rows[i] = []string{
			strconv.FormatInt(r.ID, 10),
			r.ClientHint,
			fmt.Sprintf("%.2f", r.ConfidenceScore),
			r.Source,
			r.Status,
			r.SeenAt.Format(time.RFC3339),
		}
	}
	PrintTable([]string{"ID", "CLIENT", "CONFIDENCE", "SOURCE", "STATUS", "SEEN AT"}, rows)
	return nil
}

func runCoverageBypassConfirm(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("invalid id %q", args[0])
	}
	var resp coverageBypassReport
	// C11: per-id — `bypass confirm 999` on a coverage-ENABLED server used to
	// print "coverage is not enabled on this server", sending the operator off
	// to fix a config problem that does not exist.
	if err := client.Post(fmt.Sprintf("/api/bypass/reports/%d/confirm", id), map[string]any{}, &resp); err != nil {
		return err
	}
	printSuccess(cmd.OutOrStdout(), cmd, fmt.Sprintf("Confirmed bypass report id=%d (client=%q, status=%s)", resp.ID, resp.ClientHint, resp.Status))
	return nil
}

func runCoverageBypassDismiss(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id, err := strconv.ParseInt(strings.TrimSpace(args[0]), 10, 64)
	if err != nil || id <= 0 {
		return fmt.Errorf("invalid id %q", args[0])
	}
	var resp coverageBypassReport
	// C11: per-id — see runCoverageBypassConfirm.
	if err := client.Post(fmt.Sprintf("/api/bypass/reports/%d/dismiss", id), map[string]any{}, &resp); err != nil {
		return err
	}
	printSuccess(cmd.OutOrStdout(), cmd, fmt.Sprintf("Dismissed bypass report id=%d (30d suppression)", resp.ID))
	return nil
}

// coverageWindowQuery renders the optional --window flag as an escaped query
// string (or "" when unset), so a value carrying & or = cannot smuggle extra
// parameters into the request (C13).
func coverageWindowQuery(window string) string {
	if window == "" {
		return ""
	}
	q := url.Values{}
	q.Set("window", window)
	return "?" + q.Encode()
}

// translateCoverageCollectionErr surfaces "feature off" to the operator with a
// neutral message instead of letting the bare 404 pass through. We detect by the
// literal "404" / "not found" the APIClient emits — the shape mirrors the
// existing classifyCLIError heuristics in root.go.
//
// C11: this is deliberately restricted to COLLECTION endpoints
// (/api/coverage/summary, /silent, /expected, /api/bypass/reports). Those return
// 404 for the whole route when coverage.enabled is false, so the translation is
// sound there. Per-ID routes — DELETE /api/coverage/expected/{id},
// POST /api/bypass/reports/{id}/{confirm,dismiss} — return 404 for a MISSING
// ROW, and running the same substring heuristic over those told operators of a
// perfectly-enabled server to go change server config. Those call sites now
// return the error untouched; do not re-point them here.
func translateCoverageCollectionErr(err error) error {
	if err == nil {
		return nil
	}
	// Status-first. apiError carries the HTTP status the transport
	// observed, and that is the only authoritative "was this a 404" —
	// see the Status field doc in client.go. The previous substring
	// match on "404" / "not found" over the whole error text was too
	// broad in both directions: it rewrote the misconfigured-`--server`
	// hint (serverURLError's message contains both "404" and "Not
	// Found") into coverage advice, and it would fire on any unrelated
	// error whose text happened to contain those words.
	var apiErr *apiError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
		return fmt.Errorf("%s", coverageNotAvailableMessage)
	}
	return err
}

// --- wire types (mirror internal/coverage shapes) ---

type coverageSummary struct {
	OrgID              string                   `json:"org_id"`
	Window             string                   `json:"window"`
	WindowStart        time.Time                `json:"window_start"`
	WindowEnd          time.Time                `json:"window_end"`
	TrackedClients     int                      `json:"tracked_clients"`
	TrackedRepos       int                      `json:"tracked_repos"`
	TotalInstalls      int64                    `json:"total_installs"`
	EcosystemBreakdown []coverageEcosystemRow   `json:"ecosystem_breakdown"`
	Clients            []coverageClientActivity `json:"clients"`
}

type coverageEcosystemRow struct {
	Format   string `json:"format"`
	Installs int64  `json:"installs"`
}

type coverageClientActivity struct {
	ClientID string    `json:"client_id"`
	Installs int64     `json:"installs"`
	LastSeen time.Time `json:"last_seen"`
}

type coverageSilentEntry struct {
	ID                       int64     `json:"id"`
	ClientPattern            string    `json:"client_pattern"`
	ExpectedActiveWithinDays int       `json:"expected_active_within_days"`
	AddedAt                  time.Time `json:"added_at"`
	AddedBy                  string    `json:"added_by"`
	LastSeen                 time.Time `json:"last_seen,omitempty"`
}

type coverageExpected struct {
	ID                       int64     `json:"id"`
	ClientPattern            string    `json:"client_pattern"`
	ExpectedActiveWithinDays int       `json:"expected_active_within_days"`
	AddedAt                  time.Time `json:"added_at"`
	AddedBy                  string    `json:"added_by"`
}
