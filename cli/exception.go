package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// exceptionItem mirrors the exceptionEntry JSON envelope returned by the
// /api/exceptions handlers in internal/server/exceptions_api.go. Kept
// field-for-field in sync with internal/server/entries.go:exceptionEntry so
// the CLI never has to round-trip through a generic map.
type exceptionItem struct {
	ID            string    `json:"id"`
	Repository    string    `json:"repository"`
	Format        string    `json:"format"`
	PackageID     string    `json:"package"`
	Version       string    `json:"version"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
	ExpiresAt     time.Time `json:"expiresAt"`
	Status        string    `json:"status"`
	DaysRemaining int       `json:"daysRemaining"`
	// Decision/CVE/Note mirror the server-side exceptionEntry fields that
	// the VEX export needs. Empty strings on the wire mean "row predates
	// this change" — exceptionItemsToVEXInput falls back to decision=allow.
	Decision string `json:"decision,omitempty"`
	CVE      string `json:"cve,omitempty"`
	Note     string `json:"note,omitempty"`
}

var exceptionCmd = &cobra.Command{
	Use:   "exception",
	Short: "Manage policy exceptions (scoped allow-rules with expiry)",
}

// ── list ──────────────────────────────────────────────────────────────────────

var exceptionListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active policy exceptions",
	RunE:  runExceptionList,
}

func init() {
	exceptionListCmd.Flags().Bool("json", false, "Output as JSON")
	exceptionCmd.AddCommand(exceptionListCmd)
}

func runExceptionList(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	var resp struct {
		Entries []exceptionItem `json:"entries"`
	}
	if err := client.Get("/api/exceptions", &resp); err != nil {
		return err
	}

	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(resp.Entries)
	}

	if len(resp.Entries) == 0 {
		fmt.Println("No exceptions found.")
		return nil
	}
	rows := make([][]string, len(resp.Entries))
	for i, e := range resp.Entries {
		days := "-"
		if e.DaysRemaining >= 0 {
			days = fmt.Sprintf("%d", e.DaysRemaining)
		}
		rows[i] = []string{
			e.ID,
			e.Repository,
			e.PackageID,
			e.Version,
			e.Status,
			days,
			e.UpdatedAt.Format("2006-01-02"),
		}
	}
	PrintTable([]string{"ID", "REPO", "PACKAGE", "VERSION", "STATUS", "DAYS_LEFT", "UPDATED"}, rows)
	return nil
}

// ── create ────────────────────────────────────────────────────────────────────

var exceptionCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new exception (allow a specific package@version)",
	Long: "Create a policy exception that allows a specific package version through " +
		"the proxy even when it matches block conditions. Exceptions are scoped to " +
		"(repository, package, version) and expire after the org's configured " +
		"exception age (or --expires when set). Use --from-file for JSON input, " +
		"or pass the flags directly.\n\n" +
		"Examples:\n" +
		"  chainsaw exception create --repository npm-proxy --package left-pad --version 1.3.0\n" +
		"  chainsaw exception create --repository npm-proxy --package left-pad --version 1.3.0 \\\n" +
		"      --reason \"transitive dep, upstream fix pending\" --expires 7d\n" +
		"\n" +
		"  # VEX-friendly: mark log4j-core 2.14.1 as not_affected because we\n" +
		"  # don't invoke the JNDI lookup path. The CVE + decision are what\n" +
		"  # `chainsaw sbom vex export` needs to emit a CycloneDX VEX row.\n" +
		"  chainsaw exception create --repository maven-central --package log4j:log4j-core \\\n" +
		"      --version 2.14.1 --cve CVE-2021-44228 --decision allow \\\n" +
		"      --reason \"JNDI lookup path not invoked in our codebase\"\n" +
		"\n" +
		// Note: shorthand like 'npm:left-pad@1.3.0' is referenced in some docs but not yet supported here.
		"Use the explicit --repository / --package / --version triple.",
	RunE: runExceptionCreate,
}

func init() {
	exceptionCreateCmd.Flags().String("repository", "", "Repository name (required; --ecosystem is an accepted alias)")
	exceptionCreateCmd.Flags().String("ecosystem", "", "Alias for --repository — smoke spec D.5 and several internal runbooks use --ecosystem")
	exceptionCreateCmd.Flags().String("package", "", "Package name (required)")
	exceptionCreateCmd.Flags().String("version", "", "Package version (required)")
	exceptionCreateCmd.Flags().String("reason", "", "Human-readable justification for the exception (recorded in audit log)")
	exceptionCreateCmd.Flags().String("expires", "", "Duration before the exception expires (e.g. 7d, 24h, 30m). Alias of --days expressed as a duration string.")
	exceptionCreateCmd.Flags().Int("days", 0, "Number of days before the exception expires (mutually exclusive with --expires-at and --expires). Defaults to 30 when no other expiry flag is supplied.")
	exceptionCreateCmd.Flags().String("expires-at", "", "Explicit RFC3339 timestamp for expiry (mutually exclusive with --days and --expires)")
	exceptionCreateCmd.Flags().String("from-file", "", "Read request body as JSON from file (--ecosystem/--days/--expires-at/--reason still apply on top)")
	exceptionCreateCmd.Flags().String("cve", "", "CVE ID (or comma-separated list) the exception applies to (e.g. CVE-2021-44228). Required for `chainsaw sbom vex export` to emit a VEX row.")
	exceptionCreateCmd.Flags().String("decision", "", "VEX decision: 'allow' (default — maps to not_affected), 'monitor' (in_triage), or 'deny'. Empty falls through to the server default of allow.")
	exceptionCreateCmd.Flags().String("vex-note", "", "Free-text justification used in the CycloneDX VEX 'analysis.detail' field. Falls back to --reason when omitted.")
	exceptionCreateCmd.Flags().Bool("json", false, "Print created exception as JSON")
	exceptionCmd.AddCommand(exceptionCreateCmd)
}

// defaultExceptionDays is the fallback expiry window when the caller did
// not pass --expires, --expires-at, or --days. The smoke spec D.5 requires
// every exception to be "time-bombed" — silently writing
// expiresAt=0001-01-01T00:00:00Z (the previous behaviour) defeats the
// audit trail. 30 days mirrors the org-config default that the server
// applies when it gets an empty expires_at.
const defaultExceptionDays = 30

func runExceptionCreate(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	// Compute expiry up-front so the same precedence applies whether the
	// body comes from --from-file or from individual flags. Order:
	//   1. --expires-at (explicit RFC3339)
	//   2. --days (integer days)
	//   3. --expires (Go duration / "7d" extension — pre-existing flag)
	//   4. default (defaultExceptionDays)
	// The three explicit forms are mutually exclusive; passing more than
	// one is a usage error rather than a silent "last wins" surprise.
	expiresAt, err := resolveExceptionExpiry(cmd)
	if err != nil {
		return err
	}

	// VEX-related flags. Validated client-side too so a typo'd
	// --decision fails fast with a clear error rather than going to
	// the server and back. Mirrors validateExceptionDecision in
	// internal/server/exceptions_api.go — keep the allowed set in sync.
	cveFlag := strings.TrimSpace(mustString(cmd, "cve"))
	decisionFlag := strings.ToLower(strings.TrimSpace(mustString(cmd, "decision")))
	vexNoteFlag := strings.TrimSpace(mustString(cmd, "vex-note"))
	switch decisionFlag {
	case "", "allow", "deny", "monitor":
		// ok
	default:
		return fmt.Errorf("--decision must be one of 'allow', 'deny', 'monitor' (or omitted); got %q", decisionFlag)
	}

	var body map[string]any

	fromFile, _ := cmd.Flags().GetString("from-file")
	if fromFile != "" {
		data, ferr := os.ReadFile(fromFile)
		if ferr != nil {
			return fmt.Errorf("read --from-file: %w", ferr)
		}
		if jerr := json.Unmarshal(data, &body); jerr != nil {
			return fmt.Errorf("parse --from-file as JSON: %w", jerr)
		}
		// --ecosystem alias / --reason / expiry flags can still be
		// layered on top of --from-file so a base JSON template plus
		// per-call overrides works without writing a new file each
		// time. Empty flag values do not clobber file-supplied keys.
		if eco := strings.TrimSpace(mustString(cmd, "ecosystem")); eco != "" {
			body["repository"] = eco
		}
		if reason := strings.TrimSpace(mustString(cmd, "reason")); reason != "" {
			body["reason"] = reason
		}
		applyVEXOverridesFromFlags(body, cveFlag, decisionFlag, vexNoteFlag, mustString(cmd, "reason"))
	} else {
		repo, _ := cmd.Flags().GetString("repository")
		eco, _ := cmd.Flags().GetString("ecosystem")
		pkg, _ := cmd.Flags().GetString("package")
		version, _ := cmd.Flags().GetString("version")
		repo = strings.TrimSpace(repo)
		eco = strings.TrimSpace(eco)
		pkg = strings.TrimSpace(pkg)
		version = strings.TrimSpace(version)
		// --ecosystem is an accepted alias for --repository. Passing
		// both with different values is a usage error so we don't
		// silently pick one.
		if repo != "" && eco != "" && repo != eco {
			return fmt.Errorf("--repository and --ecosystem both set with different values (%q vs %q); pick one", repo, eco)
		}
		if repo == "" {
			repo = eco
		}
		if repo == "" || pkg == "" || version == "" {
			return fmt.Errorf("--repository (or --ecosystem), --package, and --version are all required (or use --from-file)")
		}
		body = map[string]any{
			"repository": repo,
			"package":    pkg,
			"version":    version,
		}
		reason := strings.TrimSpace(mustString(cmd, "reason"))
		if reason != "" {
			body["reason"] = reason
		}
		applyVEXOverridesFromFlags(body, cveFlag, decisionFlag, vexNoteFlag, reason)
	}
	// Server-side default still applies when expiresAt is the zero time;
	// only stamp expires_at when we have a real value (caller passed a
	// flag OR we computed the defaultExceptionDays fallback).
	if !expiresAt.IsZero() {
		body["expires_at"] = expiresAt.UTC().Format(time.RFC3339)
	}

	var resp struct {
		Entry exceptionItem `json:"entry"`
	}
	if err := client.Post("/api/exceptions", body, &resp); err != nil {
		return err
	}

	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(resp.Entry)
	}
	fmt.Printf("Created exception %s for %s@%s in %s\n",
		resp.Entry.ID, resp.Entry.PackageID, resp.Entry.Version, resp.Entry.Repository)
	return nil
}

// applyVEXOverridesFromFlags layers the VEX-shaped flags (--cve,
// --decision, --vex-note) onto the request body. Empty flag values
// never clobber file-supplied keys, so a --from-file template can
// carry defaults while individual invocations override per-call.
//
// --vex-note falls back to --reason when omitted, matching how
// operators historically used --reason for VEX justification before
// the dedicated flag existed.
func applyVEXOverridesFromFlags(body map[string]any, cve, decision, vexNote, reason string) {
	if cve != "" {
		body["cve"] = cve
	}
	if decision != "" {
		body["decision"] = decision
	}
	note := vexNote
	if note == "" {
		note = strings.TrimSpace(reason)
	}
	if note != "" {
		body["note"] = note
	}
}

// resolveExceptionExpiry picks the expiresAt timestamp for an exception
// from the (mutually-exclusive) --expires-at / --days / --expires flags,
// defaulting to defaultExceptionDays when nothing is supplied. Returns
// the zero time only when the caller explicitly passes --days=0 alone,
// in which case we leave it to the server to apply its own default
// (i.e. "don't stamp expires_at on the request body").
//
// The three flags are aliases for the same concept at different
// abstraction levels — supporting all three is a smoke-spec ask. They
// don't compose; passing more than one with a non-empty value is an
// error so we never silently pick a winner.
func resolveExceptionExpiry(cmd *cobra.Command) (time.Time, error) {
	expiresAtFlag := strings.TrimSpace(mustString(cmd, "expires-at"))
	expiresFlag := strings.TrimSpace(mustString(cmd, "expires"))
	daysFlag, _ := cmd.Flags().GetInt("days")
	daysSet := cmd.Flags().Changed("days")

	set := 0
	if expiresAtFlag != "" {
		set++
	}
	if expiresFlag != "" {
		set++
	}
	if daysSet {
		set++
	}
	if set > 1 {
		return time.Time{}, fmt.Errorf("--expires-at, --days, and --expires are mutually exclusive; pick one")
	}

	switch {
	case expiresAtFlag != "":
		t, err := time.Parse(time.RFC3339, expiresAtFlag)
		if err != nil {
			return time.Time{}, fmt.Errorf("--expires-at: must be RFC3339 (e.g. 2026-06-01T00:00:00Z): %w", err)
		}
		if !t.After(time.Now()) {
			return time.Time{}, fmt.Errorf("--expires-at must be in the future, got %s", t.Format(time.RFC3339))
		}
		return t, nil
	case daysSet:
		if daysFlag < 0 {
			return time.Time{}, fmt.Errorf("--days must be non-negative, got %d", daysFlag)
		}
		if daysFlag == 0 {
			// Explicit opt-out — let the server's default kick in.
			return time.Time{}, nil
		}
		return time.Now().Add(time.Duration(daysFlag) * 24 * time.Hour), nil
	case expiresFlag != "":
		d, err := parseSinceDuration(expiresFlag)
		if err != nil {
			return time.Time{}, fmt.Errorf("--expires: %w", err)
		}
		return time.Now().Add(d), nil
	default:
		return time.Now().Add(defaultExceptionDays * 24 * time.Hour), nil
	}
}

// ── renew ─────────────────────────────────────────────────────────────────────

var exceptionRenewCmd = &cobra.Command{
	Use:   "renew <exception-id>",
	Short: "Renew an exception, resetting its expiry clock",
	Long: "Extends an exception's life by resetting createdAt to now. The server " +
		"recomputes expiresAt from the org's configured exception age. Only " +
		"renewable on allow-mode exceptions that target vulnerable packages.",
	Args: cobra.ExactArgs(1),
	RunE: runExceptionRenew,
}

func init() {
	exceptionRenewCmd.Flags().Bool("json", false, "Print renewed exception as JSON")
	exceptionCmd.AddCommand(exceptionRenewCmd)
}

func runExceptionRenew(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id := strings.TrimSpace(args[0])
	if id == "" {
		return fmt.Errorf("exception id is required")
	}

	var resp struct {
		Entry exceptionItem `json:"entry"`
	}
	if err := client.Post("/api/exceptions/"+id+"/renew", nil, &resp); err != nil {
		return err
	}

	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(resp.Entry)
	}
	fmt.Printf("Renewed exception %s (status: %s, days remaining: %d)\n",
		resp.Entry.ID, resp.Entry.Status, resp.Entry.DaysRemaining)
	return nil
}

// ── delete ────────────────────────────────────────────────────────────────────

var exceptionDeleteCmd = &cobra.Command{
	Use:   "delete <exception-id>",
	Short: "Delete a policy exception",
	Long: `Delete a policy exception by id.

Confirmation handling:
  - When stdin is a TTY, the command prompts ("Delete exception <id>? [y/N]:")
    and aborts without action on anything other than "y". --yes skips the prompt.
  - When stdin is NOT a TTY (CI, piped, scripts), there is no interactive
    prompt to display — the command requires --yes and exits with a clear
    error if it's missing, rather than silently aborting. The old behaviour
    (silent "Aborted." with exit 0 on non-TTY without --yes) made the
    command unusable from scripts without operators noticing.`,
	Args: cobra.ExactArgs(1),
	RunE: runExceptionDelete,
}

func init() {
	exceptionDeleteCmd.Flags().Bool("yes", false, "Skip the interactive confirmation prompt. REQUIRED when stdin is not a TTY (scripts, CI) — otherwise the command exits with an error instead of silently aborting.")
	exceptionDeleteCmd.Flags().Bool("dry-run", false, "Preview what would be deleted without actually deleting")
	exceptionCmd.AddCommand(exceptionDeleteCmd)
	rootCmd.AddCommand(exceptionCmd)
}

func runExceptionDelete(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id := strings.TrimSpace(args[0])
	if id == "" {
		return fmt.Errorf("exception id is required")
	}

	dryRun, _ := cmd.Flags().GetBool("dry-run")
	out := cmd.OutOrStdout()

	if dryRun {
		// Server returns the underlying allow-policy as the target (exception
		// storage is a policy row under the hood), so decode into a generic
		// map and pull the fields the operator cares about.
		dryClient := client.WithHeader(DryRunHeader, "true")
		var preview struct {
			DryRun bool           `json:"dry_run"`
			Would  string         `json:"would"`
			Target map[string]any `json:"target"`
		}
		if err := dryClient.DeleteInto("/api/exceptions/"+id, &preview); err != nil {
			return err
		}
		// Pull the fields most useful for the preview. Fall back to the id
		// if any of them are missing so the line is never empty.
		name, _ := preview.Target["name"].(string)
		if name == "" {
			name = id
		}
		fmt.Fprintf(out, "Would delete exception %q (id=%s)\n", name, id)
		return nil
	}

	yes, _ := cmd.Flags().GetBool("yes")
	if !yes {
		// Non-TTY callers (CI, piped scripts) never see the prompt —
		// PromptConfirm returns false and we'd silently print "Aborted."
		// and exit 0, which masks broken automation. Require --yes
		// explicitly here and exit with a clear error instead.
		if !stdinIsTerminal() {
			return fmt.Errorf("refusing to delete exception %s without --yes (stdin is not a TTY, so there is no confirmation prompt to display). Re-run with --yes to confirm.", id)
		}
		if !PromptConfirm(fmt.Sprintf("Delete exception %q?", id)) {
			fmt.Fprintln(out, "Aborted.")
			return nil
		}
	}

	if err := client.Delete("/api/exceptions/" + id); err != nil {
		return err
	}
	fmt.Printf("Deleted exception %s\n", id)
	return nil
}
