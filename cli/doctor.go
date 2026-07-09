package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/cli/hook"
	"github.com/chain305/chainsaw-core/telemetry"
)

// cliEmit is the indirection the friction-telemetry call sites (doctor,
// setup, install-hook) route through, so tests can capture events without
// standing up a network client. Defaults to the process-wide emit(); same
// nil-safe, disabled-aware semantics. Mirrors guardEmit in guard_nudge.go.
var cliEmit = emit

// newDoctorCmd builds a fresh doctor command. Tests use this to avoid
// sharing state with the package-global instance.
func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "doctor",
		GroupID: GrpDebug,
		Short:   "Diagnose local package-manager wiring and server-install health",
		Long: `Enumerate every supported package manager and report whether its binary
is on PATH and whether the chainsaw-managed block is present in its user
config file.

With --strict, also check project-scope config overrides, registry-
pointing env vars (NPM_CONFIG_REGISTRY, PIP_INDEX_URL, GOPROXY, ...),
lockfiles for hardcoded public-registry URLs, and direct-egress
reachability to public registries. Exits non-zero when any of those
drift signals fire, so CI can wire --strict as a preflight gate.

With --attest, additionally POST the strict report to the configured
Chainsaw server at /api/attestations so the org compliance dashboard
sees this endpoint.

With --upgrade-check, diagnose the local chainsaw-proxy server install
before upgrading: env vars, config YAML parse, data-dir perms, port
availability, upstream-registry reachability, TLS cert validity,
docker-compose version drift, and — critically — any removed flags
(e.g. --embedded-ui) or deprecated env defaults (e.g. CHAINSAW_STRICT_JWT)
that would brick a systemd unit on boot. Exit 0 = safe to upgrade,
1 = warnings worth acknowledging, 2 = breaking changes present. See
MIGRATIONS.md for the manual upgrade path when breaking changes land.

With --fix, apply auto-fixable remediations surfaced by --upgrade-check
(today: chmod 0400 on stale generated_password / generated_jwt_secret
files). Breaking findings are never auto-fixed — operator must
acknowledge.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			upgradeCheck, _ := cmd.Flags().GetBool("upgrade-check")
			fix, _ := cmd.Flags().GetBool("fix")
			if upgradeCheck || fix {
				return runDoctorUpgradeCheck(cmd, args)
			}
			bypassCheck, _ := cmd.Flags().GetBool("bypass-check")
			if bypassCheck {
				return runDoctorBypassCheck(cmd, args)
			}
			offline, _ := cmd.Flags().GetBool("offline")
			if offline {
				return runDoctorOffline(cmd, args)
			}
			strict, _ := cmd.Flags().GetBool("strict")
			if strict {
				return runDoctorStrict(cmd, args)
			}
			return runDoctor(cmd, args)
		},
	}
	cmd.Flags().Bool("strict", false, "Fail (non-zero exit) on any drift: project configs, env overrides, lockfile hits, direct egress reachable.")
	cmd.Flags().Bool("no-egress-probe", false, "With --strict: skip the direct-egress reachability probe and report it as 'skipped' (a distinct sentinel from 'unknown' that never soft-fails). For air-gapped CI where outbound is known-blocked, so the run doesn't eat the ~9s probe timeout.")
	cmd.Flags().Bool("bypass-check", false, "Compare host package-manager config files (.npmrc, pip.conf, ~/.gemrc, cargo config) against the configured chainsaw URL. Reports drift; exits 0 even when a config is missing.")
	cmd.Flags().Bool("attest", false, "POST the strict report to /api/attestations on the configured server. Implies --strict.")
	cmd.Flags().String("device-id", "", "Override the derived device identifier (default: hostname/USER). MDM provisioning scripts use this to assign stable device IDs.")
	cmd.Flags().String("bundle-id", "", "W11 phone-home channel: when set together with --attest, the attest POST body includes bundle_id. The proxy stamps applied_at on the matching hardening_bundles row, closing the MDM-installed bundle loop. MDM-rendered install scripts pre-fill this from the bundle emitted by the admin hardening wizard at /admin/hardening (POST /api/hardening/bundle).")
	cmd.Flags().Bool("upgrade-check", false, "Run server-upgrade-safety diagnostics: compare running schema, flag deprecated flags, check data-dir/TLS/ports. Exit 0=safe, 1=warn, 2=breaking. See MIGRATIONS.md.")
	cmd.Flags().Bool("fix", false, "Apply auto-fixable remediations from --upgrade-check (e.g. chmod 0400 on generated_* files, generate JWT secret). Breaking findings are never auto-fixed.")
	cmd.Flags().String("config", "", "Path to chainsaw-proxy YAML config (for --upgrade-check). Defaults to $CHAINSAW_CONFIG.")
	cmd.Flags().String("data-dir", "", "Path to chainsaw data directory (for --upgrade-check). Defaults to $CHAINSAW_DATA_DIR or /etc/chainsaw/data.")
	cmd.Flags().String("docker-compose-path", "", "Path to docker-compose.yml for version-drift check (for --upgrade-check). Empty disables the check.")
	cmd.Flags().Bool("skip-network", false, "Skip upstream-registry reachability probes (for --upgrade-check). Use in air-gapped environments.")
	cmd.Flags().Bool("offline", false, "Air-gap diagnostics (W4): walk every intelligence condition and report whether it runs offline (✓), is degraded (⚠), or requires a refreshed bundle (✗). Reads CHAINSAW_INTEL_BUNDLE_PATH and CHAINSAW_OFFLINE_FAIL_MODE.")

	// `chainsaw doctor verify-hook <manager>` — close the
	// install-hook → audit feedback loop (OBSERVABILITY_AUDIT gap 2).
	// See doctor_verify_hook.go for the rationale and per-manager driver
	// registry.
	cmd.AddCommand(newDoctorVerifyHookCmd())
	return cmd
}

func init() {
	rootCmd.AddCommand(newDoctorCmd())
}

type doctorManagerEntry struct {
	Name      string `json:"name"`
	Installed bool   `json:"installed"`
	Wired     bool   `json:"wired"`
	// Shimmed is true when this manager is routed through the `chainsaw guard
	// init` shell-function shim (detected from the user's shell rc files) even
	// though its config file is not wired. Protected, via a different mechanism.
	Shimmed    bool   `json:"shimmed,omitempty"`
	ConfigPath string `json:"config_path"`
	Error      string `json:"error,omitempty"`
}

type doctorReport struct {
	Managers   []doctorManagerEntry   `json:"managers"`
	Onboarding *doctorOnboardingState `json:"onboarding,omitempty"`
	// OrgSlug carries the wrong-org-slug probe verdict (WS2 #10). Omitted
	// when the check was skipped with no server configured (the free
	// local-guard case needs no slug). A WRONG_SLUG outcome here means the
	// guard would NOT fire — the command exits non-zero.
	OrgSlug *orgSlugResult `json:"org_slug,omitempty"`
}

// doctorOnboardingState is the /api/onboarding/progress response
// shape — persona and the 12 boolean setup steps. Omitted from
// JSON output when the CLI isn't authenticated (no sense in an
// empty object). Mirrors the dashboard setup checklist and the
// MCP chainsaw_onboarding_state tool; agents and humans see the
// same state indicators.
type doctorOnboardingState struct {
	Persona string          `json:"persona"`
	Steps   map[string]bool `json:"steps"`
}

func runDoctor(cmd *cobra.Command, _ []string) error {
	report := doctorReport{}
	for _, m := range hook.All() {
		entry := doctorManagerEntry{Name: m.Name()}
		st, err := m.Status()
		if err != nil {
			entry.Error = err.Error()
		}
		entry.ConfigPath = st.ConfigPath
		entry.Installed = st.Installed
		entry.Wired = st.Wired
		// Status may return a zero-value ConfigPath if it errored early;
		// fall back to asking the manager directly so doctor always prints
		// a useful path.
		if entry.ConfigPath == "" {
			if p, perr := m.ConfigPath(); perr == nil {
				entry.ConfigPath = p
			}
		}
		report.Managers = append(report.Managers, entry)
	}

	// A config file that isn't wired doesn't mean "unprotected": `chainsaw guard
	// init` shims npm/pip/go at the shell level. Detect that so the table can
	// tell the truth instead of flatly reporting "no".
	shimInstalled, shimSource := detectGuardShim(shellRCCandidates())
	if shimInstalled {
		guarded := guardedManagerSet()
		for i := range report.Managers {
			if guarded[report.Managers[i].Name] {
				report.Managers[i].Shimmed = true
			}
		}
	}

	// Onboarding state is best-effort: no token, no server URL, or an
	// HTTP error all yield nil. The wiring check still runs and the
	// command still exits 0 — an auth hiccup shouldn't make `doctor`
	// fail for a user who just wants to see whether pip is wired.
	if ob := loadDoctorOnboardingState(); ob != nil {
		report.Onboarding = ob
	}

	if useJSON(cmd) {
		// WS2 #10: attach the wrong-org-slug verdict to the JSON report, then
		// still fail non-zero when it's a genuine wrong slug so CI branches on
		// the exit code, not just the payload. Emit the report first so the
		// caller always gets the structured result even on the fail path.
		report.OrgSlug = orgSlugResultForJSON(cmd)
		if err := writeJSON(cmd, report); err != nil {
			return err
		}
		if report.OrgSlug != nil && report.OrgSlug.Outcome == orgSlugWrongSlug {
			cliEmit(telemetryEventDoctorOrgSlug, map[string]any{
				"outcome":    string(report.OrgSlug.Outcome),
				"error_code": report.OrgSlug.ErrorCode,
			})
			return &orgSlugCheckError{res: *report.OrgSlug}
		}
		return nil
	}

	if report.Onboarding != nil {
		printDoctorOnboarding(cmd.OutOrStdout(), report.Onboarding)
	}
	printDoctorTable(cmd, cmd.OutOrStdout(), report)

	// Explain the "shim" state once, when it's actually showing for a manager
	// that isn't config-wired — otherwise the column is self-explanatory.
	anyShimOnly := false
	for _, e := range report.Managers {
		if e.Shimmed && !e.Wired {
			anyShimOnly = true
			break
		}
	}
	if anyShimOnly {
		fmt.Fprintf(cmd.OutOrStdout(),
			"\nshim = routed through the shell guard (`chainsaw guard init` in %s); installs are\n"+
				"       checked, the manager's own config is left untouched. \"yes\" means the config\n"+
				"       file also points at chainsaw (survives outside your shell, e.g. CI).\n",
			shimSource)
	}

	if warning := chainsawPathWarning(); warning != "" {
		fmt.Fprintln(cmd.ErrOrStderr(), warning)
	}

	passed, failed := 0, 0
	failedChecks := []string{}
	for _, e := range report.Managers {
		if e.Wired {
			passed++
		} else {
			failed++
			// Record WHICH manager isn't wired, not just how many. Lets the
			// funnel surface the most common blocker (e.g. "npm" dominating
			// failed_checks) instead of an opaque count. A shimmed-but-not-
			// config-wired manager still counts as a check that didn't pass.
			failedChecks = append(failedChecks, e.Name)
		}
	}
	cliEmit(telemetry.EventCLIDoctorRun, map[string]any{
		"checks_passed": passed,
		"checks_failed": failed,
		"failed_checks": failedChecks,
	})

	// WS2 #10 (load-bearing): the wrong-org-slug check. Probes the org-scoped
	// repo path and, on a genuine CHW-4314/CHW-1303 rejection, prints the
	// explicit "block did NOT fire" remediation and returns a non-zero error.
	// A valid slug passes silently; a transient network error degrades to a
	// note and never false-positives. Runs LAST so its verdict is the closing
	// signal — a security tool must fail closed and loud on a silent-insecure
	// config. Kept out of the manager loop above so its exit semantics (loud,
	// non-zero) stay independent of the wiring table.
	return runDoctorOrgSlugCheck(cmd, false)
}

// loadDoctorOnboardingState calls /api/onboarding/progress. Returns
// nil on any failure — this is a diagnostic enhancement, never a
// blocking check.
func loadDoctorOnboardingState() *doctorOnboardingState {
	server := cfgServerURL()
	token := cfgToken()
	if server == "" || token == "" {
		return nil
	}
	client := NewAPIClient(server, token)
	var resp doctorOnboardingState
	if err := client.Get("/api/onboarding/progress", &resp); err != nil {
		return nil
	}
	return &resp
}

// printDoctorOnboarding renders the onboarding checklist in doctor's
// human-readable output. Step order is deliberate (most-common-first
// so new users see their obvious blockers at the top). Matches the
// canonical ordering used by the MCP chainsaw_onboarding_state tool —
// if a new step lands, update both places.
func printDoctorOnboarding(w io.Writer, ob *doctorOnboardingState) {
	fmt.Fprintln(w, "Onboarding state")
	if ob.Persona != "" {
		fmt.Fprintf(w, "  persona                   %s\n", ob.Persona)
	} else {
		fmt.Fprintln(w, "  persona                   (not set — run `chainsaw setup` to pick one)")
	}
	order := []struct {
		key   string
		label string
	}{
		{"client_created", "client_credential exists"},
		{"ci_service_token_created", "CI service token exists"},
		{"package_ingested", "packages proxied"},
		{"policy_applied", "policies applied"},
		{"sso_configured", "SSO configured"},
		{"siem_webhook_added", "SIEM/webhook configured"},
		{"scim_enabled", "SCIM enabled"},
		{"admin_team_invited", "second admin present"},
		{"teammate_invited", "teammates invited"},
	}
	for _, row := range order {
		mark := "✗"
		if ob.Steps[row.key] {
			mark = "✓"
		}
		fmt.Fprintf(w, "  %s %s\n", mark, row.label)
	}
	fmt.Fprintln(w)
}

func printDoctorTable(cmd *cobra.Command, out io.Writer, report doctorReport) {
	colorize := IsColorEnabled(cmd)

	const (
		hManager   = "MANAGER"
		hInstalled = "INSTALLED"
		hWired     = "WIRED"
		hConfig    = "CONFIG"
	)
	// Column widths are measured against the PLAIN (uncoloured) cell text.
	// text/tabwriter counts ANSI escape bytes as visible width, so a coloured
	// "yes" reads as ~12 columns wide instead of 3 — which is what collapsed the
	// INSTALLED/WIRED columns into each other. We pad by hand against the plain
	// width instead, then drop the colour onto the already-sized cell.
	wManager, wInstalled, wWired := len(hManager), len(hInstalled), len(hWired)
	for _, e := range report.Managers {
		wManager = max(wManager, len(e.Name))
		wInstalled = max(wInstalled, len(plainYesNo(e.Installed)))
		wWired = max(wWired, len(plainWired(e)))
	}

	const gap = "  "
	padTo := func(plain string, width int) string {
		if n := width - len(plain); n > 0 {
			return strings.Repeat(" ", n)
		}
		return ""
	}

	fmt.Fprint(out,
		hManager+padTo(hManager, wManager)+gap+
			hInstalled+padTo(hInstalled, wInstalled)+gap+
			hWired+padTo(hWired, wWired)+gap+
			hConfig+"\n")
	for _, e := range report.Managers {
		inst, wired := plainYesNo(e.Installed), plainWired(e)
		fmt.Fprint(out,
			e.Name+padTo(e.Name, wManager)+gap+
				colorYesNo(e.Installed, colorize)+padTo(inst, wInstalled)+gap+
				colorWired(e, colorize)+padTo(wired, wWired)+gap+
				e.ConfigPath+"\n")
	}
}

// plainWired is the uncoloured WIRED cell text. "yes" = config-file wired,
// "shim" = shell-function guard active but config untouched, "no" = neither.
func plainWired(e doctorManagerEntry) string {
	switch {
	case e.Wired:
		return "yes"
	case e.Shimmed:
		return "shim"
	default:
		return "no"
	}
}

// colorWired renders the WIRED cell: green "yes" (fully wired), yellow "shim"
// (partial — shell only), default "no". Padding is applied by the caller
// against plainWired so escape bytes never enter the width calculation.
func colorWired(e doctorManagerEntry, colorize bool) string {
	s := plainWired(e)
	if !colorize {
		return s
	}
	switch s {
	case "yes":
		return ansiGreen + s + ansiReset
	case "shim":
		return ansiYellow + s + ansiReset
	}
	return s
}

// plainYesNo is the uncoloured cell text, used for width math.
func plainYesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// colorYesNo renders the cell, optionally colouring "yes" green. "no" is left
// in the default colour per the spec. Padding is applied by the caller against
// plainYesNo so the escape bytes never enter the width calculation.
func colorYesNo(b bool, colorize bool) string {
	if b && colorize {
		return ansiGreen + "yes" + ansiReset
	}
	return plainYesNo(b)
}

// chainsawPathWarning returns a warning string if the running chainsaw
// binary is not located in a directory on $PATH. Empty string means
// "nothing to warn about" — either the binary path is resolvable and on
// PATH, or os.Executable() failed (in which case we silently skip per
// the spec).
func chainsawPathWarning() string {
	exe, err := os.Executable()
	if err != nil || exe == "" {
		return ""
	}
	dir := filepath.Dir(exe)
	for _, p := range strings.Split(os.Getenv("PATH"), string(os.PathListSeparator)) {
		if p == "" {
			continue
		}
		if p == dir {
			return ""
		}
	}
	return fmt.Sprintf("warning: chainsaw binary at %s is not on PATH — package managers may not find it", exe)
}

// writeJSON is a small helper that matches the json.Encoder + SetIndent
// pattern used by version.go. Shared by doctor, install-hook, and
// uninstall-hook so their JSON output stays byte-identical in shape.
func writeJSON(cmd *cobra.Command, v any) error {
	// Honor --output (invariant C): the JSON result lands in the file when set.
	// The no-file fallback is cmd.OutOrStdout() (not raw os.Stdout) so cobra's
	// SetOut redirection stays intact — byte-identical to the previous path.
	enc := json.NewEncoder(outWriterOr(cmd, cmd.OutOrStdout()))
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
