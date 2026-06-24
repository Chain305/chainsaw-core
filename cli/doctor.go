package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/cli/hook"
)

// newDoctorCmd builds a fresh doctor command. Tests use this to avoid
// sharing state with the package-global instance.
func newDoctorCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Diagnose local package-manager wiring and server-install health",
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
	Name       string `json:"name"`
	Installed  bool   `json:"installed"`
	Wired      bool   `json:"wired"`
	ConfigPath string `json:"config_path"`
	Error      string `json:"error,omitempty"`
}

type doctorReport struct {
	Managers   []doctorManagerEntry   `json:"managers"`
	Onboarding *doctorOnboardingState `json:"onboarding,omitempty"`
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

	// Onboarding state is best-effort: no token, no server URL, or an
	// HTTP error all yield nil. The wiring check still runs and the
	// command still exits 0 — an auth hiccup shouldn't make `doctor`
	// fail for a user who just wants to see whether pip is wired.
	if ob := loadDoctorOnboardingState(); ob != nil {
		report.Onboarding = ob
	}

	if useJSON(cmd) {
		return writeJSON(cmd, report)
	}

	if report.Onboarding != nil {
		printDoctorOnboarding(cmd.OutOrStdout(), report.Onboarding)
	}
	printDoctorTable(cmd, cmd.OutOrStdout(), report)

	if warning := chainsawPathWarning(); warning != "" {
		fmt.Fprintln(cmd.ErrOrStderr(), warning)
	}

	passed, failed := 0, 0
	for _, e := range report.Managers {
		if e.Wired {
			passed++
		} else {
			failed++
		}
	}
	emit("cli.doctor.run", map[string]any{
		"checks_passed": passed,
		"checks_failed": failed,
	})
	return nil
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
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "MANAGER\tINSTALLED\tWIRED\tCONFIG")
	for _, e := range report.Managers {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			e.Name,
			formatYesNo(e.Installed, colorize),
			formatYesNo(e.Wired, colorize),
			e.ConfigPath,
		)
	}
	w.Flush()
}

// formatYesNo returns "yes" or "no", optionally coloured green for "yes".
// "no" is left in the default colour per the spec.
func formatYesNo(b bool, colorize bool) string {
	if b {
		if colorize {
			return ansiGreen + "yes" + ansiReset
		}
		return "yes"
	}
	return "no"
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
	enc := json.NewEncoder(cmd.OutOrStdout())
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
