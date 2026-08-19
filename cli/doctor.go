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
			return dispatchDoctorMode(cmd, args)
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
	// HELP TEXT IS BUILT FROM THE FIXED UNICODE SET, NEVER FROM glyphs().
	//
	// This string used to call glyphs() so it would name whatever alphabet the
	// --offline matrix was about to print. That was well-meant and wrong in
	// the one way help text cannot afford: help is built at command-
	// CONSTRUCTION time, and gen-cli-docs constructs the tree on a developer's
	// machine to render how-tos-site/content/cli-reference/doctor.md. So the
	// published reference already varied with the generating host's console —
	// the exact boundary the package rule in glyphs_test.go draws ("never in
	// Short/Long/flag usage"), violated one file over from where it is stated.
	// The Unicode ladder (unicode_decide.go) only widened the set of inputs
	// that could flip it.
	//
	// The console-aware naming did not disappear; it moved to the place that
	// can honour it. doctor_offline.go's legend line is rendered at RUN time
	// from the same resolved set as the rows above it, and is pinned by
	// TestDoctorOffline_LegendMatchesRenderedAlphabet. A fallback-console user
	// reading --help sees the canonical glyph names; the table they then run
	// tells them, in its own alphabet, what it actually drew.
	cmd.Flags().Bool("offline", false, fmt.Sprintf("Air-gap diagnostics (W4): walk every intelligence condition and report whether it runs offline (%s), is degraded (%s), or requires a refreshed bundle (%s). The matrix prints an ASCII alphabet instead on consoles that cannot render these; its legend names whichever set it used. Reads CHAINSAW_INTEL_BUNDLE_PATH and CHAINSAW_OFFLINE_FAIL_MODE.",
		unicodeGlyphs.ok, unicodeGlyphs.warn, unicodeGlyphs.fail))

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

// doctorMode names one of doctor's mutually-exclusive report modes,
// together with the runner that produces it.
type doctorMode struct {
	flags string
	run   func(*cobra.Command, []string) error
}

// dispatchDoctorMode resolves which doctor report to run.
//
// It reads EVERY mode flag up front, for two reasons that used to be two
// separate bugs in one if-chain:
//
//   - --attest was never consulted at all. Its own help text says "Implies
//     --strict", and postAttestation is only reachable from runDoctorStrict,
//     so `chainsaw doctor --bundle-id=<id> --attest` — the exact command in
//     docs/DEPLOYMENT.md step 8 — printed the plain manager table, exited 0
//     ("returns OK"), POSTed nothing, and left applied_at NULL. The operator
//     then concluded the hardening-bundle loop was broken server-side.
//   - The chain dispatched by PRECEDENCE with no conflict detection, so a CI
//     job wired as `doctor --strict --bypass-check` (a natural "check both"
//     reading, since --bypass-check advertises that it "exits 0 even when a
//     config is missing") silently ran only the bypass report and exited 0.
//     The strict gate never ran and nothing said so.
//
// Combining modes is refused rather than ordered: each mode has its own exit
// ladder, and silently honouring one of two requested gates is how a gate
// stops being a gate.
func dispatchDoctorMode(cmd *cobra.Command, args []string) error {
	mode, err := resolveDoctorMode(cmd)
	if err != nil {
		return err
	}
	return mode.run(cmd, args)
}

// resolveDoctorMode picks the single mode to run, or errors when more than
// one was requested. Split out from dispatchDoctorMode so tests can assert
// WHICH mode a flag combination selects against the real resolution logic
// rather than a copy of it.
func resolveDoctorMode(cmd *cobra.Command) (doctorMode, error) {
	getBool := func(name string) bool {
		v, _ := cmd.Flags().GetBool(name)
		return v
	}
	upgradeCheck, fix := getBool("upgrade-check"), getBool("fix")
	bypassCheck := getBool("bypass-check")
	offline := getBool("offline")
	strict, attest := getBool("strict"), getBool("attest")

	var requested []doctorMode
	if upgradeCheck || fix {
		requested = append(requested, doctorMode{"--upgrade-check/--fix", runDoctorUpgradeCheck})
	}
	if bypassCheck {
		requested = append(requested, doctorMode{"--bypass-check", runDoctorBypassCheck})
	}
	if offline {
		requested = append(requested, doctorMode{"--offline", runDoctorOffline})
	}
	if strict || attest {
		requested = append(requested, doctorMode{"--strict/--attest", runDoctorStrict})
	}

	switch len(requested) {
	case 0:
		return doctorMode{"(default)", runDoctor}, nil
	case 1:
		return requested[0], nil
	}

	names := make([]string, 0, len(requested))
	for _, m := range requested {
		names = append(names, m.flags)
	}
	return doctorMode{}, &ExitCodeError{
		Code: ExitUsage,
		Err: fmt.Errorf("doctor modes are mutually exclusive, but %s were requested together; each has its own exit-code ladder, so run them as separate invocations",
			strings.Join(names, " and ")),
	}
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

	// Tally + emit BEFORE the --json early return. runDoctor used to emit
	// cli.doctor.run only on the human path, so every scripted and CI
	// invocation — the population whose blockers the event exists to
	// surface — was invisible to the funnel.
	tally := tallyDoctorManagers(report.Managers)
	cliEmit(telemetry.EventCLIDoctorRun, tally.telemetryProps())

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

	// Remediation footer: a fresh user sees "wired: no" in the table with no
	// idea how to fix it. Name the installed-but-unwired-and-unshimmed managers
	// and the exact command. Deliberately says "not wired" — NOT "unprotected"
	// (a fear claim that outruns what doctor actually knows; doctor is an ops
	// surface, keep it operational).
	//
	// Same slice the telemetry tally reports as installed_failed_checks, so
	// the footer the user reads and the field the funnel reads can never
	// disagree.
	unwired := tally.InstalledFailedChecks
	if len(unwired) > 0 {
		fmt.Fprintf(cmd.OutOrStdout(),
			"\n%d manager(s) installed but not wired: %s\n"+
				"  Wire one:  chainsaw install-hook %s\n"+
				"  Wire all:  chainsaw install-hook --all\n",
			len(unwired), strings.Join(unwired, ", "), unwired[0])
	}

	if warning := chainsawPathWarning(); warning != "" {
		fmt.Fprintln(cmd.ErrOrStderr(), warning)
	}

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

// doctorTally is the manager rollup runDoctor reports to telemetry and
// renders in its remediation footer. Extracted as a pure function of the
// report so it can be tested without executing the command.
type doctorTally struct {
	// ChecksPassed / ChecksFailed / FailedChecks are the ORIGINAL,
	// unchanged dimensions: every registered manager, wired or not.
	ChecksPassed int
	ChecksFailed int
	FailedChecks []string

	// ManagersInstalled and InstalledFailedChecks are additive. They exist
	// because the original three count managers the user does not have:
	// a laptop with only npm installed and wired reports checks_failed: 10
	// with failed_checks [yarn,bun,pip,cargo,maven,gradle,sbt,nuget,go,docker]
	// while the SAME run prints "0 manager(s) installed but not wired".
	//
	// Redefining the original three in place was rejected: they are shipped
	// dimensions with history, and silently changing what they count breaks
	// longitudinal comparison with no marker in the data to say when the
	// meaning changed. Adding fields lets the funnel move over deliberately
	// and keeps both series readable.
	ManagersInstalled     int
	InstalledFailedChecks []string
}

// tallyDoctorManagers rolls up a doctor report's manager rows.
func tallyDoctorManagers(entries []doctorManagerEntry) doctorTally {
	t := doctorTally{FailedChecks: []string{}}
	for _, e := range entries {
		if e.Wired {
			t.ChecksPassed++
		} else {
			t.ChecksFailed++
			// Record WHICH manager isn't wired, not just how many. A
			// shimmed-but-not-config-wired manager still counts as a
			// check that didn't pass.
			t.FailedChecks = append(t.FailedChecks, e.Name)
		}
		if e.Installed {
			t.ManagersInstalled++
			if !e.Wired && !e.Shimmed {
				t.InstalledFailedChecks = append(t.InstalledFailedChecks, e.Name)
			}
		}
	}
	return t
}

// telemetryProps renders the tally as the cli.doctor.run payload.
func (t doctorTally) telemetryProps() map[string]any {
	installedFailed := t.InstalledFailedChecks
	if installedFailed == nil {
		installedFailed = []string{}
	}
	return map[string]any{
		"checks_passed":           t.ChecksPassed,
		"checks_failed":           t.ChecksFailed,
		"failed_checks":           t.FailedChecks,
		"managers_installed":      t.ManagersInstalled,
		"installed_failed_checks": installedFailed,
	}
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
	g := glyphs()
	fmt.Fprintln(w, "Onboarding state")
	if ob.Persona != "" {
		fmt.Fprintf(w, "  persona                   %s\n", ob.Persona)
	} else {
		fmt.Fprintln(w, "  persona                   (not set "+g.dash+" run `chainsaw setup` to pick one)")
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
		// Nine rows in a fixed column. On CP437 done and not-done were the
		// same box, so the checklist reported nothing at all.
		mark := g.fail
		if ob.Steps[row.key] {
			mark = g.ok
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
	return fmt.Sprintf("warning: chainsaw binary at %s is not on PATH %s package managers may not find it", exe, glyphs().dash)
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
