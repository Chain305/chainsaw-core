package cli

// doctor_verify_hook.go — `chainsaw doctor verify-hook <manager>` (Wave AH gap 2).
//
// The OBSERVABILITY_AUDIT.md gap 2 motivation: three Wave AG bugs were
// invisible to chainsaw because the *client tool* (bun, swift, docker)
// decided the proxy was broken / unreachable / non-existent and fell back
// to upstream directly. install-hook writes the config but never proves
// the wire works — verify-hook closes that loop by driving a synthetic
// install through the configured manager and confirming the proxy
// actually received the request.
//
// Design:
//   - One sentinel package coordinate per run: chainsaw-verify-<hex>-<ts>.
//     Deliberately not a real package — the install MUST fail upstream.
//     What we're verifying is that the proxy *saw* the attempt.
//   - Per-manager driver builds the right install command. The install is
//     expected to fail (404 / unknown package). We swallow the failure
//     and instead query /api/events?package_name=<sentinel> to confirm
//     receipt.
//   - Three outcomes:
//        PASS  — proxy saw the sentinel (the hook works)
//        FAIL  — proxy did NOT see the sentinel within timeout (BYPASS:
//                client routed direct to upstream)
//        DEGRADED — we couldn't reach the audit API to confirm; print a
//                  one-liner the user can run themselves
//   - Fail-closed only for unambiguous bypass. Inability to reach the
//     audit API (CI runners often can't) degrades, doesn't fail — same
//     posture as the rest of the doctor surface.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/cli/hook"
)

// verifyOutcome is the three-valued outcome of a verify-hook run.
type verifyOutcome string

const (
	verifyPass     verifyOutcome = "PASS"
	verifyFail     verifyOutcome = "FAIL"
	verifyDegraded verifyOutcome = "DEGRADED"
)

// verifyResult is the JSON shape printed for a verify-hook run. Stable
// across managers so CI scripts can parse it without branching.
type verifyResult struct {
	Manager   string        `json:"manager"`
	Sentinel  string        `json:"sentinel"`
	Outcome   verifyOutcome `json:"outcome"`
	Reason    string        `json:"reason,omitempty"`
	Hint      string        `json:"hint,omitempty"`
	GrepHint  string        `json:"grep_hint,omitempty"`
	Duration  string        `json:"duration"`
	InstallOK bool          `json:"install_ok"`
}

// verifyDriver is the per-manager strategy for driving a synthetic install
// + recognising the install actually attempted (vs failed before the
// network). All drivers return the executed cmd's combined output for
// inclusion in --verbose diagnostics, but the verdict comes from the
// audit-API receipt confirmation, not from the cmd's exit code.
type verifyDriver interface {
	// Manager returns the short name of the wired manager this driver
	// covers. Must match a hook.Manager.Name() — the registry tripwire
	// (TestVerifyHookKnowsAllInstallHookManagers) asserts this.
	Manager() string
	// Drive synthesises an install for sentinelCoord and returns the
	// raw combined output of the per-manager command. The error is
	// the *cmd* error — for verify-hook this is expected (sentinel
	// doesn't exist upstream) so callers ignore it and use the audit
	// API to confirm receipt.
	Drive(ctx context.Context, sentinelCoord string) ([]byte, error)
	// BypassHint returns the per-manager remediation string surfaced
	// when verify yields FAIL. Specific enough to point at the known
	// bypass class (e.g. bun → "use .npmrc, not bunfig.toml").
	BypassHint() string
}

// verifyDrivers is the canonical registry. Adding a manager: implement
// verifyDriver, register here, and TestVerifyHookKnowsAllInstallHookManagers
// will start passing for it.
//
// v1 scope: npm, bun, docker (covers the two Wave AG bypass classes).
// v1 stretch: pip, cargo (safe-case baselines).
// Deferred: swift, yarn, maven, gradle, sbt, nuget, go.
func verifyDrivers() map[string]verifyDriver {
	return map[string]verifyDriver{
		"npm":    npmVerifyDriver{},
		"bun":    bunVerifyDriver{},
		"docker": dockerVerifyDriver{},
		"pip":    pipVerifyDriver{},
		"cargo":  cargoVerifyDriver{},
	}
}

// verifyDriverFor returns the driver for the given manager name, or an
// error listing the explicitly-unsupported managers when we know the
// hook surface exists but verify doesn't cover it yet.
func verifyDriverFor(name string) (verifyDriver, error) {
	if d, ok := verifyDrivers()[name]; ok {
		return d, nil
	}
	// If install-hook knows about the manager but verify doesn't, give
	// a specific deferred-coverage message rather than the generic
	// "unknown manager" string. Helps users distinguish a typo from a
	// known gap.
	if _, err := hook.ByName(name); err == nil {
		return nil, fmt.Errorf("verify not yet supported for %q (known managers without verify coverage: swift, yarn, maven, gradle, sbt, nuget, go); file a follow-up if you need it", name)
	}
	supported := make([]string, 0, len(verifyDrivers()))
	for k := range verifyDrivers() {
		supported = append(supported, k)
	}
	return nil, fmt.Errorf("unknown package manager %q; verify supports: %s", name, strings.Join(supported, ", "))
}

// newDoctorVerifyHookCmd builds the `chainsaw doctor verify-hook` subcommand.
// Tests instantiate it directly to avoid sharing flag state with the
// package-global registration.
func newDoctorVerifyHookCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "verify-hook <manager>",
		Short: "Drive a synthetic install through a wired manager and confirm the proxy saw it",
		Long: `Catch client-side bypasses (OBSERVABILITY_AUDIT gap 2).

install-hook writes the manager's config block, but never proves the wire
actually works. Multiple Wave AG bugs were INVISIBLE to chainsaw because
the client tool (bun, docker, swift) decided the proxy was broken or the
refspec invalid and fell back to upstream directly — bypassing the proxy
entirely.

verify-hook drives a synthetic install through the configured manager
using a sentinel package coordinate (chainsaw-verify-<hex>-<ts>), waits
for the request to land in the audit log, and reports PASS / FAIL /
DEGRADED:

  PASS      proxy saw the sentinel — the hook is wired and routing.
  FAIL      proxy did NOT see the sentinel — the client tool bypassed
            chainsaw. Output includes a manager-specific remediation hint.
  DEGRADED  could not reach /api/events to confirm receipt. Verification
            ran but cannot prove the result. A one-liner is printed so
            you can grep the proxy logs yourself.

The synthetic install is *expected* to fail upstream (the sentinel is
not a real package). What we're verifying is that the proxy received
the attempt — not that an install succeeded.

v1 managers: npm, bun, docker, pip, cargo.
Deferred: swift, yarn, maven, gradle, sbt, nuget, go.

Examples:
  chainsaw doctor verify-hook bun
  chainsaw doctor verify-hook docker --timeout 60s
  chainsaw --server https://chainsaw.example doctor verify-hook npm --json`,
		RunE: runDoctorVerifyHook,
		Args: cobra.ExactArgs(1),
	}
	c.Flags().Duration("timeout", 30*time.Second, "Maximum time to wait for the sentinel to appear in the audit log.")
	c.Flags().Bool("verbose", false, "Print the executed manager command and its raw output.")
	return c
}

// runDoctorVerifyHook is the cobra RunE entry point. Splits into:
//  1. Resolve the driver for the manager.
//  2. Generate a sentinel coordinate.
//  3. Drive the install (swallow the expected cmd failure).
//  4. Poll the audit API for the sentinel.
//  5. Render PASS / FAIL / DEGRADED + exit code.
func runDoctorVerifyHook(cmd *cobra.Command, args []string) error {
	manager := strings.TrimSpace(args[0])
	driver, err := verifyDriverFor(manager)
	if err != nil {
		return err
	}
	timeout, _ := cmd.Flags().GetDuration("timeout")
	verbose, _ := cmd.Flags().GetBool("verbose")

	sentinel, err := newSentinelCoord()
	if err != nil {
		return fmt.Errorf("generate sentinel: %w", err)
	}

	start := time.Now()
	driveCtx, driveCancel := context.WithTimeout(cmd.Context(), 60*time.Second)
	defer driveCancel()
	output, driveErr := driver.Drive(driveCtx, sentinel)
	installOK := driveErr == nil
	// The install IS expected to fail upstream (sentinel doesn't exist).
	// We log the error in verbose mode but don't bail — what we care
	// about is whether the proxy saw the request.

	confirmCtx, confirmCancel := context.WithTimeout(cmd.Context(), timeout)
	defer confirmCancel()
	receipt := pollAuditReceipt(confirmCtx, sentinel)

	res := verifyResult{
		Manager:   manager,
		Sentinel:  sentinel,
		Duration:  time.Since(start).Round(time.Millisecond).String(),
		InstallOK: installOK,
	}
	switch receipt.outcome {
	case verifyPass:
		res.Outcome = verifyPass
		res.Reason = fmt.Sprintf("proxy received %d event(s) matching sentinel", receipt.matchCount)
	case verifyFail:
		res.Outcome = verifyFail
		res.Reason = "proxy never saw the sentinel — client bypassed chainsaw"
		res.Hint = driver.BypassHint()
	case verifyDegraded:
		res.Outcome = verifyDegraded
		res.Reason = receipt.degradedReason
		res.GrepHint = grepHintFor(sentinel)
	}

	if useJSON(cmd) {
		if verbose && len(output) > 0 {
			// In JSON mode the verbose output rides as a separate key so
			// callers can ignore it without parsing free-form text.
			return writeJSON(cmd, map[string]any{
				"result":         res,
				"command_output": string(output),
				"command_error":  errString(driveErr),
			})
		}
		if err := writeJSON(cmd, res); err != nil {
			return err
		}
	} else {
		printVerifyResult(cmd, res, verbose, output, driveErr)
	}

	emit("cli.doctor.verify_hook", map[string]any{
		"manager":  manager,
		"outcome":  string(res.Outcome),
		"sentinel": sentinel,
	})

	switch res.Outcome {
	case verifyPass:
		return nil
	case verifyFail:
		// Exit 1 so CI gates can wire this as a preflight check.
		os.Exit(1)
	case verifyDegraded:
		// Exit 0 so a flaky network doesn't break CI. The output still
		// makes clear we couldn't confirm.
		return nil
	}
	return nil
}

// newSentinelCoord returns a unique-per-run package coordinate of the
// form `chainsaw-verify-<8hex>-<unix-seconds>`. Chosen for:
//   - lower-case + dash → valid in every ecosystem's name grammar
//   - leading "chainsaw-verify-" → instantly recognisable in audit drawer
//   - 8 hex bytes + unix time → ~2^32 collision space per second, plenty
func newSentinelCoord() (string, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return fmt.Sprintf("chainsaw-verify-%s-%d", hex.EncodeToString(buf), time.Now().Unix()), nil
}

// errString flattens an error to a string for JSON output, returning "" for nil.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// grepHintFor returns a one-liner the user can copy-paste to grep the
// proxy logs themselves when the audit API is unreachable. Used in
// DEGRADED output so verify-hook is still useful in air-gapped CI.
func grepHintFor(sentinel string) string {
	return fmt.Sprintf("kubectl logs -n chainsaw -l app=chainsaw-proxy --tail=500 | grep %s", sentinel)
}

// receiptResult bundles the audit-API poll outcome.
type receiptResult struct {
	outcome        verifyOutcome
	matchCount     int
	degradedReason string
}

// pollAuditReceipt queries /api/events?package_name=<sentinel> on a poll
// interval until either the sentinel appears (PASS), the context times
// out (FAIL), or we hit a non-recoverable transport error (DEGRADED).
//
// Why poll: the proxy writes the event row asynchronously (via
// auditBuffer.add → batched DB insert), so a single GET right after the
// install can race. 500ms poll with a 30s default timeout matches the
// dashboard refresh cadence.
//
// Why /api/events: it's the existing, permissioned audit query surface
// (server_bom_events.go::handleEvents) and already supports
// `?package_name=<partial>` LIKE matching. No new endpoint required.
func pollAuditReceipt(ctx context.Context, sentinel string) receiptResult {
	server := strings.TrimSpace(cfgServerURL())
	token := strings.TrimSpace(cfgToken())
	if server == "" {
		return receiptResult{outcome: verifyDegraded, degradedReason: "no server configured (set --server or run `chainsaw auth login`)"}
	}
	if token == "" {
		return receiptResult{outcome: verifyDegraded, degradedReason: "not authenticated to query the audit log (run `chainsaw auth login`)"}
	}
	client := newClient()
	path := "/api/events?package_name=" + url.QueryEscape(sentinel) + "&limit=10"

	// First call: classify the error class. If the audit API is
	// reachable AND the sentinel is already there, return PASS
	// immediately. If unreachable, return DEGRADED without polling
	// (no point — 30 polls of the same transport error doesn't help).
	var resp eventsResponseEnvelope
	firstErr := client.Get(path, &resp)
	if firstErr != nil {
		return receiptResult{outcome: verifyDegraded, degradedReason: fmt.Sprintf("audit API unreachable: %v", firstErr)}
	}
	if resp.Total > 0 || matchSentinelInEvents(resp.Events, sentinel) {
		return receiptResult{outcome: verifyPass, matchCount: countSentinelMatches(resp.Events, sentinel, resp.Total)}
	}

	// Audit API is reachable; poll until timeout or match.
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return receiptResult{outcome: verifyFail}
		case <-ticker.C:
			var poll eventsResponseEnvelope
			if err := client.Get(path, &poll); err != nil {
				// Transient — keep polling. If it stays broken until
				// timeout, we'll fall through to FAIL, which is
				// arguably wrong (degraded would be safer). Bias the
				// other way: if the FIRST call worked, subsequent
				// failures are transient.
				continue
			}
			if poll.Total > 0 || matchSentinelInEvents(poll.Events, sentinel) {
				return receiptResult{outcome: verifyPass, matchCount: countSentinelMatches(poll.Events, sentinel, poll.Total)}
			}
		}
	}
}

// eventsResponseEnvelope is the minimal subset of /api/events we read.
// Fields match server_bom_events.go::handleEvents output; we declare
// only what we use so a server-side rename of unrelated fields can't
// break the CLI.
type eventsResponseEnvelope struct {
	Total  int                  `json:"total"`
	Events []eventsResponseItem `json:"events"`
}

type eventsResponseItem struct {
	RequestedPackage string `json:"requested_package"`
	EventType        string `json:"event_type"`
}

// matchSentinelInEvents reports whether any event's requested_package
// contains the sentinel substring. The server-side LIKE filter already
// did this work, but we defend against the off-chance the filter is
// ignored (older server, schema drift) by re-checking client-side.
func matchSentinelInEvents(items []eventsResponseItem, sentinel string) bool {
	for _, it := range items {
		if strings.Contains(it.RequestedPackage, sentinel) {
			return true
		}
	}
	return false
}

// countSentinelMatches prefers the server's total when it's non-zero
// (the server has the canonical count post-filter) and falls back to
// the client-side count for the safety-net case above.
func countSentinelMatches(items []eventsResponseItem, sentinel string, total int) int {
	if total > 0 {
		return total
	}
	n := 0
	for _, it := range items {
		if strings.Contains(it.RequestedPackage, sentinel) {
			n++
		}
	}
	return n
}

// printVerifyResult renders the human-readable output. JSON-mode callers
// route around this entirely.
func printVerifyResult(cmd *cobra.Command, res verifyResult, verbose bool, cmdOut []byte, cmdErr error) {
	out := cmd.OutOrStdout()
	errOut := cmd.ErrOrStderr()
	switch res.Outcome {
	case verifyPass:
		fmt.Fprintf(out, "PASS  %s: proxy saw sentinel %s (%s)\n", res.Manager, res.Sentinel, res.Duration)
	case verifyFail:
		fmt.Fprintf(errOut, "FAIL  %s: proxy never saw sentinel %s (%s)\n", res.Manager, res.Sentinel, res.Duration)
		fmt.Fprintf(errOut, "      cause: %s\n", res.Reason)
		if res.Hint != "" {
			fmt.Fprintf(errOut, "      fix:   %s\n", res.Hint)
		}
	case verifyDegraded:
		fmt.Fprintf(errOut, "DEGRADED  %s: verify ran but could not confirm proxy receipt (%s)\n", res.Manager, res.Duration)
		fmt.Fprintf(errOut, "          reason: %s\n", res.Reason)
		if res.GrepHint != "" {
			fmt.Fprintf(errOut, "          to confirm manually: %s\n", res.GrepHint)
		}
	}
	if verbose {
		fmt.Fprintf(errOut, "\n--- manager command output ---\n%s", string(cmdOut))
		if cmdErr != nil {
			fmt.Fprintf(errOut, "\n--- manager command error (expected for sentinel) ---\n%v\n", cmdErr)
		}
	}
}

// --- per-manager drivers ---

// npmVerifyDriver drives `npm install` against the configured registry.
// The .npmrc written by install-hook npm points at the chainsaw proxy;
// npm honours user-scope .npmrc on every install, so a plain `npm
// install` is enough to exercise the wire. Runs in a tempdir so we
// don't touch the user's project.
type npmVerifyDriver struct{}

func (npmVerifyDriver) Manager() string { return "npm" }
func (npmVerifyDriver) Drive(ctx context.Context, sentinel string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "chainsaw-verify-npm-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	// Empty package.json so `npm install <pkg>` doesn't error out on
	// missing manifest.
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"chainsaw-verify","version":"0.0.0","private":true}`), 0o600); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "npm", "install", "--no-save", "--no-audit", "--no-fund", sentinel)
	cmd.Dir = dir
	return cmd.CombinedOutput()
}
func (npmVerifyDriver) BypassHint() string {
	return "check ~/.npmrc has `registry=` and a `:_authToken=` line pointing at the chainsaw proxy. Run `chainsaw doctor` for the per-manager view, then `chainsaw install-hook npm` to re-wire."
}

// bunVerifyDriver drives `bun add` — exercises the exact Wave U bypass
// class (bun 1.3.12 ignored bunfig.toml URL-embedded auth and fell back
// to registry.npmjs.org). Because install-hook bun now writes .npmrc
// (Wave U) the PASS path proves the npm-compat layer is honouring the
// proxy; the FAIL path means bun ignored .npmrc too, which would be a
// new regression worth filing.
type bunVerifyDriver struct{}

func (bunVerifyDriver) Manager() string { return "bun" }
func (bunVerifyDriver) Drive(ctx context.Context, sentinel string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "chainsaw-verify-bun-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"chainsaw-verify","version":"0.0.0","private":true}`), 0o600); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "bun", "add", "--no-save", sentinel)
	cmd.Dir = dir
	return cmd.CombinedOutput()
}
func (bunVerifyDriver) BypassHint() string {
	return "bun is ignoring your chainsaw config. Common causes: (a) bunfig.toml shadowing .npmrc with a public registry; (b) bun 1.3.12 ignores bunfig.toml install.registry — chainsaw install-hook bun writes .npmrc instead (Wave U). Re-run `chainsaw install-hook bun` and remove any [install.registry] block from bunfig.toml."
}

// dockerVerifyDriver drives `docker pull` against the chainsaw mirror
// path. The pull is expected to 404 (sentinel image doesn't exist), but
// the request still flows through registry-mirrors and lands in the
// audit log — unless the daemon never read daemon.json or the refspec
// was rejected client-side (Wave AG: docker rejected `@` in refspecs
// before chainsaw ever saw the request).
type dockerVerifyDriver struct{}

func (dockerVerifyDriver) Manager() string { return "docker" }
func (dockerVerifyDriver) Drive(ctx context.Context, sentinel string) ([]byte, error) {
	server := strings.TrimSpace(cfgServerURL())
	if server == "" {
		return nil, fmt.Errorf("docker verify requires --server (no chainsaw mirror to pull from)")
	}
	host, err := serverHostForDockerPull(server)
	if err != nil {
		return nil, err
	}
	// Pull a coordinate that names the sentinel as the "tag" — that way
	// the sentinel surfaces in the requested_package field of /api/events
	// the same way other ecosystems do (package_name match).
	ref := fmt.Sprintf("%s/chainproxy/docker-hub/library/%s:nonexistent", host, sentinel)
	cmd := exec.CommandContext(ctx, "docker", "pull", ref)
	return cmd.CombinedOutput()
}
func (dockerVerifyDriver) BypassHint() string {
	return "docker is not routing through the chainsaw mirror. Common causes: (a) daemon.json missing `registry-mirrors`; (b) docker daemon not restarted after install-hook (`sudo systemctl reload docker` or restart Docker Desktop); (c) refspec rejected client-side before the daemon contacts the mirror (Wave AG: docker rejects `@` in refspecs). Run `chainsaw install-hook docker` and restart the daemon."
}

// pipVerifyDriver drives `pip install` against the configured index-url.
// pip honours user-scope pip.conf via PIP_CONFIG_FILE / the standard
// search path. --dry-run keeps the install side-effect-free.
type pipVerifyDriver struct{}

func (pipVerifyDriver) Manager() string { return "pip" }
func (pipVerifyDriver) Drive(ctx context.Context, sentinel string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "pip", "install", "--dry-run", "--no-deps", "--disable-pip-version-check", sentinel)
	return cmd.CombinedOutput()
}
func (pipVerifyDriver) BypassHint() string {
	return "pip is not using the chainsaw index. Check ~/.pip/pip.conf (or $PIP_CONFIG_FILE) has `index-url = https://<chainsaw>/repository/@<org>/pypi/simple/`. Re-run `chainsaw install-hook pip`."
}

// cargoVerifyDriver drives a cargo fetch against the configured registry.
// Cargo's lookup model means we have to scaffold a temporary Cargo.toml
// referencing the sentinel as a dep, then run `cargo fetch` in that dir.
type cargoVerifyDriver struct{}

func (cargoVerifyDriver) Manager() string { return "cargo" }
func (cargoVerifyDriver) Drive(ctx context.Context, sentinel string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "chainsaw-verify-cargo-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	manifest := fmt.Sprintf(`[package]
name = "chainsaw-verify"
version = "0.0.0"
edition = "2021"

[dependencies]
%s = "0.0.1"
`, sentinel)
	if err := os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(manifest), 0o600); err != nil {
		return nil, err
	}
	srcDir := filepath.Join(dir, "src")
	if err := os.MkdirAll(srcDir, 0o700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(srcDir, "lib.rs"), []byte("// chainsaw-verify\n"), 0o600); err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, "cargo", "fetch")
	cmd.Dir = dir
	return cmd.CombinedOutput()
}
func (cargoVerifyDriver) BypassHint() string {
	return "cargo is not using the chainsaw registry. Check $CARGO_HOME/config.toml has a [registries.chainsaw] block and the project declares `registry = \"chainsaw\"` (or chainsaw is the default). Re-run `chainsaw install-hook cargo`."
}

// serverHostForDockerPull strips scheme + path from the configured
// server URL so we can prefix it into a docker ref. Mirrors the
// docker.go validateServerURL post-processing.
func serverHostForDockerPull(server string) (string, error) {
	u, err := url.Parse(strings.TrimRight(server, "/"))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("server URL %q is not parseable", server)
	}
	return u.Host, nil
}
