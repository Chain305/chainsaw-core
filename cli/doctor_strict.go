package cli

// Strict-mode doctor: inspects project-scope configs, env-var overrides,
// lockfiles, and direct-egress reachability. Exit-code matrix:
//
//   0  compliant
//   1  egress probe inconclusive (the network could not be confirmed to
//      block direct registry egress: every probe returned an ambiguous
//      error we can't classify). Loud warning, soft fail — a non-blocked
//      network must NOT be read by CI as a pass. This is the weakest
//      drift signal and loses every tie: any real finding (10/30/40)
//      wins. NOTE: an intentional `--no-egress-probe` skip reports
//      "skipped" (not "unknown") and never trips this code.
//   10 drift detected (project config, env var override, lockfile
//      references public registry, ...)
//   30 direct egress to a public registry is reachable (fails enforcement
//      intent even if all local config points at Chainsaw)
//   40 unsupported package manager detected locally (installed binary
//      that Chainsaw doesn't have an enforcer for yet)
//
// The strict exit code matters because `doctor --strict` is wired into
// CI preflight: a non-zero exit from a single `chainsaw` call must
// cleanly translate into a build failure without the caller scraping
// text output. The matching exit codes live in the enforcement GitHub
// Action and MDM scripts shipped in enforcement/.

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/cli/hook"
	"github.com/chain305/chainsaw-core/httpclient"
	"github.com/chain305/chainsaw-core/redact"
)

const (
	doctorExitOK = 0
	// doctorExitEgressUnknown is the weakest drift signal: the egress
	// probe could not classify the network as blocked. It is placed below
	// every genuine finding so it loses all ties — it only fires when
	// nothing else flagged (see buildStrictReport). A deliberate
	// `--no-egress-probe` skip reports "skipped" and never trips this.
	doctorExitEgressUnknown   = 1
	doctorExitDrift           = 10
	doctorExitDirectReachable = 30
	doctorExitUnsupported     = 40
)

// doctorStrictReport is the shape posted to /api/attestations when the
// `--attest` flag is set. Field names match the server's
// attestationPayload JSON tags exactly.
type doctorStrictReport struct {
	DeviceID             string                    `json:"device_id"`
	User                 string                    `json:"user"`
	Mode                 string                    `json:"mode"`
	Ecosystems           map[string]ecosystemState `json:"ecosystems"`
	DirectRegistryEgress string                    `json:"direct_registry_egress"`
	ConfigHash           string                    `json:"config_hash"`
	Platform             string                    `json:"platform"`
	ChainsawVersion      string                    `json:"chainsaw_version"`
	LastRemediatedAt     *time.Time                `json:"last_remediated_at,omitempty"`
	// W11 — when --bundle-id is set on the CLI, this carries the
	// hardening bundle identifier the MDM-rendered install script
	// applied. The server cross-references this against the
	// hardening_bundles table and stamps applied_at on a match.
	// Omitted from the JSON payload when empty so older servers (which
	// don't know the field) keep parsing the body unchanged.
	BundleID string `json:"bundle_id,omitempty"`
	// strict-only — not in the server payload but printed by the CLI.
	EnvOverrides map[string]string `json:"env_overrides,omitempty"`
	LockfileHits []string          `json:"lockfile_hits,omitempty"`
}

type ecosystemState struct {
	Status     string `json:"status"`
	ConfigPath string `json:"config_path,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// envKind says how an env var's VALUE should be judged. The original table
// was a flat list of names run through one URL heuristic
// (valPointsAtChainsaw), which is only meaningful for a var that actually
// holds a registry URL. Roughly half the watched vars hold a directory
// path, an opts string, or a credential, and every one of those failed the
// heuristic — reporting "drifted" and exiting 10 on correctly-wired hosts.
//
// The in-repo proof that this was self-contradictory: cli/hook/cargo.go:49,
// gradle.go:38 and maven.go:54 resolve their config path THROUGH
// CARGO_HOME / GRADLE_USER_HOME / M2_HOME. evaluateManager uses the var to
// FIND the wired file, reports the manager compliant, and then flags that
// same var as drift.
type envKind int

const (
	// envURL holds a registry/proxy URL. The heuristic applies: a value
	// that does not resolve to Chainsaw is genuine drift.
	envURL envKind = iota
	// envConfigPath redirects the manager at a DIFFERENT config file. The
	// value is a path, not a URL, so the verdict comes from the file it
	// names: if that file carries the chainsaw-managed block the manager
	// is still wired; if it demonstrably does not, the wired user config
	// is being bypassed.
	envConfigPath
	// envInfo is reported for the operator's benefit and NEVER fails the
	// run. These vars hold directory paths, opts strings, protocol
	// selectors, or credentials — values no URL heuristic can classify,
	// so any verdict derived from one is a coin flip dressed as a finding.
	envInfo
)

type envWatch struct {
	Key  string
	Kind envKind
}

// envOverrides maps manager names to the env vars that can silently override
// their file config, together with how each var's value must be judged (see
// envKind). Order is stable (sort.Strings on keys before printing) so output
// diffs are reviewable.
//
// YARN_NPM_AUTH_TOKEN is envInfo rather than envURL deliberately: it holds a
// credential. A credential can never satisfy a "looks like a Chainsaw URL"
// test, so grading it produced a guaranteed false "drifted" on every host
// that had yarn auth configured at all.
var envOverrides = map[string][]envWatch{
	"npm": {
		{"NPM_CONFIG_REGISTRY", envURL},
		{"NPM_CONFIG_USERCONFIG", envConfigPath},
	},
	"yarn": {
		{"YARN_NPM_REGISTRY_SERVER", envURL},
		{"YARN_NPM_AUTH_TOKEN", envInfo},
	},
	"bun": {
		{"BUN_CONFIG_REGISTRY", envURL},
	},
	"pip": {
		{"PIP_INDEX_URL", envURL},
		{"PIP_EXTRA_INDEX_URL", envURL},
		{"PIP_CONFIG_FILE", envConfigPath},
	},
	"cargo": {
		{"CARGO_HOME", envInfo},
		{"CARGO_REGISTRIES_CRATES_IO_PROTOCOL", envInfo},
	},
	"maven": {
		{"MAVEN_OPTS", envInfo},
		{"M2_HOME", envInfo},
	},
	"gradle": {
		{"GRADLE_OPTS", envInfo},
		{"GRADLE_USER_HOME", envInfo},
	},
	"nuget": {
		{"NUGET_PACKAGES", envInfo},
	},
	"go": {
		{"GOPROXY", envURL},
		// GOPRIVATE is a genuine bypass lever — it tells the Go toolchain to
		// skip the proxy for matching module paths — but its value is a
		// COMMA-SEPARATED GLOB (github.com/myorg/*), never a URL. Grading it
		// with valPointsAtChainsaw can therefore only ever produce a false
		// "drifted": the pattern will never contain the proxy host.
		//
		// Worse, the go env block this CLI itself writes tells the operator to
		// set exactly that (cli/hook/gomod.go:187), so envURL made
		// `doctor --strict` exit 10 on every host that followed our own
		// instructions. Report it; let a human judge the scope.
		{"GOPRIVATE", envInfo},
		{"GOSUMDB", envInfo},
		{"GOFLAGS", envInfo},
		{"GOINSECURE", envInfo},
	},
	"docker": {
		{"DOCKER_CONFIG", envInfo},
		{"DOCKER_HOST", envInfo},
	},
}

// publicRegistryProbes are the upstream hosts we probe for direct
// reachability. They are intentionally the same list that the server's
// /api/compliance/egress-allowlist returns — "what the firewall should
// block" and "what doctor probes" stay in sync.
var publicRegistryProbes = []string{
	"https://registry.npmjs.org/",
	"https://pypi.org/",
	"https://repo.maven.apache.org/maven2/",
}

func runDoctorStrict(cmd *cobra.Command, _ []string) error {
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	report, exit := buildStrictReport(ctx, cmd)

	attest, _ := cmd.Flags().GetBool("attest")
	if attest {
		if err := postAttestation(ctx, cmd, report); err != nil {
			fmt.Fprintln(cmd.ErrOrStderr(), "attestation POST failed:", err)
			// Attestation failure doesn't change the compliance exit code
			// — the doctor check itself succeeded. Ops will surface the
			// POST error separately.
		}
	}

	if useJSON(cmd) {
		_ = writeJSON(cmd, report)
	} else {
		printStrictReport(cmd, report, exit)
	}

	// Y3/Y4 — returned, not os.Exit'd. The manual flushTelemetry() that used to
	// sit here was a patch over the real problem: os.Exit inside a RunE never
	// returns to Execute(), so markSessionEnd never ran and the
	// cli.session.completed event carrying exit_code / error_class was never
	// QUEUED — flushing early could not save an event that did not exist yet.
	// Returning the code lets Execute() do both, in order. doctorExitDrift and
	// friends keep their values.
	if exit != doctorExitOK {
		return &ExitCodeError{Code: exit}
	}
	return nil
}

func buildStrictReport(ctx context.Context, cmd *cobra.Command) (doctorStrictReport, int) {
	report := doctorStrictReport{
		Mode:            "monitor",
		Ecosystems:      map[string]ecosystemState{},
		EnvOverrides:    map[string]string{},
		Platform:        runtime.GOOS + "/" + runtime.GOARCH,
		ChainsawVersion: versionString(),
	}
	report.DeviceID, report.User = deriveDeviceIdentity()
	if v, _ := cmd.Flags().GetString("device-id"); strings.TrimSpace(v) != "" {
		report.DeviceID = strings.TrimSpace(v)
	}
	// W11 — propagate --bundle-id so postAttestation includes it in
	// the request body. The flag may be absent (older callers, manual
	// runs) — empty string is omitted from the JSON via omitempty so
	// servers can't tell the field even existed.
	if v, _ := cmd.Flags().GetString("bundle-id"); strings.TrimSpace(v) != "" {
		report.BundleID = strings.TrimSpace(v)
	}

	exit := doctorExitOK

	// envRaw never leaves this function: it feeds the config hash and
	// nothing else. See evaluateManager for why the hash must see raw
	// values while every rendered/POSTed view sees redacted ones.
	envRaw := map[string]string{}

	for _, m := range hook.All() {
		state := evaluateManager(m, report.EnvOverrides, envRaw)
		report.Ecosystems[m.Name()] = state
		switch state.Status {
		case "drifted":
			if exit < doctorExitDrift {
				exit = doctorExitDrift
			}
		case "unsupported":
			if exit < doctorExitUnsupported {
				exit = doctorExitUnsupported
			}
		}
	}

	report.LockfileHits = scanLockfilesForPublicSources()
	if len(report.LockfileHits) > 0 && exit < doctorExitDrift {
		exit = doctorExitDrift
	}

	// --no-egress-probe (documented in newDoctorCmd) short-circuits the
	// probe for air-gapped CI where outbound is known-blocked, so the run
	// doesn't eat the ~9s probe timeout. We report "skipped" — a distinct
	// sentinel from "unknown" — so the soft-fail below never fires for an
	// intentional skip. The flag may be unregistered on hand-built test
	// commands; GetBool then returns false, preserving the probe.
	if noProbe, _ := cmd.Flags().GetBool("no-egress-probe"); noProbe {
		report.DirectRegistryEgress = "skipped"
	} else {
		report.DirectRegistryEgress = probeDirectEgressFn(ctx, cmd.ErrOrStderr(), useJSON(cmd))
	}
	exit = applyEgressExit(exit, report.DirectRegistryEgress)

	report.ConfigHash = hashStateSnapshot(report, envRaw)
	return report, exit
}

// applyEgressExit folds the direct-egress classification into the running exit
// code. "reachable" is a hard, drift-level finding (a developer can reach a
// public registry directly, bypassing the guard). "unknown" is a loud soft-fail
// — a network we could not confirm is blocked must not read as a pass in CI —
// but only when nothing stronger already fired, so it never downgrades a real
// finding above it. "blocked" and "skipped" leave the exit untouched. Pulled out
// as a pure function so the CI exit contract is unit-testable without standing
// up the full manager-drift evaluation.
func applyEgressExit(exit int, egress string) int {
	switch {
	case egress == "reachable" && exit < doctorExitDirectReachable:
		return doctorExitDirectReachable
	case egress == "unknown" && exit == doctorExitOK:
		return doctorExitEgressUnknown
	}
	return exit
}

// evaluateManager combines the manager's own Status() (which detects the
// sentinel block in the user-scope config) with strict-mode checks:
// project-scope config present, env overrides set.
//
// Two env maps, deliberately:
//   - envOut is the REDACTED view. It is printed and marshalled into the
//     attestation POST body, so a var like YARN_NPM_AUTH_TOKEN or
//     CHAINSAW-adjacent credential must never appear verbatim in it.
//   - envRaw is the unredacted view and feeds hashStateSnapshot ONLY. The
//     config hash must stay byte-identical to what pre-redaction builds
//     produced, otherwise every device in the fleet emits a spurious
//     compliance_drift audit row the first time it upgrades.
//
// This is the "hash the raw value, redact at the serialization boundary"
// rule from the redact package doc, applied at its most consequential site.
func evaluateManager(m hook.Manager, envOut, envRaw map[string]string) ecosystemState {
	if !m.IsInstalled() {
		return ecosystemState{Status: "unconfigured", Reason: "binary not on PATH"}
	}
	st, err := m.Status()
	state := ecosystemState{ConfigPath: st.ConfigPath}
	if err != nil {
		state.Status = "drifted"
		state.Reason = err.Error()
		return state
	}
	if !st.Wired {
		state.Status = "drifted"
		state.Reason = "no chainsaw-managed block in " + st.ConfigPath
	} else {
		state.Status = "compliant"
	}

	if projPath, perr := m.ConfigPathForScope(hook.ScopeProject); perr == nil {
		if fi, ferr := os.Stat(projPath); ferr == nil && fi.Size() > 0 {
			data, rerr := os.ReadFile(projPath)
			if rerr == nil && !hasChainsawSentinel(data) && looksLikeOverride(m.Name(), data) {
				state.Status = "drifted"
				state.Reason = "project-scope override detected at " + projPath
			}
		}
	}

	for _, w := range envOverrides[m.Name()] {
		val := strings.TrimSpace(os.Getenv(w.Key))
		if val == "" {
			continue
		}
		envRaw[w.Key] = val
		envOut[w.Key] = redact.Value(w.Key, val)

		reason := envDriftReason(w, val)
		if reason == "" {
			continue
		}
		state.Status = "drifted"
		if state.Reason == "" {
			state.Reason = reason
		} else {
			state.Reason += "; " + reason
		}
	}
	return state
}

// envDriftReason returns the drift reason for one watched env var, or "" when
// the var is not drift. It is the only place a watched env var can turn into
// a non-zero exit code, so every kind's verdict is stated once, here.
func envDriftReason(w envWatch, val string) string {
	switch w.Kind {
	case envURL:
		if valPointsAtChainsaw(val) {
			return ""
		}
		return w.Key + " env var overrides config"
	case envConfigPath:
		// The var names a different config FILE. Judge the file, not the
		// path string: if it carries the chainsaw-managed block the
		// manager is still routed through Chainsaw.
		data, err := os.ReadFile(val)
		switch {
		case err == nil && hasChainsawSentinel(data):
			return ""
		case err == nil:
			return w.Key + " redirects config to " + val + ", which has no chainsaw-managed block"
		case os.IsNotExist(err):
			return w.Key + " points at " + val + ", which does not exist — the wired user config is not read"
		default:
			// Unreadable for some other reason (permissions, a device
			// node, a race). We cannot prove drift, and a strict gate
			// must not fail on something it could not read. Report it in
			// env overrides and move on.
			return ""
		}
	default: // envInfo
		// Reported, never graded. See envKind.
		return ""
	}
}

// hasChainsawSentinel inlines a dependency-light sentinel check so
// doctor_strict doesn't import the hook package's unexported helpers.
// The sentinel prefix is stable across managers.
func hasChainsawSentinel(data []byte) bool {
	return strings.Contains(string(data), "chainsaw-managed")
}

// looksLikeOverride reports whether a project-scope config file contains
// anything that would override the user's managed config. Parse-aware
// where feasible so a `.npmrc` that only sets `save-exact=true` is not
// flagged — registry/index-url/source are the override keys.
func looksLikeOverride(manager string, data []byte) bool {
	text := string(data)
	switch manager {
	case "npm", "yarn":
		return containsPrefixLine(text, "registry=") || strings.Contains(text, ":_authToken=") || strings.Contains(text, "npmRegistryServer")
	case "bun":
		return strings.Contains(text, "[install.registry]") || strings.Contains(text, "registry =")
	case "pip":
		return strings.Contains(text, "index-url") || strings.Contains(text, "extra-index-url")
	case "cargo":
		return strings.Contains(text, "[source.") || strings.Contains(text, "replace-with") || strings.Contains(text, "[registries")
	case "maven":
		return strings.Contains(text, "<mirror>") || strings.Contains(text, "<repository>")
	case "gradle":
		return strings.Contains(text, "repositories") || strings.Contains(text, "mavenCentral()") || strings.Contains(text, "google()")
	case "nuget":
		return strings.Contains(text, "<packageSources>") || strings.Contains(text, "<add key=")
	case "go":
		return strings.Contains(text, "GOPROXY=")
	case "docker":
		return strings.Contains(text, "registry-mirrors")
	}
	return false
}

// containsPrefixLine reports whether any non-comment line starts with
// prefix after trimming leading whitespace. Used to distinguish between
// a .npmrc that has `#registry=...` (a commented-out hint) vs an active
// override.
func containsPrefixLine(text, prefix string) bool {
	for _, line := range strings.Split(text, "\n") {
		trim := strings.TrimSpace(line)
		if trim == "" || strings.HasPrefix(trim, "#") || strings.HasPrefix(trim, ";") {
			continue
		}
		if strings.HasPrefix(trim, prefix) {
			return true
		}
	}
	return false
}

// valPointsAtChainsaw returns true when the env-var value looks like a
// Chainsaw URL. Heuristic — we don't know the exact deployment URL at
// doctor time, so "contains chainsaw" or "localhost" (dev default) are
// both acceptable; anything else is suspect.
func valPointsAtChainsaw(v string) bool {
	lower := strings.ToLower(v)
	if strings.Contains(lower, "chainsaw") || strings.Contains(lower, "localhost") {
		return true
	}
	// Loopback IPs are acceptable too — dev setups.
	if strings.Contains(lower, "127.0.0.1") || strings.Contains(lower, "::1") {
		return true
	}
	return false
}

// scanLockfilesForPublicSources walks cwd (not recursively — only the
// root) looking for lockfiles that reference public registries. Deep
// recursion lives in `chainsaw scan-repo`; doctor keeps its scope
// shallow to stay fast on developer machines.
func scanLockfilesForPublicSources() []string {
	var hits []string
	cwd, err := os.Getwd()
	if err != nil {
		return nil
	}
	candidates := []struct {
		name     string
		patterns []string
	}{
		{"package-lock.json", []string{`"resolved": "https://registry.npmjs.org/`, `"resolved": "https://registry.yarnpkg.com/`}},
		{"yarn.lock", []string{"https://registry.npmjs.org/", "https://registry.yarnpkg.com/"}},
		{"poetry.lock", []string{"pypi.org/"}},
		{"Pipfile.lock", []string{"pypi.org/"}},
		{"uv.lock", []string{"pypi.org/"}},
		{"Cargo.lock", []string{"registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io/"}},
		{"Gemfile.lock", []string{"remote: https://rubygems.org/"}},
		{"composer.lock", []string{"packagist.org"}},
	}
	for _, c := range candidates {
		path := filepath.Join(cwd, c.name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, p := range c.patterns {
			if strings.Contains(string(data), p) {
				hits = append(hits, c.name+" references "+p)
				break
			}
		}
	}
	sort.Strings(hits)
	return hits
}

// probeDirectEgress fires a short HEAD probe at each public registry.
//   - "blocked" — every probe fails (DNS/connect refused/timeout). This is
//     the desired state under network-mandatory enforcement.
//   - "reachable" — any probe returns a status code (even 4xx/5xx). The
//     fact that the connection succeeded means the network isn't stopping
//     direct egress.
//   - "unknown" — every probe returned an ambiguous error we can't
//     classify; we could neither confirm reachability nor a clean block.
//     Treated as a soft fail by buildStrictReport. (The intentional
//     `--no-egress-probe` skip is handled by the caller and reported as
//     "skipped" — it does not reach this function.)
//
// It prints a one-line progress note to stderr before the loop (the
// probe can take up to ~9s) unless quiet is set — quiet is true under
// --json so scripted/JSON consumers see no extra stderr noise and stdout
// stays pure JSON.
// probeDirectEgressFn is the seam buildStrictReport calls through. Tests
// override it to inject a fixed classification without making live HEAD
// requests; production points it at probeDirectEgressImpl.
var probeDirectEgressFn = probeDirectEgressImpl

func probeDirectEgressImpl(ctx context.Context, stderr io.Writer, quiet bool) string {
	if !quiet {
		fmt.Fprintf(stderr, "probing direct egress to %d registries%s\n", len(publicRegistryProbes), glyphs().ellipsis)
	}
	client := httpclient.New(httpclient.WithTimeout(3 * time.Second))
	reachable := 0
	blocked := 0
	unknown := 0
	for _, url := range publicRegistryProbes {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
		if err != nil {
			// A malformed probe URL is our bug, not the network's answer.
			// It says nothing about egress, so it must not read as a block.
			unknown++
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			if classifyProbeError(err) == "blocked" {
				blocked++
			} else {
				unknown++
			}
			continue
		}
		resp.Body.Close()
		reachable++
	}
	switch {
	case reachable > 0:
		return "reachable"
	case unknown > 0:
		// We could not classify at least one probe, so we cannot certify
		// containment. Soft-fail (exit 1) rather than print "blocked".
		return "unknown"
	case blocked == len(publicRegistryProbes):
		return "blocked"
	default:
		return "unknown"
	}
}

// classifyProbeError decides whether a failed egress probe proves the
// network blocked us ("blocked") or merely proves we learned nothing
// ("unknown").
//
// The bias here is deliberate and asymmetric. "blocked" is the compliant,
// exit-0 answer, so a wrong "blocked" is a false all-clear. But "unknown"
// soft-fails at exit 1, and the single most common real deployment of this
// probe is an air-gapped CI runner where EVERY probe fails — if the routine
// air-gap error shapes drifted into "unknown", every such runner would
// start failing its preflight. That would be a far worse regression than
// the bug being fixed.
//
// So the rule is: the error shapes an air-gapped or firewalled box actually
// produces — DNS failure, connection refused, host/network unreachable, and
// EVERY flavour of timeout — stay "blocked". Only errors that mean "the
// connection got far enough to fail somewhere else" become "unknown":
//
//   - TLS / x509 verification failures. This is the case the fix exists
//     for: behind a MITM proxy whose CA Go does not trust but npm does
//     (NODE_EXTRA_CA_CERTS), the TCP connection SUCCEEDED. The host can
//     reach registry.npmjs.org; only Go's trust store disagrees. Calling
//     that "blocked" certified egress containment on a host that has none.
//   - context.Canceled — the operator interrupted us; no verdict was reached.
//   - anything we cannot name.
func classifyProbeError(err error) string {
	if err == nil {
		return "blocked"
	}

	// Timeouts first, and unconditionally blocked. A firewall that DROPs
	// (rather than REJECTs) produces a timeout, and that is the single most
	// common air-gap shape. context.DeadlineExceeded reaches here too:
	// net/url wraps it and *url.Error.Timeout() reports true.
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "blocked"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		return "blocked"
	}

	// Cancellation is not a network answer.
	if errors.Is(err, context.Canceled) {
		return "unknown"
	}

	// TLS/x509: the transport connected, then trust evaluation failed.
	var certVerifyErr *tls.CertificateVerificationError
	var recordErr tls.RecordHeaderError
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certInvalid x509.CertificateInvalidError
	if errors.As(err, &certVerifyErr) || errors.As(err, &recordErr) ||
		errors.As(err, &unknownAuthority) || errors.As(err, &hostnameErr) ||
		errors.As(err, &certInvalid) {
		return "unknown"
	}

	// Name resolution failed — nothing to connect to. Air-gap shape.
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return "blocked"
	}

	// Refused / unreachable, named portably via the dial-phase OpError so
	// this compiles and behaves the same on every GOOS. A failure during
	// "dial" means we never established a connection at all.
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return "blocked"
	}
	if errors.Is(err, syscall.ECONNREFUSED) ||
		errors.Is(err, syscall.EHOSTUNREACH) ||
		errors.Is(err, syscall.ENETUNREACH) {
		return "blocked"
	}

	return "unknown"
}

func deriveDeviceIdentity() (string, string) {
	host, _ := os.Hostname()
	user := os.Getenv("USER")
	if user == "" {
		user = os.Getenv("USERNAME")
	}
	devID := host
	if user != "" {
		devID = host + "/" + user
	}
	if devID == "" {
		devID = "unknown-device"
	}
	return devID, user
}

func versionString() string {
	return Version
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return fmt.Sprintf("%x", sum[:])
}

// hashStateSnapshot returns a cheap SHA-256 over the fields that identify
// drift. It deliberately leaves out LastRemediatedAt and lockfileHits so
// the hash reflects "the config we care about" rather than transient
// state — two runs on the same config produce the same hash.
//
// envRaw, not r.EnvOverrides: the hash must see the UNREDACTED env values.
// Hashing the redacted view would collapse every credential to "<set>", so
// a rotated token would stop changing the hash — and, on the release that
// introduced redaction, every device in the fleet would emit one spurious
// compliance_drift audit row as its hash shifted for no config change.
func hashStateSnapshot(r doctorStrictReport, envRaw map[string]string) string {
	// Keep it dependency-light: render to JSON then SHA-256.
	type minimal struct {
		Ecosystems map[string]ecosystemState `json:"ecosystems"`
		Egress     string                    `json:"direct_registry_egress"`
		Env        map[string]string         `json:"env"`
	}
	b, _ := json.Marshal(minimal{
		Ecosystems: r.Ecosystems,
		Egress:     r.DirectRegistryEgress,
		Env:        envRaw,
	})
	return sha256Hex(b)
}

func printStrictReport(cmd *cobra.Command, r doctorStrictReport, exit int) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "device: %s\nuser: %s\nplatform: %s\nchainsaw: %s\n\n",
		r.DeviceID, r.User, r.Platform, r.ChainsawVersion)
	// tabwriter sizes columns to the widest cell, so a long Reason no
	// longer shoves the table out of alignment the way the old fixed
	// %-15s/%-12s pads did. Status/Reason are uncoloured plain strings
	// here, so tabwriter's ANSI-blind width counting is not a concern.
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ECOSYSTEM\tSTATUS\tREASON")
	names := make([]string, 0, len(r.Ecosystems))
	for k := range r.Ecosystems {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		st := r.Ecosystems[name]
		fmt.Fprintf(tw, "%s\t%s\t%s\n", name, st.Status, st.Reason)
	}
	tw.Flush()
	fmt.Fprintf(out, "\ndirect-egress-to-public-registries: %s\n", r.DirectRegistryEgress)
	if r.DirectRegistryEgress == "unknown" {
		g := glyphs()
		fmt.Fprintln(out, "  "+g.warn+" egress probe inconclusive "+g.dash+" could not confirm the network blocks direct registry egress; treat as NOT blocked")
	}
	if len(r.EnvOverrides) > 0 {
		fmt.Fprintln(out, "\nenv overrides:")
		// Sorted, as the envOverrides doc comment has always promised —
		// map iteration order made two runs on an unchanged machine
		// produce diffable-looking output.
		keys := make([]string, 0, len(r.EnvOverrides))
		for k := range r.EnvOverrides {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			// Values are already redacted at assignment in
			// evaluateManager; this loop is a pure sink.
			fmt.Fprintf(out, "  %s=%s\n", k, r.EnvOverrides[k])
		}
	}
	if len(r.LockfileHits) > 0 {
		fmt.Fprintln(out, "\nlockfile drift:")
		for _, h := range r.LockfileHits {
			fmt.Fprintf(out, "  %s\n", h)
		}
	}
	fmt.Fprintf(out, "\nexit-code: %d\n", exit)
}

// postAttestation sends the strict report to /api/attestations on the
// configured server. Fails open on network error so CI can decide
// separately whether to block on attestation delivery vs compliance
// state itself.
func postAttestation(ctx context.Context, cmd *cobra.Command, r doctorStrictReport) error {
	server := cfgServerURL()
	if flag, _ := cmd.Flags().GetString("server"); strings.TrimSpace(flag) != "" {
		server = strings.TrimSpace(flag)
	}
	if server == "" {
		return errors.New("no chainsaw server configured (set --server or CHAINSAW_SERVER)")
	}
	body, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(server, "/")+"/api/attestations", strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := strings.TrimSpace(os.Getenv("CHAINSAW_TOKEN")); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := httpclient.New().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("attestation rejected: %s", resp.Status)
	}
	return nil
}

// readLines is a small helper for future scanners that need line-by-line
// inspection of config files without pulling in bufio.Scanner everywhere.
func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var lines []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		lines = append(lines, s.Text())
	}
	return lines, s.Err()
}

// Silence the unused import linter when readLines isn't reached; the
// helper is still needed by scan_repo.go in this package.
var _ = readLines
