package cli

// Strict-mode doctor: inspects project-scope configs, env-var overrides,
// lockfiles, and direct-egress reachability. Exit-code matrix:
//
//   0  compliant
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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/cli/hook"
	"github.com/chain305/chainsaw-core/httpclient"
)

const (
	doctorExitOK              = 0
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

// envOverrides maps manager names to the env vars that silently override
// their file config. `doctor --strict` checks each one and flags any that
// don't resolve to a Chainsaw URL. Order is stable (sort.Strings on keys
// before printing) so output diffs are reviewable.
var envOverrides = map[string][]string{
	"npm":    {"NPM_CONFIG_REGISTRY", "NPM_CONFIG_USERCONFIG"},
	"yarn":   {"YARN_NPM_REGISTRY_SERVER", "YARN_NPM_AUTH_TOKEN"},
	"bun":    {"BUN_CONFIG_REGISTRY"},
	"pip":    {"PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_CONFIG_FILE"},
	"cargo":  {"CARGO_HOME", "CARGO_REGISTRIES_CRATES_IO_PROTOCOL"},
	"maven":  {"MAVEN_OPTS", "M2_HOME"},
	"gradle": {"GRADLE_OPTS", "GRADLE_USER_HOME"},
	"nuget":  {"NUGET_PACKAGES"},
	"go":     {"GOPROXY", "GOPRIVATE", "GOSUMDB", "GOFLAGS", "GOINSECURE"},
	"docker": {"DOCKER_CONFIG", "DOCKER_HOST"},
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

	if exit != doctorExitOK {
		os.Exit(exit)
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

	for _, m := range hook.All() {
		state := evaluateManager(m, report.EnvOverrides)
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

	report.DirectRegistryEgress = probeDirectEgress(ctx)
	if report.DirectRegistryEgress == "reachable" && exit < doctorExitDirectReachable {
		exit = doctorExitDirectReachable
	}

	report.ConfigHash = hashStateSnapshot(report)
	return report, exit
}

// evaluateManager combines the manager's own Status() (which detects the
// sentinel block in the user-scope config) with strict-mode checks:
// project-scope config present, env overrides set.
func evaluateManager(m hook.Manager, envOut map[string]string) ecosystemState {
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

	for _, key := range envOverrides[m.Name()] {
		val := strings.TrimSpace(os.Getenv(key))
		if val == "" {
			continue
		}
		envOut[key] = val
		if valPointsAtChainsaw(val) {
			continue
		}
		state.Status = "drifted"
		if state.Reason == "" {
			state.Reason = key + " env var overrides config"
		} else {
			state.Reason += "; " + key + " env var overrides config"
		}
	}
	return state
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
//   - "unknown" — `--no-egress-probe` was passed, or every probe returned
//     an ambiguous error we can't classify.
func probeDirectEgress(ctx context.Context) string {
	client := httpclient.New(httpclient.WithTimeout(3 * time.Second))
	reachable := 0
	blocked := 0
	for _, url := range publicRegistryProbes {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
		if err != nil {
			blocked++
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			// net.OpError / timeout / DNS failure — treat as blocked.
			blocked++
			continue
		}
		resp.Body.Close()
		reachable++
	}
	switch {
	case reachable > 0:
		return "reachable"
	case blocked == len(publicRegistryProbes):
		return "blocked"
	default:
		return "unknown"
	}
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
func hashStateSnapshot(r doctorStrictReport) string {
	// Keep it dependency-light: render to JSON then SHA-256.
	type minimal struct {
		Ecosystems map[string]ecosystemState `json:"ecosystems"`
		Egress     string                    `json:"direct_registry_egress"`
		Env        map[string]string         `json:"env"`
	}
	b, _ := json.Marshal(minimal{
		Ecosystems: r.Ecosystems,
		Egress:     r.DirectRegistryEgress,
		Env:        r.EnvOverrides,
	})
	return sha256Hex(b)
}

func printStrictReport(cmd *cobra.Command, r doctorStrictReport, exit int) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "device: %s\nuser: %s\nplatform: %s\nchainsaw: %s\n\n",
		r.DeviceID, r.User, r.Platform, r.ChainsawVersion)
	fmt.Fprintln(out, "ECOSYSTEM       STATUS       REASON")
	names := make([]string, 0, len(r.Ecosystems))
	for k := range r.Ecosystems {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		st := r.Ecosystems[name]
		fmt.Fprintf(out, "%-15s %-12s %s\n", name, st.Status, st.Reason)
	}
	fmt.Fprintf(out, "\ndirect-egress-to-public-registries: %s\n", r.DirectRegistryEgress)
	if len(r.EnvOverrides) > 0 {
		fmt.Fprintln(out, "\nenv overrides:")
		for k, v := range r.EnvOverrides {
			fmt.Fprintf(out, "  %s=%s\n", k, v)
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
