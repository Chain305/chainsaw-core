// Package doctor provides local diagnostic checks for a chainsaw
// server install, independent of the `chainsaw` CLI's package-manager
// wiring checks (which live in internal/cli/doctor.go).
//
// The checks here answer the operator question: "is this box in a
// shape to run the chainsaw-proxy server, and is it safe to upgrade
// from the currently-running binary to the one on disk?"
//
// This package is intentionally dependency-light: no database driver
// imports, no HTTP client specific to internal packages. Every check
// returns a Finding with a severity so the caller can render a
// scorecard and pick an exit code.
package doctor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
)

// Severity ranks a finding. Higher is worse. Worst severity across
// all findings drives the process exit code.
type Severity int

const (
	SeverityOK Severity = iota
	SeverityWarn
	SeverityBreaking
)

// String returns the lower-case name used in JSON output.
func (s Severity) String() string {
	switch s {
	case SeverityOK:
		return "ok"
	case SeverityWarn:
		return "warn"
	case SeverityBreaking:
		return "breaking"
	default:
		return "unknown"
	}
}

// Mark returns a single-glyph status indicator suitable for the
// text-mode scorecard.
func (s Severity) Mark() string {
	switch s {
	case SeverityOK:
		return "✓"
	case SeverityWarn:
		return "⚠"
	case SeverityBreaking:
		return "✗"
	default:
		return "?"
	}
}

// Finding is a single diagnostic result.
type Finding struct {
	Check    string   `json:"check"`
	Severity Severity `json:"-"`
	// SeverityName is the rendered-for-JSON name. Populated by
	// MarshalJSON-friendly callers via Report.Normalize().
	SeverityName string `json:"severity"`
	Message      string `json:"message"`
	// Remediation is a short imperative hint. Empty when no obvious
	// fix applies (e.g. on OK findings).
	Remediation string `json:"remediation,omitempty"`
	// AutoFixable signals to `doctor --fix` that a programmatic
	// remediation exists. Only consulted on SeverityWarn findings;
	// breaking findings never auto-fix (operator must acknowledge).
	AutoFixable bool `json:"auto_fixable,omitempty"`
}

// Report is the output of a doctor run.
type Report struct {
	Version     string    `json:"chainsaw_version"`
	Platform    string    `json:"platform"`
	GeneratedAt time.Time `json:"generated_at"`
	Findings    []Finding `json:"findings"`
}

// Normalize fills derived fields (e.g. SeverityName) so the report
// is self-describing in JSON.
func (r *Report) Normalize() {
	for i := range r.Findings {
		r.Findings[i].SeverityName = r.Findings[i].Severity.String()
	}
}

// Worst returns the highest severity across all findings. An empty
// report is SeverityOK.
func (r *Report) Worst() Severity {
	worst := SeverityOK
	for _, f := range r.Findings {
		if f.Severity > worst {
			worst = f.Severity
		}
	}
	return worst
}

// ExitCode maps a report's worst finding to the documented exit codes:
//
//	0 = all green
//	1 = warnings
//	2 = breaking changes
func (r *Report) ExitCode() int {
	switch r.Worst() {
	case SeverityBreaking:
		return 2
	case SeverityWarn:
		return 1
	default:
		return 0
	}
}

// Options controls which checks run and how they resolve paths.
// Zero value is valid: everything runs with default paths.
type Options struct {
	// Version is the binary's advertised version string (from
	// internal/cli.Version). Used for version-drift and
	// upgrade-safety comparisons.
	Version string
	// ConfigPath is the --config YAML that the daemon would read.
	// Empty means "auto-detect via the same precedence chainsaw-proxy
	// uses" — which for doctor purposes is just $CHAINSAW_CONFIG.
	ConfigPath string
	// DataDir is the on-disk data directory. Empty uses the baked
	// default (/etc/chainsaw/data).
	DataDir string
	// Env is the environment to inspect. nil uses os.Environ().
	// Tests pass a pinned map.
	Env func(key string) string
	// HTTPClient is used for upstream-registry reachability probes.
	// nil constructs a default client with a 5s timeout.
	HTTPClient *http.Client
	// UpstreamRegistries overrides the probe list. Empty uses the
	// built-in list (npm, pypi, maven).
	UpstreamRegistries []string
	// SkipNetwork skips the upstream-registry probe. Useful in
	// hermetic test / CI environments that don't allow egress.
	SkipNetwork bool
	// DockerComposePath is the path to docker-compose.yml for the
	// version-drift check. Empty disables the check (no finding is
	// emitted rather than a false-positive warning).
	DockerComposePath string
	// PortsToCheck is the list of TCP ports to verify are bindable.
	// Empty uses the default server ports.
	PortsToCheck []int
	// DBProber probes the database for its current schema_version
	// without pulling the pgx driver into this package. The CLI
	// wires up a pgstore-backed implementation; tests pass a
	// hermetic fake (see doctor_test.go). When nil and a DSN is
	// present, checkDatabase emits an informational finding rather
	// than silently skipping.
	DBProber DBProber
	// ExpectedSchemaVersion is the schema revision the binary ships
	// with. Passed in (rather than read from pgstore) so this
	// package stays dependency-light and tests can override.
	ExpectedSchemaVersion string
}

// DBProber is the minimal surface the doctor needs to evaluate
// database state. Implementations must honour ctx cancellation so a
// --timeout hanging at a non-responsive Postgres doesn't block the
// whole report.
//
// The two method split isolates the connect-failure path (reported
// as Breaking) from the schema-version comparison (reported as OK /
// Warn depending on drift).
type DBProber interface {
	// Ping verifies the server is reachable and authenticating. It
	// returns an error the operator can action (timeout, auth
	// failure, DSN typo).
	Ping(ctx context.Context) error
	// SchemaVersion returns the version string stored in the
	// schema_version table. Returns ErrNoSchemaVersion (or any
	// implementation-specific sentinel that matches the doctor's
	// "fresh DB" detection — see checkDatabase) when the marker row
	// is absent.
	SchemaVersion(ctx context.Context) (string, error)
}

// ErrFreshDatabase is returned by DBProber.SchemaVersion
// implementations to signal "server reachable but no schema_version
// row yet". Doctor reports this as a warning prompting the operator
// to boot the server once to seed the marker. pgstore maps its own
// ErrNoSchemaVersion to this sentinel via the CLI-side adapter.
var ErrFreshDatabase = errors.New("schema_version row not present (fresh DB)")

// DefaultUpstreamRegistries is the probe list that mirrors the
// upstream registries chainsaw-proxy will call out to in a typical
// deployment. HEAD requests with a short timeout — if the firewall
// blocks egress we report unreachable, which is a warning not a
// breaking finding (some deployments deliberately air-gap).
var DefaultUpstreamRegistries = []string{
	"https://registry.npmjs.org/",
	"https://pypi.org/",
	"https://repo.maven.apache.org/maven2/",
}

// DefaultServerPorts is the set of TCP ports the chainsaw-proxy
// server typically binds. Kept in sync with cmd/chainsaw-proxy/main.go's
// defaultListen (":8787"); 8080 and 8443 are conventional secondary
// ports that reverse proxies and admin UIs expect.
var DefaultServerPorts = []int{8787, 8080, 8443}

// BreakingFlagRemovals lists CLI flags that were accepted by older
// releases but now cause a hard failure. The doctor --upgrade-check
// scans the operator's systemd unit / env / config for any of these
// strings and emits a breaking finding so the upgrade is paused
// before boot-time bricks production.
//
// Kept as a struct (not just a string slice) because the remediation
// text is per-flag — generic "remove this flag" is less helpful than
// "the embedded UI moved to a sidecar container; see MIGRATIONS.md".
var BreakingFlagRemovals = []struct {
	Flag        string
	Remediation string
}{
	{
		Flag:        "--embedded-ui",
		Remediation: "Removed in 0.16.0. UI is now served by a separate container/sidecar — see MIGRATIONS.md.",
	},
	{
		Flag:        "--legacy-auth",
		Remediation: "Removed in 0.15.0. Use `chainsaw auth login` or CHAINSAW_JWT_SECRET.",
	},
	{
		Flag:        "--unsafe-cors",
		Remediation: "Removed in 0.14.0. Configure CORS via the server config YAML instead.",
	},
}

// DeprecatedEnvFlip describes an env var whose default flipped in a
// release — operators relying on the old default will see behaviour
// change silently unless they pin the value.
type DeprecatedEnvFlip struct {
	Name        string
	OldDefault  string
	NewDefault  string
	Remediation string
}

// DeprecatedEnvFlips is the list of env vars whose default changed in
// a way that can brick a running deployment. CHAINSAW_STRICT_JWT is
// the P1-4 example from the audit: 0.16.0 turned it on by default,
// which refuses to start if no JWT secret is resolvable.
var DeprecatedEnvFlips = []DeprecatedEnvFlip{
	{
		Name:        "CHAINSAW_STRICT_JWT",
		OldDefault:  "0",
		NewDefault:  "1",
		Remediation: "0.16.0 flipped this on by default. Either set CHAINSAW_JWT_SECRET (or rely on the auto-generated secret file) or pin CHAINSAW_STRICT_JWT=0 temporarily.",
	},
}

// Run executes every applicable check against the resolved Options
// and returns a populated Report. It never returns an error — check
// failures become Findings. Callers inspect Report.ExitCode() to
// map to process exit.
func Run(ctx context.Context, opts Options) *Report {
	report := &Report{
		Version:     opts.Version,
		Platform:    runtime.GOOS + "/" + runtime.GOARCH,
		GeneratedAt: time.Now().UTC(),
	}
	getenv := opts.Env
	if getenv == nil {
		getenv = os.Getenv
	}

	report.Findings = append(report.Findings, checkEnv(getenv)...)
	report.Findings = append(report.Findings, checkConfig(opts.ConfigPath, getenv)...)
	report.Findings = append(report.Findings, checkDataDir(opts.DataDir, getenv)...)
	report.Findings = append(report.Findings, checkPorts(opts.PortsToCheck)...)
	report.Findings = append(report.Findings, checkTLS(opts.ConfigPath, getenv)...)
	report.Findings = append(report.Findings, checkBreakingFlags(getenv)...)
	report.Findings = append(report.Findings, checkVersionDrift(opts.Version, opts.DockerComposePath)...)
	if !opts.SkipNetwork {
		report.Findings = append(report.Findings, checkUpstreamRegistries(ctx, opts.HTTPClient, opts.UpstreamRegistries)...)
	}
	// Database + schema-version check. When a DSN is configured and
	// a DBProber is wired (CLI does this with a pgstore-backed
	// adapter), doctor pings the DB and compares the stored
	// schema_version against Options.ExpectedSchemaVersion. Without
	// a prober we fall back to the informational "DSN present,
	// schema check deferred" finding to preserve the pre-wire-up
	// behaviour on binaries that haven't picked up the adapter yet.
	expectedSchemaVersion := opts.ExpectedSchemaVersion
	if strings.TrimSpace(expectedSchemaVersion) == "" {
		// Fall back to the binary version when the caller didn't
		// plumb a separate schema-version constant — keeps the
		// stub-replacement feature forward-compatible while older
		// callers continue to work.
		expectedSchemaVersion = opts.Version
	}
	report.Findings = append(report.Findings, checkDatabase(ctx, getenv, opts.DBProber, expectedSchemaVersion, opts.SkipNetwork)...)

	report.Normalize()
	sortFindings(report.Findings)
	return report
}

func sortFindings(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].Severity != findings[j].Severity {
			return findings[i].Severity > findings[j].Severity
		}
		return findings[i].Check < findings[j].Check
	})
}

// ---------- individual checks -----------------------------------

func checkEnv(getenv func(string) string) []Finding {
	var out []Finding
	// Required-ish env vars; "not set" isn't itself breaking (operators
	// often set these via config YAML instead), just worth surfacing.
	required := []string{"CHAINSAW_DATABASE_URL"}
	for _, name := range required {
		if strings.TrimSpace(getenv(name)) == "" {
			out = append(out, Finding{
				Check:       "env:" + name,
				Severity:    SeverityWarn,
				Message:     name + " is not set",
				Remediation: "Either export " + name + " or configure the equivalent in your YAML.",
			})
		}
	}

	// Deprecated env-flip warnings. We can't know the operator's
	// *previous* version, so we flag when the new default would
	// change behaviour AND the var isn't pinned.
	for _, flip := range DeprecatedEnvFlips {
		if strings.TrimSpace(getenv(flip.Name)) == "" {
			out = append(out, Finding{
				Check:       "env-flip:" + flip.Name,
				Severity:    SeverityWarn,
				Message:     fmt.Sprintf("%s default flipped from %q to %q — pin the value to preserve prior behaviour on upgrade", flip.Name, flip.OldDefault, flip.NewDefault),
				Remediation: flip.Remediation,
			})
		}
	}

	// Net-positive: if no warnings so far, emit an OK row so the
	// scorecard has one. A totally empty env is unusual but valid.
	if len(out) == 0 {
		out = append(out, Finding{
			Check:    "env",
			Severity: SeverityOK,
			Message:  "all required env vars set; no deprecated flips detected",
		})
	}
	return out
}

func checkConfig(path string, getenv func(string) string) []Finding {
	if strings.TrimSpace(path) == "" {
		path = strings.TrimSpace(getenv("CHAINSAW_CONFIG"))
	}
	if path == "" {
		return []Finding{{
			Check:    "config",
			Severity: SeverityOK,
			Message:  "no --config supplied; skipping YAML parse",
		}}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return []Finding{{
			Check:       "config",
			Severity:    SeverityBreaking,
			Message:     fmt.Sprintf("%s: %v", path, err),
			Remediation: "Verify the path and file permissions; the daemon will refuse to start if this file is unreadable.",
		}}
	}
	if len(data) == 0 {
		return []Finding{{
			Check:       "config",
			Severity:    SeverityWarn,
			Message:     path + " is empty",
			Remediation: "Either delete the file or populate it with a valid YAML document.",
		}}
	}
	// Strict schema validation: detect unknown top-level fields,
	// unknown nested fields, type mismatches, multi-document YAML,
	// and the deprecated-field list. See internal/doctor/config_strict.go
	// for the rationale behind a local strict mirror vs. re-using
	// internal/config.Config directly (the latter's `Extra` inline
	// map absorbs unknown top-level keys silently).
	findings := strictYAMLCheck(path, data)
	if len(findings) == 0 {
		return []Finding{{
			Check:    "config",
			Severity: SeverityOK,
			Message:  fmt.Sprintf("%s readable (%d bytes), schema clean", path, len(data)),
		}}
	}
	return findings
}

func checkDataDir(dir string, getenv func(string) string) []Finding {
	if strings.TrimSpace(dir) == "" {
		dir = strings.TrimSpace(getenv("CHAINSAW_DATA_DIR"))
	}
	if dir == "" {
		dir = "/etc/chainsaw/data"
	}
	var out []Finding

	info, err := os.Stat(dir)
	if err != nil {
		return []Finding{{
			Check:       "data-dir",
			Severity:    SeverityWarn,
			Message:     fmt.Sprintf("%s: %v", dir, err),
			Remediation: "Create the directory with mode 0700 owned by the chainsaw service user, or override via CHAINSAW_DATA_DIR.",
		}}
	}
	if !info.IsDir() {
		return []Finding{{
			Check:       "data-dir",
			Severity:    SeverityBreaking,
			Message:     dir + " is not a directory",
			Remediation: "Remove the file and re-create as a directory.",
		}}
	}

	// Writable?
	probe := filepath.Join(dir, ".chainsaw-doctor-write-probe")
	if err := os.WriteFile(probe, []byte("probe\n"), 0o600); err != nil {
		out = append(out, Finding{
			Check:       "data-dir:writable",
			Severity:    SeverityBreaking,
			Message:     "cannot write to " + dir + ": " + err.Error(),
			Remediation: "Ensure the service user owns the directory.",
		})
	} else {
		_ = os.Remove(probe)
	}

	// Secret-file perms. generated_password and generated_jwt_secret
	// should be 0400. If present, enforce — if absent, informational.
	for _, name := range []string{"generated_password", "generated_jwt_secret"} {
		p := filepath.Join(dir, name)
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		mode := fi.Mode().Perm()
		if mode != 0o400 {
			out = append(out, Finding{
				Check:       "data-dir:" + name,
				Severity:    SeverityWarn,
				Message:     fmt.Sprintf("%s has mode %04o; expected 0400", p, mode),
				Remediation: fmt.Sprintf("chmod 0400 %s", p),
				AutoFixable: true,
			})
		}
	}

	if len(out) == 0 {
		out = append(out, Finding{
			Check:    "data-dir",
			Severity: SeverityOK,
			Message:  dir + " exists, writable, secret files (if present) have 0400 perms",
		})
	}
	return out
}

func checkPorts(ports []int) []Finding {
	if len(ports) == 0 {
		ports = DefaultServerPorts
	}
	var out []Finding
	for _, p := range ports {
		addr := fmt.Sprintf("127.0.0.1:%d", p)
		l, err := net.Listen("tcp", addr)
		if err != nil {
			out = append(out, Finding{
				Check:       fmt.Sprintf("port:%d", p),
				Severity:    SeverityWarn,
				Message:     fmt.Sprintf("%s: %v", addr, err),
				Remediation: "Another process is holding the port. Run `lsof -iTCP -sTCP:LISTEN -n -P | grep " + fmt.Sprintf("%d", p) + "`.",
			})
			continue
		}
		_ = l.Close()
	}
	if len(out) == 0 {
		out = append(out, Finding{
			Check:    "ports",
			Severity: SeverityOK,
			Message:  fmt.Sprintf("default ports %v available", ports),
		})
	}
	return out
}

func checkTLS(configPath string, getenv func(string) string) []Finding {
	// We don't parse the YAML here (to stay out of internal/config);
	// instead we look for the conventional CHAINSAW_TLS_CERT /
	// CHAINSAW_TLS_KEY env vars that operators typically set when
	// terminating TLS in-process. Absence is OK (plaintext listener
	// is a valid deployment shape).
	cert := strings.TrimSpace(getenv("CHAINSAW_TLS_CERT"))
	key := strings.TrimSpace(getenv("CHAINSAW_TLS_KEY"))
	if cert == "" && key == "" {
		return []Finding{{
			Check:    "tls",
			Severity: SeverityOK,
			Message:  "no in-process TLS configured (plaintext listener)",
		}}
	}
	if cert == "" || key == "" {
		return []Finding{{
			Check:       "tls",
			Severity:    SeverityBreaking,
			Message:     "half-configured TLS: both cert and key must be set or neither",
			Remediation: "Either unset both, or provide a matching PEM cert + key pair.",
		}}
	}
	certBytes, err := os.ReadFile(cert)
	if err != nil {
		return []Finding{{
			Check:       "tls:cert",
			Severity:    SeverityBreaking,
			Message:     fmt.Sprintf("%s: %v", cert, err),
			Remediation: "Verify the path and service-user read permission.",
		}}
	}
	keyBytes, err := os.ReadFile(key)
	if err != nil {
		return []Finding{{
			Check:       "tls:key",
			Severity:    SeverityBreaking,
			Message:     fmt.Sprintf("%s: %v", key, err),
			Remediation: "Verify the path and service-user read permission.",
		}}
	}
	if _, err := tls.X509KeyPair(certBytes, keyBytes); err != nil {
		return []Finding{{
			Check:       "tls:pair",
			Severity:    SeverityBreaking,
			Message:     "cert/key pair does not match: " + err.Error(),
			Remediation: "Regenerate the pair or reissue the cert for the current key.",
		}}
	}
	// Expiry check (30-day threshold).
	block, _ := pem.Decode(certBytes)
	if block != nil {
		if leaf, err := x509.ParseCertificate(block.Bytes); err == nil {
			daysLeft := int(time.Until(leaf.NotAfter).Hours() / 24)
			if daysLeft < 0 {
				return []Finding{{
					Check:       "tls:expiry",
					Severity:    SeverityBreaking,
					Message:     "certificate expired " + fmt.Sprintf("%d", -daysLeft) + " days ago",
					Remediation: "Rotate the cert immediately.",
				}}
			}
			if daysLeft < 30 {
				return []Finding{{
					Check:       "tls:expiry",
					Severity:    SeverityWarn,
					Message:     fmt.Sprintf("certificate expires in %d days (<30)", daysLeft),
					Remediation: "Rotate before expiry to avoid a forced outage.",
				}}
			}
		}
	}
	_ = configPath // reserved for future YAML-level validation
	return []Finding{{
		Check:    "tls",
		Severity: SeverityOK,
		Message:  "cert + key parse, pair matches, expiry ≥30 days",
	}}
}

func checkUpstreamRegistries(ctx context.Context, client *http.Client, registries []string) []Finding {
	if len(registries) == 0 {
		registries = DefaultUpstreamRegistries
	}
	if client == nil {
		client = httpclient.New(httpclient.WithTimeout(5 * time.Second))
	}
	var unreachable []string
	for _, url := range registries {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
		if err != nil {
			unreachable = append(unreachable, url+" (bad url)")
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			unreachable = append(unreachable, url)
			continue
		}
		_ = resp.Body.Close()
	}
	if len(unreachable) == 0 {
		return []Finding{{
			Check:    "upstream-registries",
			Severity: SeverityOK,
			Message:  fmt.Sprintf("%d upstream registries reachable", len(registries)),
		}}
	}
	return []Finding{{
		Check:       "upstream-registries",
		Severity:    SeverityWarn,
		Message:     fmt.Sprintf("unreachable: %s", strings.Join(unreachable, ", ")),
		Remediation: "Verify firewall egress rules; air-gapped deployments can ignore this warning.",
	}}
}

func checkBreakingFlags(getenv func(string) string) []Finding {
	// We have no direct handle on the operator's systemd unit, so the
	// best we can do is scan the conventional places they'd pass CLI
	// flags: CHAINSAW_FLAGS, ARGS, and the inherited os.Args if this
	// very `doctor` invocation is embedded in the same command line.
	haystacks := []string{
		getenv("CHAINSAW_FLAGS"),
		getenv("CHAINSAW_ARGS"),
	}
	// Also include os.Args — but only the non-doctor tokens. This
	// catches "chainsaw --embedded-ui doctor --upgrade-check".
	for _, a := range os.Args {
		if a == "doctor" || strings.HasPrefix(a, "--upgrade") || strings.HasPrefix(a, "--json") || strings.HasPrefix(a, "--fix") {
			continue
		}
		haystacks = append(haystacks, a)
	}

	var findings []Finding
	for _, removed := range BreakingFlagRemovals {
		for _, h := range haystacks {
			if h == "" {
				continue
			}
			if strings.Contains(h, removed.Flag) {
				findings = append(findings, Finding{
					Check:       "breaking-flag:" + removed.Flag,
					Severity:    SeverityBreaking,
					Message:     removed.Flag + " is no longer accepted",
					Remediation: removed.Remediation,
				})
				break
			}
		}
	}
	if len(findings) == 0 {
		findings = append(findings, Finding{
			Check:    "breaking-flags",
			Severity: SeverityOK,
			Message:  "no removed flags detected in env or args",
		})
	}
	return findings
}

func checkVersionDrift(binaryVersion, composePath string) []Finding {
	if strings.TrimSpace(composePath) == "" {
		return []Finding{{
			Check:    "version-drift",
			Severity: SeverityOK,
			Message:  "no docker-compose.yml path supplied; skipping drift comparison",
		}}
	}
	data, err := os.ReadFile(composePath)
	if err != nil {
		return []Finding{{
			Check:       "version-drift",
			Severity:    SeverityWarn,
			Message:     fmt.Sprintf("%s: %v", composePath, err),
			Remediation: "Either supply a readable compose file or omit --docker-compose-path.",
		}}
	}
	// Very shallow parse: look for "chainsaw-proxy:<tag>" style pins.
	// This is intentionally approximate — compose files vary wildly
	// and we don't want to pull in a YAML dep just for this.
	text := string(data)
	for _, marker := range []string{"chainsaw-proxy:", "chainsaw:"} {
		idx := strings.Index(text, marker)
		if idx < 0 {
			continue
		}
		rest := text[idx+len(marker):]
		end := strings.IndexAny(rest, " \n\t\r\"'")
		if end < 0 {
			end = len(rest)
		}
		pinned := strings.TrimSpace(rest[:end])
		if pinned == "" || pinned == "latest" {
			return []Finding{{
				Check:       "version-drift",
				Severity:    SeverityWarn,
				Message:     composePath + " pins image tag " + strconvQuote(pinned) + " — no drift can be measured",
				Remediation: "Pin a specific version in docker-compose.yml.",
			}}
		}
		if pinned != binaryVersion {
			return []Finding{{
				Check:       "version-drift",
				Severity:    SeverityWarn,
				Message:     fmt.Sprintf("binary version %q differs from compose-pinned %q", binaryVersion, pinned),
				Remediation: "Update docker-compose.yml or rebuild the binary so both sides agree.",
			}}
		}
		return []Finding{{
			Check:    "version-drift",
			Severity: SeverityOK,
			Message:  "binary and docker-compose.yml both at " + pinned,
		}}
	}
	return []Finding{{
		Check:    "version-drift",
		Severity: SeverityOK,
		Message:  "no chainsaw image line found in " + composePath,
	}}
}

// strconvQuote is a tiny fmt %q replacement so we don't drag strconv
// into callers. Keeps the package self-contained.
func strconvQuote(s string) string {
	return `"` + s + `"`
}

// checkDatabase pings the DB (if a prober is configured), reads the
// schema_version row, and compares it against expected — the binary's
// pgstore.CurrentSchemaVersion. Paths:
//
//  1. no DSN            → SeverityOK informational (users running
//     doctor without a server). Same shape as
//     the prior stub so "I haven't wired a DB
//     yet" doesn't scare operators.
//  2. --skip-network    → same SeverityOK skip (caller explicitly
//     disabled outbound probes).
//  3. DSN, no prober    → SeverityOK informational ("deferred");
//     indicates the caller hasn't wired the
//     pgstore adapter yet.
//  4. ping fails        → SeverityBreaking with the connect error.
//  5. fresh DB          → SeverityWarn: "run server once to seed".
//  6. versions match    → SeverityOK.
//  7. DB older          → SeverityWarn: "server startup will migrate".
//  8. DB newer          → SeverityWarn: "binary predates DB — see
//     MIGRATIONS.md for downgrade guidance".
func checkDatabase(ctx context.Context, getenv func(string) string, prober DBProber, expected string, skipNetwork bool) []Finding {
	dsn := strings.TrimSpace(getenv("CHAINSAW_DATABASE_URL"))
	if dsn == "" {
		return []Finding{{
			Check:    "database",
			Severity: SeverityOK,
			Message:  "CHAINSAW_DATABASE_URL not set; skipping schema-version check",
		}}
	}
	if skipNetwork {
		return []Finding{{
			Check:    "database",
			Severity: SeverityOK,
			Message:  "skipping database probe (--skip-network)",
		}}
	}
	if prober == nil {
		return []Finding{{
			Check:    "database",
			Severity: SeverityOK,
			Message:  "DSN present; schema-version check skipped (no DB prober wired — see cmd/chainsaw CLI glue)",
		}}
	}
	if err := prober.Ping(ctx); err != nil {
		return []Finding{{
			Check:       "database",
			Severity:    SeverityBreaking,
			Message:     fmt.Sprintf("cannot connect to database: %v", err),
			Remediation: "Verify CHAINSAW_DATABASE_URL host/port/credentials and that Postgres is reachable from this host.",
		}}
	}
	stored, err := prober.SchemaVersion(ctx)
	if err != nil {
		if errors.Is(err, ErrFreshDatabase) {
			return []Finding{{
				Check:       "database",
				Severity:    SeverityWarn,
				Message:     "fresh database (no schema_version row) — run the server once to initialize the schema",
				Remediation: "Boot chainsaw-proxy; it will CREATE the tables and INSERT the schema_version marker.",
			}}
		}
		return []Finding{{
			Check:       "database",
			Severity:    SeverityBreaking,
			Message:     fmt.Sprintf("schema_version lookup failed: %v", err),
			Remediation: "Check the Postgres user has SELECT on the chainsaw schema; see MIGRATIONS.md for the table shape.",
		}}
	}
	if strings.TrimSpace(expected) == "" {
		// Defensive: if the caller forgot to plumb ExpectedSchemaVersion
		// we still want to show the DB's value rather than panic or
		// compare against "".
		return []Finding{{
			Check:    "database",
			Severity: SeverityOK,
			Message:  fmt.Sprintf("database reachable, schema_version=%q (binary did not supply an expected version)", stored),
		}}
	}
	switch cmp := compareSchemaVersions(stored, expected); {
	case cmp == 0:
		return []Finding{{
			Check:    "database",
			Severity: SeverityOK,
			Message:  fmt.Sprintf("schema_version=%s matches binary", stored),
		}}
	case cmp < 0:
		return []Finding{{
			Check:       "database",
			Severity:    SeverityWarn,
			Message:     fmt.Sprintf("schema_version=%s older than binary %s — server startup will perform schema upgrade", stored, expected),
			Remediation: "Review MIGRATIONS.md for the " + expected + " entry, then restart chainsaw-proxy to apply the schema changes.",
		}}
	default:
		return []Finding{{
			Check:       "database",
			Severity:    SeverityWarn,
			Message:     fmt.Sprintf("schema_version=%s newer than binary %s — running an older binary against a newer schema", stored, expected),
			Remediation: "Either upgrade this binary to match the database, or consult MIGRATIONS.md for downgrade guidance.",
		}}
	}
}

// compareSchemaVersions returns -1 if a < b, 0 if equal, +1 if a > b.
// Mirrors pgstore.schemaVersionLess semantics so doctor and pgstore
// agree. Kept local to avoid importing internal/pgstore into doctor.
func compareSchemaVersions(a, b string) int {
	if a == b {
		return 0
	}
	as := splitDotted(a)
	bs := splitDotted(b)
	n := len(as)
	if len(bs) < n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		if as[i] == bs[i] {
			continue
		}
		ai, aok := atoiSimple(as[i])
		bi, bok := atoiSimple(bs[i])
		if aok && bok {
			if ai < bi {
				return -1
			}
			return 1
		}
		if as[i] < bs[i] {
			return -1
		}
		return 1
	}
	if len(as) == len(bs) {
		return 0
	}
	if len(as) < len(bs) {
		return -1
	}
	return 1
}

func splitDotted(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '.' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start <= len(s) {
		out = append(out, s[start:])
	}
	return out
}

func atoiSimple(s string) (int, bool) {
	if s == "" {
		return 0, false
	}
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
