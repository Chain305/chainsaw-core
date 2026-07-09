package cli

// CLI-side telemetry runtime. This file holds the process-wide
// telemetry.Client (lazy, one per invocation) and the emit() helper that
// every command calls. The goal is zero-friction instrumentation — adding
// an event to a command is one line.
//
// Boundaries:
//   * No event is emitted when telemetry is disabled (Mode == Disabled).
//   * No event is emitted when install_id is disabled or unavailable.
//   * emit() never returns an error; telemetry can't break the CLI.

import (
	"context"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/chain305/chainsaw-core/telemetry"
)

var (
	telemetryOnce sync.Once
	telemetryCli  *telemetry.Client

	sessionStarted time.Time
)

// initTelemetry constructs the telemetry client on first use. Nil-safe
// return — if we can't figure out an endpoint or install_id, we hand
// back a disabled client that silently no-ops.
func initTelemetry() *telemetry.Client {
	telemetryOnce.Do(func() {
		mode := telemetry.ResolveMode()
		if mode == telemetry.ModeDisabled {
			telemetryCli = telemetry.New(telemetry.Config{Mode: telemetry.ModeDisabled})
			return
		}
		// Endpoint resolution:
		//   - configured server (setup/login/DefaultServer) → <server>/api/telemetry/ingest
		//   - else, CLOUD build with no server → DefaultTelemetryEndpoint
		//     (chain305.com), so free/local guard users are MEASURABLE. The
		//     anonymous ingest route accepts install:<id> events without a
		//     Bearer token (per-IP rate-limited server-side).
		//   - self-hosted build with no server → no default; emit nothing
		//     (a self-hoster must point at THEIR server, never ours).
		// Consent/privacy is enforced upstream by ResolveMode (DNT /
		// CHAINSAW_OFFLINE / CHAINSAW_TELEMETRY_DISABLED → ModeDisabled before we
		// get here) and the scrub; package-identifying data stays behind the
		// separate first-run consent. CHAINSAW_TELEMETRY_ENDPOINT overrides all.
		server := strings.TrimRight(cfgServerURL(), "/")
		defaultURL := ""
		if server != "" {
			defaultURL = server + "/api/telemetry/ingest"
		} else if !telemetry.IsSelfHosted() {
			defaultURL = DefaultTelemetryEndpoint
		}
		endpoint := telemetry.Endpoint(defaultURL)
		if endpoint == "" || strings.HasPrefix(endpoint, "/") {
			telemetryCli = telemetry.New(telemetry.Config{Mode: telemetry.ModeDisabled})
			return
		}
		telemetryCli = telemetry.New(telemetry.Config{
			Endpoint:        endpoint,
			Source:          telemetry.SurfaceCLI,
			ChainsawVersion: Version,
			APIKey:          cfgToken(),
			Env:             resolveEnv(),
			Mode:            mode,
		})
	})
	return telemetryCli
}

// emit is the one call-site every command uses. Silently drops events if
// telemetry is disabled or the install_id is unavailable. Properties
// get stamped with install_id, user_id (when known), org_id, persona.
func emit(name string, props map[string]any) {
	c := initTelemetry()
	if c == nil {
		return
	}
	install, err := telemetry.ProcessInstall()
	if err != nil || install.Disabled {
		return
	}
	distinctID := telemetry.DistinctID(install)
	if distinctID == "" {
		return
	}

	enriched := make(map[string]any, len(props)+4)
	for k, v := range props {
		enriched[k] = v
	}
	enriched["install_id"] = install.ID
	enriched["surface"] = string(telemetry.SurfaceCLI)
	if org := strings.TrimSpace(cfgOrgID()); org != "" {
		enriched["org_id"] = org
	}

	c.Capture(name, distinctID, enriched)
}

// flushTelemetry drains any pending events. Called from the Execute()
// wrapper after the command returns. Bounded by the client's HTTP
// timeout; never hangs the process.
func flushTelemetry() {
	if telemetryCli == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	telemetryCli.Flush(ctx)
	telemetryCli.Close()
}

// markSessionStart records the session start time; called from the
// PersistentPreRunE hook once the command tree is resolved.
func markSessionStart(cmdPath string) {
	sessionStarted = time.Now()
	emit(telemetry.EventCLISessionStarted, map[string]any{
		"cli_command": cmdPath,
		"ci":          isCIEnvironment(),
		"tty":         isStdoutTTY(),
		"first_run":   isFirstRun(),
	})
}

// markSessionEnd emits the completion event. cmdPath is the resolved
// command (or "unknown" if parsing failed before PreRun ran); exitCode
// maps to the process exit status.
func markSessionEnd(cmdPath string, exitCode int, errClass string) {
	dur := int64(0)
	if !sessionStarted.IsZero() {
		dur = time.Since(sessionStarted).Milliseconds()
	}
	props := map[string]any{
		"cli_command": cmdPath,
		"exit_code":   exitCode,
		"duration_ms": dur,
	}
	if errClass != "" {
		props["error_class"] = errClass
	}
	emit(telemetry.EventCLISessionCompleted, props)
}

// resolveEnv returns the env tag stamped on every event. Honors
// CHAINSAW_ENV if the operator wants to tag (e.g. "staging"); otherwise
// falls back to a heuristic.
func resolveEnv() string {
	if v := strings.TrimSpace(os.Getenv("CHAINSAW_ENV")); v != "" {
		return v
	}
	return "prod"
}

func isCIEnvironment() bool {
	for _, k := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "JENKINS_URL", "TEAMCITY_VERSION"} {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" && !strings.EqualFold(v, "false") {
			return true
		}
	}
	return false
}

func isStdoutTTY() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

// isFirstRun reports whether this invocation is the first time this
// install_id has been loaded (the install file was freshly created).
// Cheap heuristic: the file's mtime is within the last few seconds.
func isFirstRun() bool {
	dir, err := telemetry.ConfigDir()
	if err != nil {
		return false
	}
	fi, err := os.Stat(dir + "/install_id")
	if err != nil {
		return false
	}
	return time.Since(fi.ModTime()) < 5*time.Second
}
