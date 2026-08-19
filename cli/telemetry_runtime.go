package cli

// CLI-side telemetry runtime. This file holds the process-wide
// telemetry.Client (lazy, one per invocation) and the emit() helper that
// every command calls. The goal is zero-friction instrumentation — adding
// an event to a command is one line.
//
// Boundaries:
//   - No event is emitted until the operator has EXPLICITLY consented
//     (cliTelemetryConsented). Default deny: absent, undecided, or corrupt
//     state sends nothing.
//   - No event is emitted when telemetry is disabled (Mode == Disabled).
//   - No event is emitted when install_id is disabled or unavailable.
//   - emit() never returns an error; telemetry can't break the CLI.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/chain305/chainsaw-core/telemetry"
)

var (
	telemetryOnce sync.Once
	telemetryCli  *telemetry.Client

	sessionStarted time.Time

	// pendingSessionStart holds the cli.session.started event between
	// markSessionStart (which runs before cobra parses anything) and
	// markSessionEnd (which runs after initConfig). See markSessionStart.
	pendingSessionStart     map[string]any
	pendingSessionStartedAt time.Time

	// flushTelemetryOnce makes flushTelemetry idempotent so Execute() can
	// call it explicitly before os.Exit AND keep the deferred call for the
	// panic path without double-flushing / double-closing.
	flushTelemetryOnce sync.Once
)

// cliTelemetryConsented reports whether the operator has EXPLICITLY opted
// in to telemetry on this machine (`chainsaw telemetry on`, or answering
// yes to the guard's first-run prompt).
//
// R1 — DEFAULT DENY. The persisted decision lives in guard_state.json and
// was read by the GUARD emitters only; the process-wide emit() gated
// solely on ResolveMode() (four env vars) and install.Disabled. Measured
// on real release builds: after `chainsaw telemetry off` the CLI still
// POSTed cli.session.started + cli.session.completed carrying install_id,
// and a CI host with NO consent record at all sent both events too —
// directly contradicting docs/TELEMETRY.md ("Non-TTY / CI runs collect
// and send nothing — ever"). The gap was the intersection of two commits:
// 6333714e added the consent gate to the guard path; 1583d651 later opened
// the anonymous session-event tier without one.
//
// Every state other than an explicit "granted" returns false: declined,
// never-asked, an unreadable file, and a corrupt JSON body all decode to
// the zero value. This is idempotent with the guard path, which already
// checks the same field before emitting.
//
// SCOPE NOTE: this is a client-side send gate, not a data-classification
// gate. Package-identifying data was already consent-gated; what this
// closes is the leak of a persistent machine identifier plus which command
// ran.
func cliTelemetryConsented() bool {
	return loadGuardState().Consent == consentGranted
}

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
		// Consent/privacy is enforced upstream by emit()'s explicit-consent
		// gate (cliTelemetryConsented) and by ResolveMode (DO_NOT_TRACK /
		// CHAINSAW_OFFLINE / CHAINSAW_TELEMETRY_DISABLED → ModeDisabled before we
		// get here), plus the scrub. CHAINSAW_TELEMETRY_ENDPOINT overrides all.
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
// the operator has not consented, if telemetry is disabled, or if the
// install_id is unavailable. Properties get stamped with install_id,
// surface, and org_id.
func emit(name string, props map[string]any) {
	emitAt(name, time.Time{}, props)
}

// emitAt is emit with an explicit event timestamp, for an event that was
// OBSERVED earlier than it could be SENT (see markSessionStart). A zero ts
// means "now".
func emitAt(name string, ts time.Time, props map[string]any) {
	// L-12: DEBUG IS A LOCAL PREVIEW AND IS NOT CONSENT-GATED.
	//
	// CHAINSAW_TELEMETRY_DEBUG=1 prints what WOULD be emitted and sends
	// nothing (telemetry.Client short-circuits ModeDebug to a stderr write
	// before the buffer, core/telemetry/client.go). Requiring consent to
	// preview what consenting means is a consent dark pattern, and the old
	// ordering made `chainsaw telemetry debug` a silent no-op on exactly the
	// box whose operator had not opted in — indistinguishable from broken.
	//
	// The R1 invariant below still holds on this branch, and that is the
	// whole point of writing the preview by hand instead of reusing the
	// client: it deliberately does NOT call initTelemetry() (no client, no
	// socket, no endpoint resolution) and does NOT call
	// telemetry.ProcessInstall() (no persistent install_id is minted on a
	// machine that has not consented). The printed install_id is an explicit
	// placeholder for that reason — see telemetryDebugPlaceholderID.
	if telemetry.ResolveMode() == telemetry.ModeDebug {
		writeTelemetryDebugEvent(name, ts, props)
		return
	}
	// R1: consent first, before ANYTHING else. Deliberately ahead of
	// initTelemetry() and telemetry.ProcessInstall() so a non-consenting
	// run constructs no client, opens no socket, and — via LoadInstall —
	// mints no persistent identifier.
	if !cliTelemetryConsented() {
		return
	}
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

	c.CaptureAt(name, distinctID, ts, enriched)
}

// flushTelemetry drains any pending events. Called explicitly from the
// Execute() wrapper immediately after markSessionEnd (BEFORE os.Exit,
// which skips defers) and again from a defer as the panic-path backstop.
// Bounded by the client's HTTP timeout; never hangs the process.
//
// R3: Execute() previously relied SOLELY on `defer flushTelemetry()`,
// which os.Exit(exitCode) never runs — so every FAILING command dropped
// its whole batch, and cli.session.completed with exit_code/error_class
// (precisely the events the funnel needs) was never delivered. The
// background flusher only ticks every 5s, which a CLI never reaches.
//
// Idempotency detail: the CLOSE is sync.Once-guarded so the explicit call
// and the deferred backstop can't double-tear-down the client. The FLUSH
// deliberately is NOT — the guard path calls flushTelemetry() mid-process
// (guard_nudge.go, before its own os.Exit), and once-guarding the drain
// would silently discard every event captured after that point on the
// passthrough branch that does return through Execute(). Flush is safe to
// call repeatedly, and Client.Close is internally once-guarded too.
func flushTelemetry() {
	// L-12: the debug branch of emitAt never builds a client, so the trailer
	// has to run BEFORE the nil check or `telemetry debug` would still end
	// in silence when the wrapped command emitted nothing at all.
	writeTelemetryDebugTrailer()
	if telemetryCli == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	telemetryCli.Flush(ctx)
	flushTelemetryOnce.Do(func() { telemetryCli.Close() })
}

// markSessionStart records the session start time and STASHES the
// cli.session.started event. It is called from Execute() before
// rootCmd.Execute(), i.e. before cobra parses argv and before
// cobra.OnInitialize(initConfig) fires.
//
// R2: the event is deliberately NOT emitted here. Emitting at this point
// froze initTelemetry's sync.Once against a config that had not been read
// yet — cfgServerURL() could only return the ldflags DefaultServer, so a
// self-hosting operator's session events went to the chain305.com FALLBACK
// endpoint with no Authorization header, and org_id was absent on
// `started` while present on `completed` (emit reads cfgOrgID() per call
// while the endpoint and APIKey are frozen in the Once).
//
// The obvious fix — running initConfig() before this — was rejected as net
// negative: it runs before cobra's ParseFlags, so --token/--server/--org
// would be invisible, and migrateTokenToKeychain's InConfig gate (whose
// docstring exists to pin "--token beats the keychain") would evaluate
// against an empty token and could clobber the flag. Deferring the EMIT
// instead changes nothing about precedence: nothing is read EARLIER than
// before, only later. The observed start time is preserved explicitly via
// emitAt so the deferral cannot distort session duration.
func markSessionStart(cmdPath string) {
	sessionStarted = time.Now()
	pendingSessionStartedAt = sessionStarted.UTC()
	pendingSessionStart = map[string]any{
		"cli_command": cmdPath,
		"ci":          isCIEnvironment(),
		"tty":         isStdoutTTY(),
		"first_run":   isFirstRun(),
	}
}

// flushPendingSessionStart emits the stashed cli.session.started event, if
// any. Idempotent: the stash is cleared on the way out.
func flushPendingSessionStart() {
	props := pendingSessionStart
	if props == nil {
		return
	}
	pendingSessionStart = nil
	emitAt(telemetry.EventCLISessionStarted, pendingSessionStartedAt, props)
}

// markSessionEnd emits the deferred start event and then the completion
// event, in that order. cmdPath is the resolved command (or "unknown" if
// parsing failed before PreRun ran); exitCode maps to the process exit
// status.
func markSessionEnd(cmdPath string, exitCode int, errClass string) {
	// R2: by now initConfig() has run, so the endpoint, Authorization
	// header, and org_id all resolve against the user's real config.
	flushPendingSessionStart()

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

// ciEnvVars are the environment variables whose presence marks a CI runner.
// Kept as a package-level list rather than inlined so tests that need a
// genuinely non-CI environment can neutralize every signal from the same
// source of truth: clearing only CI is not enough, because a GitHub Actions
// runner also exports GITHUB_ACTIONS. (That gap silenced the post-block guard
// nudge and made core/cli fail only under CI, which blocked the open-core
// publish gate.) Adding a provider here automatically extends both the
// detection and the test isolation.
var ciEnvVars = []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI", "BUILDKITE", "CIRCLECI", "JENKINS_URL", "TEAMCITY_VERSION"}

func isCIEnvironment() bool {
	for _, k := range ciEnvVars {
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

// ── local debug preview (L-12) ────────────────────────────────────────────────
//
// CHAINSAW_TELEMETRY_DEBUG=1 turns emit() into a LOCAL PRINTER. Nothing is
// buffered, nothing is sent, nothing is persisted. The sink lives here rather
// than in telemetry.Client because reaching the client at all would mean
// calling initTelemetry() and telemetry.ProcessInstall(), and the second of
// those MINTS AND WRITES a persistent install_id — the identifier a
// non-consenting operator must never acquire as a side effect of asking what
// telemetry would look like. See the branch at the top of emitAt.

// telemetryDebugPlaceholderID stands in for the install_id every real event
// carries. It is deliberately not a valid id and deliberately self-describing:
// the debug preview must not imply that a machine identifier exists, and must
// not create one to make the preview prettier.
// (Angle brackets are deliberately avoided: encoding/json HTML-escapes them,
// which would render the placeholder as \u003c… in the very output an operator
// reads to decide whether they believe us.)
const telemetryDebugPlaceholderID = "(not minted in debug mode)"

var (
	telemetryDebugOut       io.Writer = os.Stderr
	telemetryDebugPreamble  sync.Once
	telemetryDebugTrailer   sync.Once
	telemetryDebugEventSeen atomic.Int64
)

// writeTelemetryDebugPreamble prints the one-time header. It is what makes the
// command self-explanatory instead of a wall of JSON (or, worse, nothing).
func writeTelemetryDebugPreamble() {
	telemetryDebugPreamble.Do(func() {
		fmt.Fprintln(telemetryDebugOut, "chainsaw: telemetry debug mode (CHAINSAW_TELEMETRY_DEBUG=1).")
		fmt.Fprintln(telemetryDebugOut, "chainsaw: events below are printed locally and are NOT sent anywhere.")
		fmt.Fprintln(telemetryDebugOut, "chainsaw: no install_id is created, and your telemetry consent setting is not read or changed.")
	})
}

// writeTelemetryDebugEvent renders one event as it would be captured. The
// property set mirrors what emitAt stamps on a real event (surface, org_id)
// so the preview is useful for verifying instrumentation, with install_id
// replaced by the placeholder.
func writeTelemetryDebugEvent(name string, ts time.Time, props map[string]any) {
	writeTelemetryDebugPreamble()
	telemetryDebugEventSeen.Add(1)

	if ts.IsZero() {
		ts = time.Now()
	}
	enriched := make(map[string]any, len(props)+3)
	for k, v := range props {
		enriched[k] = v
	}
	enriched["install_id"] = telemetryDebugPlaceholderID
	enriched["surface"] = string(telemetry.SurfaceCLI)
	if org := strings.TrimSpace(cfgOrgID()); org != "" {
		enriched["org_id"] = org
	}

	payload := map[string]any{
		"event":      name,
		"timestamp":  ts.UTC().Format(time.RFC3339Nano),
		"sent":       false,
		"properties": enriched,
	}
	b, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintf(telemetryDebugOut, "chainsaw: telemetry debug event %s (could not render properties: %v)\n", name, err)
		return
	}
	fmt.Fprintln(telemetryDebugOut, string(b))
}

// writeTelemetryDebugTrailer closes out a debug run. NEVER A SILENT NO-OP is
// the requirement: a wrapped command that emitted nothing must say so, because
// "no output" is exactly what the broken behaviour looked like.
//
// Once-guarded so the guard path's mid-process flush and Execute()'s explicit
// + deferred flushes cannot print it three times. The guard path exits right
// after its flush, so printing there is the correct moment for that branch.
func writeTelemetryDebugTrailer() {
	if telemetry.ResolveMode() != telemetry.ModeDebug {
		return
	}
	telemetryDebugTrailer.Do(func() {
		writeTelemetryDebugPreamble()
		if telemetryDebugEventSeen.Load() == 0 {
			fmt.Fprintln(telemetryDebugOut, "chainsaw: this command emitted no telemetry events.")
			return
		}
		fmt.Fprintf(telemetryDebugOut, "chainsaw: %d telemetry event(s) printed above; 0 sent.\n", telemetryDebugEventSeen.Load())
	})
}
