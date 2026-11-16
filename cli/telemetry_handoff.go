package cli

// telemetry_handoff.go — the CLI never waits on the telemetry network.
//
// THE COST THIS REMOVES. Execute() wraps every invocation in
// cli.session.started / cli.session.completed, and flushTelemetry used to
// POST them synchronously before the process exited. Measured 2026-11-16 on
// v0.22.164 with consent granted: `chainsaw --version` took 0.58–1.36s,
// against 0.03s with telemetry disabled. The guard shell shim turns every
// npm / pip / go / cargo call — `npm run dev` and `go test` included — into
// `command chainsaw <tool> …`, so a consenting user paid that second on each
// one.
//
// THE FIX. flushTelemetry takes the buffered batch and hands it, over a
// stdin pipe, to a detached copy of this binary started as
// `chainsaw __telemetry-send`. The parent pays one process spawn and a small
// pipe write, then exits; the child does the POST in its own session, so a
// Ctrl-C or a closed terminal does not kill it.
//
// WHAT DOES NOT CHANGE.
//   - R1 (default deny). Events are only captured after emitAt's consent
//     gate. The child re-checks consent and ResolveMode before it sends, so a
//     hand-built payload on a non-consenting machine sends nothing either.
//   - The event set. Same events, same properties, same endpoint and
//     Authorization header; only the process that does the POST moves.
//   - The API key never appears in argv (visible in `ps`). It travels on the
//     pipe with the batch.
//
// A failed spawn drops the batch. A dropped event is preferable to a jammed
// CLI (core/telemetry/client.go design notes), and a synchronous fallback
// would bring back exactly the stall this file exists to remove.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/telemetry"
)

// telemetrySenderArg is argv[1] of the detached sender. Execute() routes it
// before cobra parses anything, like --cargo-plugin, so the child runs no
// initConfig, touches no keychain and emits no session events of its own.
const telemetrySenderArg = "__telemetry-send"

// telemetrySenderMaxBytes caps what the child reads from its pipe. The
// client buffer holds at most 512 events, far below this.
const telemetrySenderMaxBytes = 4 << 20

// telemetryHandoffPayload is the pipe format between parent and child.
type telemetryHandoffPayload struct {
	Endpoint string            `json:"endpoint"`
	APIKey   string            `json:"api_key,omitempty"`
	Version  string            `json:"version,omitempty"`
	Events   []telemetry.Event `json:"events"`
}

// telemetryCfg is the config initTelemetry built the client from; the
// handoff forwards its endpoint, key and version to the child.
var telemetryCfg telemetry.Config

// startTelemetrySender starts the detached sender with payload on its stdin
// and returns without waiting. A variable so tests can run the child half
// in-process; production code never reassigns it.
var startTelemetrySender = spawnTelemetrySender

// handOffTelemetry passes batch to the detached sender. Never blocks on the
// network and never returns an error: telemetry cannot break the CLI.
func handOffTelemetry(batch []telemetry.Event) {
	if len(batch) == 0 || telemetryCfg.Endpoint == "" {
		return
	}
	payload, err := json.Marshal(telemetryHandoffPayload{
		Endpoint: telemetryCfg.Endpoint,
		APIKey:   telemetryCfg.APIKey,
		Version:  telemetryCfg.ChainsawVersion,
		Events:   batch,
	})
	if err != nil {
		return
	}
	_ = startTelemetrySender(payload)
}

// spawnTelemetrySender re-executes this binary as the detached sender.
func spawnTelemetrySender(payload []byte) error {
	// Inside `go test`, os.Executable() is the test binary, which ignores
	// the unknown argument and runs the whole suite again. Refuse.
	if testing.Testing() {
		return errors.New("telemetry: detached sender disabled under go test")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, telemetrySenderArg)
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = detachedProcAttr()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return err
	}
	// A session pair is ~1 KB, well under the pipe buffer, so this write
	// returns at once; a large batch waits only until the child starts
	// reading, never on the network.
	_, werr := stdin.Write(payload)
	_ = stdin.Close()
	_ = cmd.Process.Release()
	return werr
}

// runTelemetrySender is the child half: read one payload, re-check the
// gates, POST it. Silent on every failure.
func runTelemetrySender(r io.Reader) {
	body, err := io.ReadAll(io.LimitReader(r, telemetrySenderMaxBytes))
	if err != nil {
		return
	}
	var p telemetryHandoffPayload
	if err := json.Unmarshal(body, &p); err != nil || p.Endpoint == "" || len(p.Events) == 0 {
		return
	}
	// R1 again, in the process that opens the socket. The child inherits the
	// parent's environment, so DO_NOT_TRACK / CHAINSAW_OFFLINE /
	// CHAINSAW_TELEMETRY_DISABLED and the config home resolve the same way.
	if telemetry.ResolveMode() != telemetry.ModeEnabled || !cliTelemetryConsented() {
		return
	}
	c := telemetry.New(telemetry.Config{
		Endpoint:        p.Endpoint,
		Source:          telemetry.SurfaceCLI,
		ChainsawVersion: p.Version,
		APIKey:          p.APIKey,
		Mode:            telemetry.ModeEnabled,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = c.Send(ctx, p.Events)
}
