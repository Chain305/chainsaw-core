package telemetry

// Client is the telemetry SDK embedded into the CLI, MCP server, and
// chainproxy. It accepts Capture() calls on the hot path (O(1) append to
// a bounded in-memory buffer) and flushes asynchronously to the backend
// /api/telemetry/ingest endpoint.
//
// Design notes:
//   * No PostHog SDK in client binaries. The backend owns the POSTHOG_API_KEY
//     and enriches events with server-side context (plan, email_domain)
//     before forwarding.
//   * Never blocks. Every public method returns instantly; a dropped
//     event is preferable to a jammed CLI.
//   * Respects Mode at every emit site. ModeDebug prints JSON to stderr;
//     ModeDisabled is a no-op.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
)

const (
	defaultFlushInterval = 5 * time.Second
	defaultMaxBatch      = 64
	defaultMaxBufferSize = 512
	defaultHTTPTimeout   = 4 * time.Second
)

// Event is the wire shape posted to the ingest endpoint. This struct is
// also the one the server unmarshals — keep the JSON tags identical on
// both sides (see internal/server/telemetry_ingest.go).
type Event struct {
	Name       string         `json:"name"`
	DistinctID string         `json:"distinct_id,omitempty"`
	Timestamp  time.Time      `json:"timestamp"`
	Properties map[string]any `json:"properties,omitempty"`
}

// Config configures a Client. Endpoint is required; the rest have
// sensible defaults that suit a short-lived CLI invocation.
type Config struct {
	// Endpoint is the fully-qualified URL of /api/telemetry/ingest.
	Endpoint string

	// Source identifies the emitting binary — one of the Surface
	// constants (SurfaceCLI, SurfaceMCP, etc). Set once at construction;
	// stamped on every event.
	Source Surface

	// ChainsawVersion is the semver of the emitting binary. Passed
	// through on every event so dashboards can slice by version.
	ChainsawVersion string

	// APIKey is sent as Authorization: Bearer <key> when non-empty.
	//
	// CORRECTION (was stale): this used to claim "free/local clients …
	// emit nothing — so there is no anonymous-tier ingest today". That has
	// not been true since DefaultTelemetryEndpoint shipped: a cloud build
	// with no configured server posts to chain305.com's ingest route with
	// NO Authorization header, and the route accepts install:<id> events
	// anonymously (per-IP rate-limited server-side). Authenticated events
	// are additionally enriched server-side with the owning user+org for
	// funnel correlation.
	//
	// What actually gates the anonymous tier is CLIENT-SIDE consent: emit()
	// refuses to send anything until the operator has explicitly granted
	// it (see cliTelemetryConsented in core/cli/telemetry_runtime.go).
	APIKey string

	// Env is "prod", "staging", "local", "test"; stamped on every event.
	Env string

	// Mode determines whether events are sent, dropped, or printed.
	Mode Mode

	// FlushInterval controls the background flush cadence. Zero ⇒ default.
	FlushInterval time.Duration

	// MaxBatch caps the number of events per ingest POST. Zero ⇒ default.
	MaxBatch int

	// HTTPClient overrides the HTTP client used for flushes. Useful for
	// tests; defaults to a short-timeout client.
	HTTPClient *http.Client

	// Logger receives warnings when a flush fails. Nil ⇒ silent.
	Logger Logger
}

// Logger is a minimal interface the client uses to surface non-fatal
// issues. Any slog-compatible shim works.
type Logger interface {
	Warn(msg string, args ...any)
}

// Client is safe for concurrent use after New returns.
type Client struct {
	cfg      Config
	mu       sync.Mutex
	buf      []Event
	closedCh chan struct{}
	once     sync.Once

	// For ModeDebug: stderr is the natural sink so stdout stays clean
	// for scriptable CLI output.
	debugSink io.Writer
}

// New constructs a Client and starts the background flusher goroutine.
// If cfg.Mode is ModeDisabled the returned client is a usable no-op.
func New(cfg Config) *Client {
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = defaultFlushInterval
	}
	if cfg.MaxBatch == 0 {
		cfg.MaxBatch = defaultMaxBatch
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = httpclient.New(httpclient.WithTimeout(defaultHTTPTimeout))
	}
	c := &Client{
		cfg:       cfg,
		closedCh:  make(chan struct{}),
		debugSink: os.Stderr,
	}
	if cfg.Mode == ModeEnabled {
		go c.runFlusher()
	}
	return c
}

// Capture records an event stamped with the current wall clock. Missing
// or invalid events are dropped silently — telemetry is never allowed to
// affect caller behavior.
func (c *Client) Capture(name string, distinctID string, props map[string]any) {
	c.CaptureAt(name, distinctID, time.Now().UTC(), props)
}

// CaptureAt is Capture with an explicit event timestamp, for callers that
// must record WHEN something happened separately from when they were able
// to hand it over. The CLI needs this: cli.session.started is observed
// before the config file has been read, so the event is stashed and only
// emitted once the endpoint / auth / org_id can be resolved correctly —
// see markSessionStart in core/cli/telemetry_runtime.go. Without an
// explicit timestamp the started event would carry the session's END time
// and the duration between started/completed would collapse to zero.
//
// A zero ts falls back to the current wall clock.
func (c *Client) CaptureAt(name string, distinctID string, ts time.Time, props map[string]any) {
	if c == nil || c.cfg.Mode == ModeDisabled {
		return
	}
	if !IsKnownEvent(name) {
		if c.cfg.Logger != nil {
			c.cfg.Logger.Warn("telemetry: dropping unknown event", "name", name)
		}
		return
	}
	if distinctID == "" {
		return
	}

	enriched := make(map[string]any, len(props)+8)
	for k, v := range props {
		enriched[k] = v
	}
	enriched["event_version"] = EventVersion
	enriched["source"] = string(c.cfg.Source)
	enriched["channel"] = string(c.cfg.Source)
	enriched["session_id"] = SessionID()
	if c.cfg.ChainsawVersion != "" {
		enriched["chainsaw_version"] = c.cfg.ChainsawVersion
	}
	if c.cfg.Env != "" {
		enriched["env"] = c.cfg.Env
	}
	enriched["runtime_os"] = runtime.GOOS
	enriched["runtime_arch"] = runtime.GOARCH
	enriched = Scrub(enriched)

	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	evt := Event{
		Name:       name,
		DistinctID: distinctID,
		Timestamp:  ts.UTC(),
		Properties: enriched,
	}

	if c.cfg.Mode == ModeDebug {
		c.writeDebug(evt)
		return
	}

	c.mu.Lock()
	if len(c.buf) >= defaultMaxBufferSize {
		// Drop oldest to keep memory bounded. Preferable to blocking the
		// caller; the first events of a long session are usually the
		// least interesting anyway.
		c.buf = c.buf[1:]
	}
	c.buf = append(c.buf, evt)
	c.mu.Unlock()
}

// Flush writes any pending events synchronously. Safe to call multiple
// times; typically the CLI's PostRun invokes this so the short-lived
// process doesn't lose its tail events.
func (c *Client) Flush(ctx context.Context) {
	if c == nil || c.cfg.Mode != ModeEnabled {
		return
	}
	c.mu.Lock()
	batch := c.buf
	c.buf = nil
	c.mu.Unlock()
	if len(batch) == 0 {
		return
	}
	if err := c.sendBatch(ctx, batch); err != nil && c.cfg.Logger != nil {
		c.cfg.Logger.Warn("telemetry flush failed", "error", err, "events", len(batch))
	}
}

// Close stops the background flusher and waits for it to drain. Safe to
// call multiple times.
func (c *Client) Close() {
	if c == nil {
		return
	}
	c.once.Do(func() {
		close(c.closedCh)
	})
	if c.cfg.Mode == ModeEnabled {
		// Give the flusher a moment to drain the final batch. Short
		// timeout so we never hang CLI shutdown.
		ctx, cancel := context.WithTimeout(context.Background(), defaultHTTPTimeout)
		defer cancel()
		c.Flush(ctx)
	}
}

func (c *Client) runFlusher() {
	ticker := time.NewTicker(c.cfg.FlushInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.closedCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), defaultHTTPTimeout)
			c.Flush(ctx)
			cancel()
		}
	}
}

func (c *Client) sendBatch(ctx context.Context, batch []Event) error {
	payload := struct {
		Events []Event `json:"events"`
	}{Events: batch}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "chainsaw-telemetry/"+c.cfg.ChainsawVersion)
	if c.cfg.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
	}
	resp, err := c.cfg.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 400 {
		return fmt.Errorf("ingest rejected: %s", resp.Status)
	}
	return nil
}

func (c *Client) writeDebug(evt Event) {
	enc := json.NewEncoder(c.debugSink)
	enc.SetIndent("", "  ")
	_, _ = c.debugSink.Write([]byte("[telemetry] "))
	_ = enc.Encode(evt)
}
