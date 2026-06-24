package cli

// `chainsaw intel` is the operator-facing surface over the public v1 HTTP
// API at /api/v1/intel/*. Every subcommand reuses the shared APIClient
// (see client.go) for transport and auth — all the v1-specific handling
// (envelope unwrap, data shape types) lives here, deliberately decoupled
// from internal/risk so the CLI keeps a lean import surface.
//
// Subcommands:
//
//   chainsaw intel package <ecosystem> <name> <version>
//   chainsaw intel scan    [--lockfile <path>]
//   chainsaw intel signals
//   chainsaw intel health
//
// Exit codes (also documented in each command's Long help):
//   0  success / all-Allow
//   1  at least one Warn/UpgradeAvailable on a tree scan
//   2  at least one Quarantine or Replace on a tree scan, or a usage/HTTP error
//
// The v1 API is feature-flagged on the server side; when disabled the
// server returns 404 CHW-IntelFeatureDisabled which we surface verbatim.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// ── Local shape definitions mirroring the v1 wire contract ──────────────────
//
// We intentionally avoid importing github.com/chain305/chainsaw-core/risk
// from the CLI: (a) the risk package is large and pulls in graph/registry
// deps the CLI shouldn't carry, (b) keeping the JSON shapes local guards
// against silent wire-contract drift (a server-side type rename must update
// both packages, which shows up as a compile break here rather than a
// mystery empty field at runtime).

// v1Envelope mirrors server.v1Envelope. Kept local so a server-side rename
// breaks the CLI loudly at parse time rather than silently.
type v1Envelope struct {
	APIVersion    string          `json:"apiVersion"`
	EngineVersion string          `json:"engineVersion"`
	Data          json.RawMessage `json:"data"`
	Warnings      []string        `json:"warnings"`
	Meta          v1Meta          `json:"meta"`
}

type v1Meta struct {
	RequestID      string `json:"requestId"`
	ProcessedCount int    `json:"processedCount"`
}

// v1IntelKey — the (eco, name, version) identifier.
type v1IntelKey struct {
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Version   string `json:"version"`
}

// v1WireKey matches the graph / tree-node key shape used in evaluate output.
type v1WireKey struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// v1FiredSignal is a single registered signal that fired on a package.
type v1FiredSignal struct {
	ID       string         `json:"id"`
	Category string         `json:"category"`
	Title    string         `json:"title"`
	Severity string         `json:"severity"`
	Weight   float64        `json:"weight"`
	Detail   string         `json:"detail,omitempty"`
	Evidence map[string]any `json:"evidence,omitempty"`
	Compound bool           `json:"compound,omitempty"`
}

type v1CategoryScore struct {
	Score        int             `json:"score"`
	Grade        string          `json:"grade"`
	FiredSignals []v1FiredSignal `json:"firedSignals,omitempty"`
}

type v1Score struct {
	Overall    int                        `json:"overall"`
	Categories map[string]v1CategoryScore `json:"categories"`
}

type v1Resolution struct {
	Verdict         string       `json:"verdict"`
	Summary         string       `json:"summary,omitempty"`
	SafeVersion     string       `json:"safeVersion,omitempty"`
	PatchAdvisory   string       `json:"patchAdvisory,omitempty"`
	Alternative     string       `json:"alternative,omitempty"`
	TransitiveBlame []v1IntelKey `json:"transitiveBlame,omitempty"`
	Rationale       []string     `json:"rationale,omitempty"`
}

// v1Evaluation mirrors risk.Evaluation. Same field names so json tags line up.
type v1Evaluation struct {
	Key           v1IntelKey   `json:"key"`
	DirectScore   v1Score      `json:"directScore"`
	RolledUp      v1Score      `json:"rolledUp"`
	Verdict       string       `json:"verdict"`
	Resolution    v1Resolution `json:"resolution"`
	EvaluatedAt   time.Time    `json:"evaluatedAt"`
	EngineVersion string       `json:"engineVersion"`
}

// v1Report is the subset of intelligence.Report we rely on — the rest is
// round-tripped as RawMessage so --json still prints the full server shape.
type v1Report struct {
	Risk *v1Evaluation `json:"Risk,omitempty"`
}

// v1PackageData is the shape of `data` in GET /packages/{eco}/{name}/{ver}.
// `report` is kept as raw JSON so --json pass-through stays lossless, while
// `risk` is parsed for the text renderer.
type v1PackageData struct {
	Report json.RawMessage `json:"report"`
	Risk   *v1Evaluation   `json:"risk"`
}

// v1TreeNode + v1TreeData mirror the tree evaluate response.
type v1TreeNode struct {
	Key  v1WireKey     `json:"key"`
	Eval *v1Evaluation `json:"eval"`
}

type v1TreeSummary struct {
	TotalNodes              int            `json:"TotalNodes"`
	DirectCount             int            `json:"DirectCount"`
	TransitiveCount         int            `json:"TransitiveCount"`
	ByVerdict               map[string]int `json:"ByVerdict"`
	MinOverall              int            `json:"MinOverall"`
	MaxTransitiveBlameChain int            `json:"MaxTransitiveBlameChain"`
}

type v1TreeData struct {
	Nodes   []v1TreeNode  `json:"nodes"`
	Summary v1TreeSummary `json:"summary"`
}

type v1SignalSummary struct {
	ID          string  `json:"id"`
	Category    string  `json:"category"`
	Severity    string  `json:"severity"`
	Weight      float64 `json:"weight"`
	Title       string  `json:"title"`
	Description string  `json:"description,omitempty"`
}

type v1HealthData struct {
	EngineVersion string   `json:"engineVersion"`
	SignalCount   int      `json:"signalCount"`
	Categories    []string `json:"categories"`
}

// ── v1Client: thin wrapper over APIClient for v1 envelope unwrap ────────────

// v1Client wraps the shared APIClient and unwraps the envelope returned
// by /api/v1/intel/* endpoints. It is NOT a separate HTTP client — it
// reuses the same authenticated transport so bearer-token, user-agent,
// dry-run, and error-classification behaviour remain identical across
// every CLI command. The *only* responsibility added here is pulling
// `data` out of the envelope and surfacing server error codes cleanly.
type v1Client struct {
	api *APIClient
}

// newV1Client returns a v1Client using the process-level auth + server
// config. Returns an actionable error (same messaging as other commands)
// when server URL or token is missing so callers can exit 2 with a clear
// message instead of a vague "connection refused" later.
func newV1Client() (*v1Client, error) {
	c := newClient()
	if c.baseURL == "" {
		return nil, errServerNotConfigured(nil)
	}
	if cfgToken() == "" {
		return nil, fmt.Errorf("not authenticated — run 'chainsaw auth login' first")
	}
	return &v1Client{api: c}, nil
}

// doUnwrap runs an HTTP call via APIClient.do-like transport and returns
// the already-unwrapped `data` bytes so each typed method can json.Unmarshal
// into its own shape. We can't reuse APIClient.do directly because that
// decodes straight into the caller's out — we need the envelope layer.
func (c *v1Client) doUnwrap(ctx context.Context, method, path string, body any) (json.RawMessage, *v1Envelope, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, nil, fmt.Errorf("encode request: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.api.baseURL+path, bodyReader)
	if err != nil {
		return nil, nil, fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if c.api.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.api.token)
	}
	for k, v := range c.api.extraHeaders {
		req.Header.Set(k, v)
	}

	resp, err := c.api.http.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("request to %s failed: %w", c.api.baseURL+path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		// Server error envelope is separate from v1Envelope — use the
		// same parse as APIClient.do so messaging stays consistent.
		var apiErr apiError
		_ = json.Unmarshal(respBody, &apiErr)
		if apiErr.Code == "" {
			apiErr.Code = fmt.Sprintf("HTTP %d", resp.StatusCode)
			apiErr.Message = strings.TrimSpace(string(respBody))
		}
		return nil, nil, &apiErr
	}

	var env v1Envelope
	if err := json.Unmarshal(respBody, &env); err != nil {
		return nil, nil, fmt.Errorf("decode v1 envelope: %w", err)
	}
	if len(env.Data) == 0 {
		return nil, &env, fmt.Errorf("v1 response missing `data` field")
	}
	return env.Data, &env, nil
}

// GetPackage fetches /api/v1/intel/packages/{eco}/{name}/{version}.
func (c *v1Client) GetPackage(ctx context.Context, key v1IntelKey) (*v1PackageData, *v1Envelope, error) {
	path := fmt.Sprintf("/api/v1/intel/packages/%s/%s/%s", key.Ecosystem, key.Package, key.Version)
	raw, env, err := c.doUnwrap(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, env, err
	}
	var data v1PackageData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, env, fmt.Errorf("decode package data: %w", err)
	}
	return &data, env, nil
}

// Evaluate runs POST /api/v1/intel/evaluate with a base64 lockfile body.
func (c *v1Client) Evaluate(ctx context.Context, lockfileType, lockfileB64 string) (*v1TreeData, *v1Envelope, error) {
	body := map[string]any{
		"lockfileType": lockfileType,
		"lockfile":     lockfileB64,
	}
	raw, env, err := c.doUnwrap(ctx, http.MethodPost, "/api/v1/intel/evaluate", body)
	if err != nil {
		return nil, env, err
	}
	var data v1TreeData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, env, fmt.Errorf("decode evaluate data: %w", err)
	}
	return &data, env, nil
}

// Signals fetches GET /api/v1/intel/signals.
func (c *v1Client) Signals(ctx context.Context) ([]v1SignalSummary, *v1Envelope, error) {
	raw, env, err := c.doUnwrap(ctx, http.MethodGet, "/api/v1/intel/signals", nil)
	if err != nil {
		return nil, env, err
	}
	var out []v1SignalSummary
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, env, fmt.Errorf("decode signals: %w", err)
	}
	return out, env, nil
}

// Health fetches GET /api/v1/intel/health.
func (c *v1Client) Health(ctx context.Context) (*v1HealthData, *v1Envelope, error) {
	raw, env, err := c.doUnwrap(ctx, http.MethodGet, "/api/v1/intel/health", nil)
	if err != nil {
		return nil, env, err
	}
	var out v1HealthData
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, env, fmt.Errorf("decode health: %w", err)
	}
	return &out, env, nil
}

// ── Command wiring ──────────────────────────────────────────────────────────

var intelCmd = &cobra.Command{
	Use:   "intel",
	Short: "Query the v1 risk-intelligence API (package, scan, signals, health)",
	Long: `intel surfaces the v1 public risk-intelligence API (/api/v1/intel/*):
single-package lookups, full tree evaluation from a lockfile, the signal
catalogue, and a quick engine health check. All subcommands honour the
persistent --json flag for machine-readable output.`,
}

func init() {
	rootCmd.AddCommand(intelCmd)
}

// ── Shared render helpers ───────────────────────────────────────────────────

// categoryOrder is the display order used by `intel package` and the
// per-node expansion in `intel scan`. Matches risk.AllCategories().
var categoryOrder = []string{
	"vulnerability", "supply_chain", "maintenance", "license", "quality",
}

// categoryLabel maps the server-side category string onto a padded text
// label for the aligned breakdown block. Keep widths in sync with the
// longest label ("Attack signals" = 14 chars; was "Supply Chain" /
// "Vulnerability" = 13 chars before the Phase-6 rename).
var categoryLabel = map[string]string{
	"vulnerability": "Vulnerability ",
	"supply_chain":  "Attack signals",
	"maintenance":   "Maintenance   ",
	"license":       "License       ",
	"quality":       "Quality       ",
}

// verdictDisplay upper-cases the wire verdict for the human renderer.
func verdictDisplay(v string) string {
	switch v {
	case "allow":
		return "ALLOW"
	case "warn":
		return "WARN"
	case "upgrade_available":
		return "UPGRADE"
	case "replace":
		return "REPLACE"
	case "quarantine":
		return "QUARANTINE"
	default:
		return strings.ToUpper(v)
	}
}

// renderEvaluation prints a single Evaluation to stdout in the human
// text form documented in chainsaw intel package --help.
func renderEvaluation(w io.Writer, ev *v1Evaluation) {
	if ev == nil {
		fmt.Fprintln(w, "No evaluation available for this package.")
		return
	}
	fmt.Fprintf(w, "%s %s (%s)\n", ev.Key.Package, ev.Key.Version, ev.Key.Ecosystem)
	fmt.Fprintf(w, "Verdict: %-8s Overall: %d (%s)\n",
		verdictDisplay(ev.Verdict), ev.RolledUp.Overall, gradeFor(ev.RolledUp.Overall))
	if ev.EngineVersion != "" {
		fmt.Fprintf(w, "Engine:  v%s\n", ev.EngineVersion)
	}
	fmt.Fprintln(w)
	for _, cat := range categoryOrder {
		cs, ok := ev.RolledUp.Categories[cat]
		if !ok {
			continue
		}
		fmt.Fprintf(w, "%s %3d %s   (%d finding%s)\n",
			categoryLabel[cat], cs.Score, cs.Grade, len(cs.FiredSignals),
			plural(len(cs.FiredSignals)))
	}

	// Resolution block — only emit when the verdict isn't a clean Allow.
	if ev.Verdict != "" && ev.Verdict != "allow" {
		fmt.Fprintln(w)
		if ev.Resolution.Summary != "" {
			fmt.Fprintf(w, "Summary:   %s\n", ev.Resolution.Summary)
		}
		if ev.Resolution.SafeVersion != "" {
			fmt.Fprintf(w, "SafeVersion: %s\n", ev.Resolution.SafeVersion)
		}
		if ev.Resolution.Alternative != "" {
			fmt.Fprintf(w, "Alternative: %s\n", ev.Resolution.Alternative)
		}
		if len(ev.Resolution.TransitiveBlame) > 0 {
			parts := make([]string, 0, len(ev.Resolution.TransitiveBlame))
			for _, b := range ev.Resolution.TransitiveBlame {
				parts = append(parts, fmt.Sprintf("%s@%s", b.Package, b.Version))
			}
			fmt.Fprintf(w, "Dragged by: %s\n", strings.Join(parts, ", "))
		}
		if len(ev.Resolution.Rationale) > 0 {
			fmt.Fprintf(w, "Rationale:\n")
			// Rationale is a list of signal IDs; surface up to the top 3.
			n := len(ev.Resolution.Rationale)
			if n > 3 {
				n = 3
			}
			for _, id := range ev.Resolution.Rationale[:n] {
				fmt.Fprintf(w, "  - %s\n", id)
			}
		}
	}
}

// gradeFor mirrors risk.gradeForScore(). Duplicated here rather than
// imported — see the top-of-file note on decoupling from internal/risk.
func gradeFor(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
