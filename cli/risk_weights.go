package cli

// `chainsaw risk-weights` — operator-facing surface for tuning per-signal
// risk weights with a mandatory simulate-then-confirm gate (Pain 9 / D.16).
//
// Subcommands:
//
//   chainsaw risk-weights show
//       Print the current category-weight overrides (and per-signal
//       overrides) for the active org. Hits GET /api/v1/intel/weights
//       and GET /api/risk/overrides.
//
//   chainsaw risk-weights preview --set <signal>=<weight> [--set ...]
//       POST /api/v1/intel/weights/simulate with the proposed weights
//       and print the projected verdict-flip counts + first-N sample
//       flips. The returned simulate_id is required by `apply`.
//
//   chainsaw risk-weights apply --simulate-id <id>
//       PUT /api/v1/intel/weights with the same proposed weights plus
//       the simulate_id from a fresh `preview` run. Returns
//       CHW-4830 if the simulate is missing / stale / mismatched —
//       the same error code the server emits for any simulate-required
//       surface (org-delete missing is CHW-4831, expired is CHW-4928;
//       harden quorum is CHW-4910; the risk-weights gate sits in the
//       same simulate-then-confirm family).
//
// Exit codes:
//   0 success
//   2 stale or missing simulate, usage error, transport error
//
// We deliberately keep the JSON wire shape local — same rationale as
// internal/cli/intel.go: a server-side rename should break the CLI loud
// rather than silently empty fields at runtime.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
)

// ── Wire shapes ─────────────────────────────────────────────────────────────

// riskWeightsShowData mirrors the GET /api/v1/intel/weights `data`
// payload. Only the fields the CLI actually surfaces are typed; the
// raw envelope is still echoed under --json so an integrator can pick
// up new fields without us cutting a release.
type riskWeightsShowData struct {
	Overridden bool               `json:"overridden"`
	Effective  map[string]float64 `json:"effective"`
	UpdatedAt  string             `json:"updatedAt,omitempty"`
	UpdatedBy  string             `json:"updatedBy,omitempty"`
}

// riskWeightsSignalOverride is the shape returned by
// GET /api/risk/overrides (one entry per overridden signal).
type riskWeightsSignalOverride struct {
	SignalID      string  `json:"signalId"`
	Weight        int     `json:"weight"`
	DefaultWeight float64 `json:"defaultWeight"`
	UpdatedBy     string  `json:"updatedBy,omitempty"`
	UpdatedAt     string  `json:"updatedAt,omitempty"`
}

type riskWeightsSignalOverridesResp struct {
	Overrides []riskWeightsSignalOverride `json:"overrides"`
}

// riskWeightsSimulateReq is the body for POST /intel/weights/simulate
// and PUT /intel/weights (when the simulate gate is on).
type riskWeightsSimulateReq struct {
	Weights               map[string]float64 `json:"weights"`
	ProposedSignalWeights map[string]int     `json:"proposed_signal_weights,omitempty"`
	SimulateID            string             `json:"simulate_id,omitempty"`
}

// riskWeightsSimulateResp mirrors the server's
// v1WeightsSimulateResponse: a simulate_id, summary string, bucket
// counts (would-block / would-permit / flips), and the first-N
// sample flips. Samples is intentionally typed as []map so we don't
// crystallise a wire contract the server team can extend over time.
type riskWeightsSimulateResp struct {
	SimulateID string                   `json:"simulate_id"`
	Summary    string                   `json:"summary"`
	Buckets    map[string]int           `json:"buckets,omitempty"`
	Samples    []map[string]interface{} `json:"samples,omitempty"`
	Fallback   string                   `json:"fallback,omitempty"`
}

// ── Command wiring ──────────────────────────────────────────────────────────

var riskWeightsCmd = &cobra.Command{
	Use:   "risk-weights",
	Short: "Show, preview, and apply per-signal risk-weight overrides",
	Long: `risk-weights is the CLI front-end for tuning the v2 risk engine's
per-signal weights with a mandatory simulate-then-confirm gate. The
'preview' subcommand returns a flip-impact projection (would-block /
would-permit deltas plus sample flips) and a simulate_id; the 'apply'
subcommand requires a fresh simulate_id from a recent preview.

The gate exists to prevent finger-fumble reclassifications: a single
PUT with bad weights can flip thousands of packages from permit to
block. preview-then-apply forces the operator to eyeball the impact
before saving.`,
}

var (
	riskWeightsPreviewSet []string
	riskWeightsApplySet   []string
	riskWeightsSimulateID string
)

var riskWeightsShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Print current category + signal weights",
	RunE:  runRiskWeightsShow,
}

var riskWeightsPreviewCmd = &cobra.Command{
	Use:   "preview",
	Short: "Preview the verdict-flip impact of a draft weight set",
	Long: `Preview prints projected verdict flips for the supplied draft weights.
Use --set repeatedly to override individual signals:

    chainsaw risk-weights preview \
        --set isVulnerable=70 \
        --set publisherChanged=50

Prints the simulate_id, the would-block / would-permit / flip counts,
and the first 10 sample flips. The simulate_id is required by 'apply'
and expires after 1 hour.`,
	RunE: runRiskWeightsPreview,
}

var riskWeightsApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply a previously-previewed weight set",
	Long: `apply PUTs the same --set values you previewed, attaching the
simulate_id from your preview run. The server re-derives the inputs
hash from the request body and refuses the write (CHW-4830) if the
simulate_id is missing, stale (> 1 hour), or for a different draft.

Re-run preview if apply returns CHW-4830.`,
	RunE: runRiskWeightsApply,
}

func init() {
	riskWeightsPreviewCmd.Flags().StringSliceVar(&riskWeightsPreviewSet, "set", nil,
		"signal weight override in the form <signalId>=<int>; repeat for multiple")
	riskWeightsApplyCmd.Flags().StringSliceVar(&riskWeightsApplySet, "set", nil,
		"same --set values used during preview (must match exactly)")
	riskWeightsApplyCmd.Flags().StringVar(&riskWeightsSimulateID, "simulate-id", "",
		"simulate_id returned by a fresh `risk-weights preview` run")

	riskWeightsCmd.AddCommand(riskWeightsShowCmd)
	riskWeightsCmd.AddCommand(riskWeightsPreviewCmd)
	riskWeightsCmd.AddCommand(riskWeightsApplyCmd)
	rootCmd.AddCommand(riskWeightsCmd)
}

// parseSetFlags converts repeated --set signal=value pairs into a
// map[string]int. The server's ProposedSignalWeights field is typed
// int — weights are clamped to [-1000, 1000] server-side. We round-trip
// a float here so an operator can paste a decimal (`0.7`) and we'll
// scale up cleanly, but the canonical wire shape stays integral.
func parseSetFlags(pairs []string) (map[string]int, error) {
	out := make(map[string]int, len(pairs))
	for _, p := range pairs {
		eq := strings.Index(p, "=")
		if eq <= 0 || eq == len(p)-1 {
			return nil, fmt.Errorf("invalid --set %q: want signalId=value", p)
		}
		key := strings.TrimSpace(p[:eq])
		valStr := strings.TrimSpace(p[eq+1:])
		// Accept both integer and decimal forms. A decimal like 0.7 is
		// interpreted as a fractional weight relative to 100 (so 70).
		// Whole numbers pass through as-is.
		if f, err := strconv.ParseFloat(valStr, 64); err == nil {
			if f > -1 && f < 1 && f != 0 {
				out[key] = int(f * 100)
			} else {
				out[key] = int(f)
			}
		} else {
			return nil, fmt.Errorf("invalid --set value %q: %w", p, err)
		}
	}
	return out, nil
}

// effectiveCategoryWeights builds the `weights` payload the server
// expects on /intel/weights endpoints. For the per-signal CLI flow we
// don't actually mutate category weights — we round-trip whatever the
// server reports as currently effective so the simulate gate's inputs
// hash stays stable across show → preview → apply.
func effectiveCategoryWeights(ctx context.Context, c *v1Client) (map[string]float64, error) {
	raw, _, err := c.doUnwrap(ctx, http.MethodGet, "/api/v1/intel/weights", nil)
	if err != nil {
		return nil, err
	}
	var data riskWeightsShowData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, fmt.Errorf("decode weights: %w", err)
	}
	if data.Effective == nil {
		return map[string]float64{}, nil
	}
	return data.Effective, nil
}

// ── show ────────────────────────────────────────────────────────────────────

func runRiskWeightsShow(cmd *cobra.Command, _ []string) error {
	client, err := newV1Client()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	ctx := context.Background()

	rawCat, env, err := client.doUnwrap(ctx, http.MethodGet, "/api/v1/intel/weights", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	var cat riskWeightsShowData
	if err := json.Unmarshal(rawCat, &cat); err != nil {
		fmt.Fprintf(os.Stderr, "error: decode weights: %v\n", err)
		os.Exit(2)
	}

	// Per-signal overrides live behind /api/risk/overrides — not behind
	// the v1 envelope. Use the APIClient directly to keep the auth
	// header consistent with other surfaces.
	var sig riskWeightsSignalOverridesResp
	if err := client.api.do(http.MethodGet, "/api/risk/overrides", nil, &sig); err != nil {
		// Soft-fail: if /api/risk/overrides is unreachable we still want
		// to show the category-level view rather than abort.
		fmt.Fprintf(os.Stderr, "warning: signal overrides unavailable: %v\n", err)
	}

	if useJSON(cmd) {
		return PrintJSON(map[string]any{
			"apiVersion":      env.APIVersion,
			"engineVersion":   env.EngineVersion,
			"categoryWeights": cat,
			"signalOverrides": sig.Overrides,
		})
	}

	renderRiskWeightsShow(cat, sig.Overrides)
	return nil
}

func renderRiskWeightsShow(cat riskWeightsShowData, sigs []riskWeightsSignalOverride) {
	fmt.Println("Category weights")
	keys := make([]string, 0, len(cat.Effective))
	for k := range cat.Effective {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-14s %.4f\n", k, cat.Effective[k])
	}
	if cat.Overridden {
		fmt.Printf("  (overridden")
		if cat.UpdatedBy != "" {
			fmt.Printf(" by %s", cat.UpdatedBy)
		}
		if cat.UpdatedAt != "" {
			fmt.Printf(" at %s", cat.UpdatedAt)
		}
		fmt.Println(")")
	} else {
		fmt.Println("  (defaults — no per-category override)")
	}
	fmt.Println()

	fmt.Printf("Per-signal overrides (%d)\n", len(sigs))
	if len(sigs) == 0 {
		fmt.Println("  (none — all signals at engine defaults)")
		return
	}
	sort.Slice(sigs, func(i, j int) bool { return sigs[i].SignalID < sigs[j].SignalID })
	for _, s := range sigs {
		fmt.Printf("  %-32s %4d (default %.0f)", s.SignalID, s.Weight, s.DefaultWeight)
		if s.UpdatedBy != "" {
			fmt.Printf(" — by %s", s.UpdatedBy)
		}
		fmt.Println()
	}
}

// ── preview ─────────────────────────────────────────────────────────────────

func runRiskWeightsPreview(cmd *cobra.Command, _ []string) error {
	if len(riskWeightsPreviewSet) == 0 {
		return fmt.Errorf("at least one --set <signalId>=<value> is required")
	}
	signalWeights, err := parseSetFlags(riskWeightsPreviewSet)
	if err != nil {
		return err
	}
	client, err := newV1Client()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	ctx := context.Background()

	cat, err := effectiveCategoryWeights(ctx, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	body := riskWeightsSimulateReq{
		Weights:               cat,
		ProposedSignalWeights: signalWeights,
	}
	// /api/v1/intel/weights/simulate does NOT use the v1 envelope; the
	// server writes the simulate response directly. Use APIClient.do.
	var resp riskWeightsSimulateResp
	if err := client.api.do(http.MethodPost, "/api/v1/intel/weights/simulate", body, &resp); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if useJSON(cmd) {
		return PrintJSON(resp)
	}
	renderRiskWeightsPreview(resp, signalWeights)
	return nil
}

func renderRiskWeightsPreview(r riskWeightsSimulateResp, draft map[string]int) {
	fmt.Println("Draft signal weights")
	keys := make([]string, 0, len(draft))
	for k := range draft {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-32s %4d\n", k, draft[k])
	}
	fmt.Println()

	fmt.Printf("Projected impact: %s\n", r.Summary)
	if r.Fallback != "" {
		fmt.Printf("  (fallback: %s — projection sampled rather than full replay)\n", r.Fallback)
	}
	if len(r.Buckets) > 0 {
		bkeys := make([]string, 0, len(r.Buckets))
		for k := range r.Buckets {
			bkeys = append(bkeys, k)
		}
		sort.Strings(bkeys)
		for _, k := range bkeys {
			fmt.Printf("  %-32s %d\n", k, r.Buckets[k])
		}
	}

	if len(r.Samples) > 0 {
		n := len(r.Samples)
		if n > 10 {
			n = 10
		}
		fmt.Printf("\nSample flips (first %d of %d):\n", n, len(r.Samples))
		for _, s := range r.Samples[:n] {
			pkg, _ := s["package"].(string)
			oldV, _ := s["old_verdict"].(string)
			newV, _ := s["new_verdict"].(string)
			delta := s["score_delta"]
			fmt.Printf("  %-40s %s → %s (Δ=%v)\n", pkg, oldV, newV, delta)
		}
	}

	fmt.Printf("\nsimulate_id: %s\n", r.SimulateID)
	fmt.Println("Apply with:")
	fmt.Printf("  chainsaw risk-weights apply --simulate-id %s", r.SimulateID)
	for _, k := range keys {
		fmt.Printf(" --set %s=%d", k, draft[k])
	}
	fmt.Println()
}

// ── apply ───────────────────────────────────────────────────────────────────

func runRiskWeightsApply(cmd *cobra.Command, _ []string) error {
	if riskWeightsSimulateID == "" {
		return fmt.Errorf("--simulate-id is required (run `chainsaw risk-weights preview` first)")
	}
	if len(riskWeightsApplySet) == 0 {
		return fmt.Errorf("at least one --set <signalId>=<value> is required (must match preview)")
	}
	signalWeights, err := parseSetFlags(riskWeightsApplySet)
	if err != nil {
		return err
	}
	client, err := newV1Client()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	ctx := context.Background()

	cat, err := effectiveCategoryWeights(ctx, client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	body := riskWeightsSimulateReq{
		Weights:               cat,
		ProposedSignalWeights: signalWeights,
		SimulateID:            riskWeightsSimulateID,
	}
	// PUT /api/v1/intel/weights returns the v1 envelope. doUnwrap will
	// classify a 409 CHW-4830 into the structured apiError so we can
	// surface the actionable message verbatim.
	raw, _, err := client.doUnwrap(ctx, http.MethodPut, "/api/v1/intel/weights", body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if useJSON(cmd) {
		// Pass-through the data block — same pattern as other v1 commands.
		_, _ = os.Stdout.Write(raw)
		fmt.Println()
		return nil
	}
	fmt.Println("Weights applied.")
	return nil
}
