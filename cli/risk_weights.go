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
//       the simulate_id from a fresh `preview` run. The server persists
//       proposed_signal_weights to risk_weight_overrides (the rows the
//       engine reads at scan time) inside the simulate gate, then
//       returns what it read back; apply diffs that against the --set
//       values and fails if anything didn't land. Returns
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
// SignalWeights is the per-signal override map the server reads back
// out of storage. `apply` diffs its --set values against this to prove
// the write landed instead of trusting a 200.
type riskWeightsShowData struct {
	Overridden    bool               `json:"overridden"`
	Effective     map[string]float64 `json:"effective"`
	SignalWeights map[string]int     `json:"signalWeights,omitempty"`
	UpdatedAt     string             `json:"updatedAt,omitempty"`
	UpdatedBy     string             `json:"updatedBy,omitempty"`
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
	Use:     "risk-weights",
	GroupID: GrpPolicy,
	Short:   "Show, preview, and apply per-signal risk-weight overrides",
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
        --set vuln.cvss_high=70 \
        --set sc.publisher_changed=50

Signal ids must exist in the engine registry — list them with
'chainsaw risk-weights show' or GET /api/risk/signals. A few signals
that back instant-block enforcement (vuln.kev, sc.known_malicious,
qual.checksum_mismatch) are not tunable and are rejected.

Prints the simulate_id, the would-block / would-permit / flip counts,
and the first 10 sample flips. The simulate_id is required by 'apply'
and expires after 1 hour.`,
	RunE: runRiskWeightsPreview,
}

var riskWeightsApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Persist a previewed weight set (requires a fresh --simulate-id)",
	Long: `apply PUTs the same --set values you previewed, attached to your
preview's simulate_id:

    chainsaw risk-weights apply --simulate-id <id> --set vuln.cvss_high=70

The --set values must match the ones you previewed exactly — the server
re-derives the simulate inputs hash from them and returns CHW-4830 if
they drifted, if the preview is older than 1h, or if another operator
saved different weights in between. Re-run 'preview' and apply the new id.

apply prints the weights the server read BACK from storage, so the output
is proof the write landed rather than an echo of the request. Confirm
independently with 'chainsaw risk-weights show'.`,
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
	client, err := newV1Client(cmd)
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
	// GET /api/v1/intel/weights now reports the same per-signal weights
	// (both surfaces read the same rows). Fall back to it when the
	// richer endpoint is unreachable so `show` can still prove what
	// `apply` persisted — the round-trip check has to survive one
	// endpoint being down.
	if len(sig.Overrides) == 0 && len(cat.SignalWeights) > 0 {
		for id, w := range cat.SignalWeights {
			sig.Overrides = append(sig.Overrides, riskWeightsSignalOverride{SignalID: id, Weight: w})
		}
	}

	if useJSON(cmd) {
		return PrintJSONTo(cmd, map[string]any{
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
	client, err := newV1Client(cmd)
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
		return PrintJSONTo(cmd, resp)
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

// errRiskWeightsNotPersisted is returned when the server accepts the PUT
// but the weights it reads back don't match what we sent. Package-level
// so a test can pin it.
//
// This is the regression guard for P3. `apply` used to PUT its --set
// values to a handler that read proposed_signal_weights only to
// re-derive the simulate inputs hash and then wrote a row with no
// signal-weight field — the values were dropped on every run while the
// command printed "Weights applied." and exited 0. A 200 is therefore
// NOT evidence of a write. The only evidence is the server reading the
// values back out of storage, which is what we check below.
var errRiskWeightsNotPersisted = fmt.Errorf("server accepted the request but did not persist the weights")

// runRiskWeightsApply PUTs the previewed weight set and then verifies,
// against the server's read-back, that every --set value actually
// landed.
//
// Deliberately NOT implemented client-side by looping
// PUT /api/risk/overrides/{signal}: that is a non-atomic multi-request
// write (a partial failure strands the org on a weight set nobody
// previewed), and it performs the real write OUTSIDE the simulate_id
// guard, reducing that guard to decoration. The write is one request,
// inside the gate, server-side.
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
	client, err := newV1Client(cmd)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	ctx := context.Background()

	// Round-trip the current category weights unchanged: this flow tunes
	// per-signal weights only, and the simulate gate hashes the category
	// map too — sending anything else would fail the staleness check.
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
	// Failures below RETURN rather than os.Exit so the whole apply path
	// stays testable end-to-end. classifyCLIError already maps them to
	// ExitOpError(2), and the verify failure pins that code explicitly —
	// the documented exit contract is unchanged.
	raw, _, err := client.doUnwrap(ctx, http.MethodPut, "/api/v1/intel/weights", body)
	if err != nil {
		return err
	}
	var saved riskWeightsShowData
	if err := json.Unmarshal(raw, &saved); err != nil {
		return fmt.Errorf("decode apply response: %w", err)
	}
	if err := verifyRiskWeightsPersisted(signalWeights, saved.SignalWeights); err != nil {
		return &ExitCodeError{Code: ExitOpError, Err: err}
	}

	if useJSON(cmd) {
		return PrintJSONTo(cmd, saved)
	}
	fmt.Println("Weights applied. Server read back:")
	keys := make([]string, 0, len(signalWeights))
	for k := range signalWeights {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("  %-32s %4d\n", k, saved.SignalWeights[k])
	}
	fmt.Println("\nVerify independently with: chainsaw risk-weights show")
	return nil
}

// verifyRiskWeightsPersisted compares what we asked for against what the
// server says is now stored. Every requested signal must be present with
// the requested value; anything else means the write was partial or
// dropped, and the operator needs to know that instead of seeing
// "Weights applied."
func verifyRiskWeightsPersisted(want, got map[string]int) error {
	missing := make([]string, 0, len(want))
	for id, w := range want {
		have, ok := got[id]
		if !ok {
			missing = append(missing, fmt.Sprintf("%s (wanted %d, absent from server read-back)", id, w))
			continue
		}
		if have != w {
			missing = append(missing, fmt.Sprintf("%s (wanted %d, server has %d)", id, w, have))
		}
	}
	if len(missing) == 0 {
		return nil
	}
	sort.Strings(missing)
	return fmt.Errorf("%w:\n  %s\nThe request returned success but the values did not land. "+
		"Do NOT assume the weight set is live — check `chainsaw risk-weights show` and report this",
		errRiskWeightsNotPersisted, strings.Join(missing, "\n  "))
}
