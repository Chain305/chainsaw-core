package cli

// features.go — `chainsaw features` prints the capability picture for this
// install: (a) the LOCAL edition/build capabilities (community vs enterprise,
// from the -ldflags Edition tag) and (b) the SERVER-side plan entitlements the
// caller's org currently has, read from GET /api/billing/current.
//
// The server list is DERIVED from the feature keys the server returns (the raw
// pricing_plans.features JSON), never a hard-coded constant — so it can't drift
// as plans gain or lose flags. knownFeatureLabels only supplies nicer human
// copy for the keys we recognise; unknown keys still render by their raw key.
//
// Degrades cleanly: with no server URL or no token it prints the local half and
// notes the server side is unavailable rather than erroring (mirrors status.go).

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/spf13/cobra"
)

// featuresUpgradeURL is the plan-upgrade destination surfaced to a user who
// wants a gated capability. Kept as a literal here because core/cli is a
// separate module from internal/errcodes (which owns the server-side
// errcodes.UpgradeURL()); both must point at the same pricing page.
const featuresUpgradeURL = "https://chain305.com/pricing"

// knownFeatureLabels maps server feature keys to human-friendly copy. It is a
// PRESENTATION aid only — the authoritative list of active/gated features is
// always the set of keys the server returns, so a new plan flag shows up here
// automatically (by its raw key) even before it gets a label.
var knownFeatureLabels = map[string]string{
	"billy":                 "Billy AI assistant",
	"onprem":                "On-prem / self-host deployment",
	"sso":                   "SAML / OIDC single sign-on",
	"integrations_external": "External integrations (SIEM, etc.)",
}

func featureLabel(key string) string {
	if l, ok := knownFeatureLabels[key]; ok {
		return l
	}
	return key
}

// featureEntry is one capability row, active or gated.
type featureEntry struct {
	Key    string `json:"key"`
	Label  string `json:"label"`
	Active bool   `json:"active"`
}

// serverFeatures is the server-entitlements half of the report. Configured is
// false when no server URL / token is set; Error carries a transport or auth
// failure without turning the whole command into a hard error.
type serverFeatures struct {
	Configured bool           `json:"configured"`
	Reachable  bool           `json:"reachable"`
	Error      string         `json:"error,omitempty"`
	PlanID     string         `json:"plan_id,omitempty"`
	PlanName   string         `json:"plan_name,omitempty"`
	Features   []featureEntry `json:"features"`
}

// featuresReport is the full `chainsaw features --json` document.
type featuresReport struct {
	Edition    string         `json:"edition"`
	UpgradeURL string         `json:"upgrade_url"`
	Local      []featureEntry `json:"local"`
	Server     serverFeatures `json:"server"`
}

var featuresCmd = &cobra.Command{
	Use:          "features",
	Short:        "Show local edition capabilities and server plan entitlements",
	GroupID:      GrpDebug,
	SilenceUsage: true,
	RunE:         runFeatures,
}

func init() {
	featuresCmd.Flags().Bool("json", false, "Output as JSON")
	rootCmd.AddCommand(featuresCmd)
}

// localCapabilities enumerates what this binary's build edition unlocks
// locally. Derived from the Edition build tag — not from any plan gate.
func localCapabilities() []featureEntry {
	enterprise := Edition == "enterprise"
	return []featureEntry{
		{Key: "offline_guard", Label: "Offline install-time guard", Active: true},
		{Key: "enterprise_build", Label: "Enterprise build extensions", Active: enterprise},
	}
}

// loadServerFeatures reads the caller's current plan entitlements. It never
// returns an error — failures are recorded on the returned serverFeatures so
// the command degrades to the local-only view.
func loadServerFeatures() serverFeatures {
	sf := serverFeatures{Features: []featureEntry{}}
	if cfgServerURL() == "" {
		sf.Error = "server URL not configured — run 'chainsaw setup' or 'chainsaw auth login'"
		return sf
	}
	sf.Configured = true
	if cfgToken() == "" {
		sf.Error = "no token configured — run 'chainsaw auth login'"
		return sf
	}

	var resp struct {
		Plan struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			Features string `json:"features"` // raw JSON object of bool flags
		} `json:"plan"`
		Status string `json:"status"`
	}
	if err := newClient().Get("/api/billing/current", &resp); err != nil {
		sf.Error = err.Error()
		return sf
	}
	sf.Reachable = true
	sf.PlanID = resp.Plan.ID
	sf.PlanName = resp.Plan.Name

	sf.Features = parsePlanFeatures(resp.Plan.Features)
	return sf
}

// parsePlanFeatures turns the raw pricing_plans.features JSON string into a
// sorted, labelled list. Non-object / empty input yields an empty list. Values
// are treated as booleans (the server-side ValidatePlanFeaturesJSON invariant);
// a non-bool value is treated as gated rather than crashing the CLI.
func parsePlanFeatures(raw string) []featureEntry {
	out := []featureEntry{}
	if raw == "" {
		return out
	}
	var flags map[string]any
	if err := json.Unmarshal([]byte(raw), &flags); err != nil {
		return out
	}
	keys := make([]string, 0, len(flags))
	for k := range flags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		active, _ := flags[k].(bool)
		out = append(out, featureEntry{Key: k, Label: featureLabel(k), Active: active})
	}
	return out
}

func runFeatures(cmd *cobra.Command, _ []string) error {
	report := featuresReport{
		Edition:    Edition,
		UpgradeURL: featuresUpgradeURL,
		Local:      localCapabilities(),
		Server:     loadServerFeatures(),
	}

	if useJSON(cmd) {
		return PrintJSONTo(cmd, report)
	}

	out := cmd.OutOrStdout()
	// The active/inactive marker is the ONLY thing distinguishing two
	// capability rows here — the labels are otherwise identical in shape. When
	// both glyphs rendered as the same replacement box on a legacy Windows
	// console, `chainsaw features` became unreadable: --json said one
	// capability was on and one was off, and the human output said nothing at
	// all. Hence glyphs() rather than literals.
	g := glyphs()
	mark := func(active bool) string {
		if active {
			return g.ok
		}
		return g.fail
	}

	fmt.Fprintln(out, "=== Chainsaw Features ===")
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Edition: %s\n", report.Edition)
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Local capabilities")
	for _, e := range report.Local {
		fmt.Fprintf(out, "  %s  %s\n", mark(e.Active), e.Label)
	}
	fmt.Fprintln(out)

	fmt.Fprintln(out, "Server entitlements")
	switch {
	case !report.Server.Configured:
		fmt.Fprintf(out, "  (unavailable) %s\n", report.Server.Error)
	case report.Server.Error != "":
		fmt.Fprintf(out, "  (unavailable) %s\n", report.Server.Error)
	default:
		if report.Server.PlanName != "" {
			fmt.Fprintf(out, "  Plan: %s\n", report.Server.PlanName)
		}
		if len(report.Server.Features) == 0 {
			fmt.Fprintln(out, "  (no plan features reported)")
		}
		for _, e := range report.Server.Features {
			fmt.Fprintf(out, "  %s  %s\n", mark(e.Active), e.Label)
		}
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "Upgrade: %s\n", report.UpgradeURL)
	return nil
}
