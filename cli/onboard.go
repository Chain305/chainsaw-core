package cli

// `chainsaw onboard` is the CLI twin of the MCP chainsaw_onboard tool.
// It records the user's persona (one of the canonical IDs: appsec,
// devsecops, enterprise_it) so future chainsaw_introduce calls — over
// CLI or MCP — return persona-tailored recommended-paths instead of
// the unsure-user nudge.
//
// Three usage modes:
//
//   chainsaw onboard --persona appsec      (set persona; idempotent)
//   chainsaw onboard --skip                (silence the nudge; no persona stored)
//   chainsaw onboard                       (read current state, no change)
//
// Always non-interactive — pair it with `chainsaw setup` for the human
// flow, or call it directly from scripts / agents that already know the
// persona they want. JSON output (--json) mirrors the chainsaw_onboard
// MCP tool's response so an agent that sees one shape sees the other.

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/agenticux"
)

// onboardResult mirrors the chainsaw_onboard MCP tool's response shape
// (see internal/server/server_mcp_onboarding.go onboardResult struct).
// Keeping the field names in lockstep means an agent that already knows
// the MCP response shape can parse `chainsaw onboard --json` output
// without a per-surface adapter.
type onboardCLIResult struct {
	Persona             string          `json:"persona,omitempty"`
	OnboardingSkippedAt string          `json:"onboarding_skipped_at,omitempty"`
	Recorded            map[string]bool `json:"recorded"`
	AvailablePersonas   []personaOpt    `json:"available_personas"`
}

type personaOpt struct {
	Name        string `json:"name"`
	Label       string `json:"label"`
	Description string `json:"description"`
}

// newOnboardCmd builds a fresh onboard command. Exposed as a factory
// (rather than a package-level var) so tests can drive the command
// without its rootCmd parentage and the test runner's os.Args getting
// in the way.
func newOnboardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "onboard",
		Short: "Record your persona to tailor onboarding (twin of the MCP chainsaw_onboard tool)",
		Long: `Record the user's persona so future chainsaw introduces (CLI or MCP)
return tailored guidance. The persona enum matches the dashboard's
onboarding flow:

  appsec         Platform & Application Security  (CVE triage, SBOM insights)
  devsecops     DevSecOps & Compliance            (policy gates, CI/CD templates)
  enterprise_it Enterprise IT & Shared Services   (SSO, SCIM, SIEM webhooks)

Pass --skip (with or without --persona) to silence the nudge in
chainsaw_introduce. With no flags, prints the current persona state
without changing it.

Persona is UX-only — it never gates permissions.`,
		RunE: runOnboard,
	}
	cmd.Flags().String("persona", "", "Persona ID (appsec, devsecops, enterprise_it)")
	cmd.Flags().Bool("skip", false, "Silence the persona-pick nudge in future introduces")
	cmd.Flags().Bool("json", false, "Output as JSON (matches MCP chainsaw_onboard response shape)")
	return cmd
}

// newOnboardingCmd builds the `chainsaw onboarding` parent command and
// its `state` subcommand. The parent prints its own --help when invoked
// with no subcommand; `state` is a thin alias around the read-only
// behaviour of `chainsaw onboard` (no flags) so agents using the MCP
// `chainsaw_onboarding_state` tool shape have a 1:1 CLI equivalent.
//
// The original `chainsaw onboard` command stays as-is — this is purely
// an additive alias surface.
func newOnboardingCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "onboarding",
		Short: "Inspect onboarding state (alias surface for chainsaw_onboarding_state)",
		Long: `Parent command for onboarding-state inspection. Mirrors the MCP
chainsaw_onboarding_state tool shape so agents that know the MCP
surface find the equivalent CLI subcommand under the same name.

Use ` + "`chainsaw onboarding state`" + ` to print the current persona
and onboarding_skipped_at timestamp. The original ` + "`chainsaw onboard`" + `
command is unchanged; this is an additive alias.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	stateCmd := &cobra.Command{
		Use:   "state",
		Short: "Print current onboarding state (persona + skipped_at)",
		Long: `Print the current onboarding state — equivalent to running
` + "`chainsaw onboard`" + ` with no flags. Output mirrors the MCP
chainsaw_onboarding_state response shape.

Pass --json for the machine-readable form (matches the MCP tool's
JSON shape exactly).`,
		RunE: runOnboardingState,
	}
	stateCmd.Flags().Bool("json", false, "Output as JSON (matches MCP chainsaw_onboarding_state response shape)")
	cmd.AddCommand(stateCmd)
	return cmd
}

func init() {
	rootCmd.AddCommand(newOnboardCmd())
	rootCmd.AddCommand(newOnboardingCmd())
}

// runOnboardingState is the read-only handler behind `chainsaw
// onboarding state`. It deliberately reuses printOnboardState so the
// output (text + JSON) is byte-identical to `chainsaw onboard` with
// no flags — the whole point of the alias is shape compatibility.
func runOnboardingState(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	return printOnboardState(cmd, client, cmd.OutOrStdout())
}

func runOnboard(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	personaFlag, _ := cmd.Flags().GetString("persona")
	persona := strings.ToLower(strings.TrimSpace(personaFlag))
	skip, _ := cmd.Flags().GetBool("skip")

	// Validate persona locally so a typo doesn't waste a round trip.
	// Mirrors normalizePersona on the server but keeps the error
	// actionable on the client side.
	if persona != "" {
		switch persona {
		case agenticux.PersonaAppSec, agenticux.PersonaDevSecOps, agenticux.PersonaEnterpriseIT:
			// ok
		default:
			return fmt.Errorf("unknown persona %q (want appsec, devsecops, or enterprise_it)", personaFlag)
		}
	}

	out := cmd.OutOrStdout()

	// No flags: read-only — fetch /api/users/me and report the current
	// persona state. Mirrors `chainsaw_onboard` MCP behaviour: calling
	// with no args reads the state without changing it.
	if persona == "" && !skip {
		return printOnboardState(cmd, client, out)
	}

	body := map[string]any{
		"skipped": skip,
	}
	if persona != "" {
		body["persona"] = persona
	}
	var resp map[string]any
	if err := client.Post("/api/users/me/persona", body, &resp); err != nil {
		return err
	}

	// Re-read so the response reflects the post-update state — handler
	// returns just {ok:true} otherwise.
	return printOnboardState(cmd, client, out)
}

// printOnboardState fetches /api/users/me and renders the current
// persona / skip state. Shared by the read-only and write-then-read
// paths so the output shape is identical.
func printOnboardState(cmd *cobra.Command, client *APIClient, out interface {
	Write(p []byte) (n int, err error)
}) error {
	var me struct {
		Persona             string  `json:"persona,omitempty"`
		PersonaInferred     bool    `json:"persona_inferred,omitempty"`
		OnboardingSkippedAt *string `json:"onboarding_skipped_at,omitempty"`
	}
	if err := client.Get("/api/users/me", &me); err != nil {
		return err
	}

	result := onboardCLIResult{
		Persona:           me.Persona,
		Recorded:          map[string]bool{"persona": me.Persona != "", "skip": me.OnboardingSkippedAt != nil},
		AvailablePersonas: availablePersonasForCLI(),
	}
	if me.OnboardingSkippedAt != nil {
		result.OnboardingSkippedAt = *me.OnboardingSkippedAt
	}

	if useJSON(cmd) {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	switch {
	case result.Persona != "":
		fmt.Fprintf(out, "Persona: %s\n", result.Persona)
	case result.OnboardingSkippedAt != "":
		fmt.Fprintf(out, "Persona: (skipped — nudge silenced)\n")
	default:
		fmt.Fprintln(out, "Persona: (not set)")
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Pick one:")
		for _, p := range result.AvailablePersonas {
			fmt.Fprintf(out, "  %-14s %s\n", p.Name, p.Label)
		}
		fmt.Fprintln(out, "")
		fmt.Fprintln(out, "Set with: chainsaw onboard --persona <id>")
		fmt.Fprintln(out, "Or skip:  chainsaw onboard --skip")
	}
	return nil
}

func availablePersonasForCLI() []personaOpt {
	return []personaOpt{
		{Name: agenticux.PersonaAppSec, Label: "Platform & Application Security", Description: "CVE triage, SBOM insights, package risk"},
		{Name: agenticux.PersonaDevSecOps, Label: "DevSecOps & Compliance", Description: "Policy gates, audit exports, CI/CD templates"},
		{Name: agenticux.PersonaEnterpriseIT, Label: "Enterprise IT & Shared Services", Description: "SSO, SCIM, SIEM webhooks, tenant-wide controls"},
	}
}
