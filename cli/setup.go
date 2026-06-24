package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/agenticux"
)

// Setup's authentication step no longer prompts for a password. Under
// Turnstile, password login from a CLI can't succeed — so the wizard
// now either drives the browser-redirect flow (runBrowserAuth) or
// accepts a pre-minted API token. See the authLogin command for the
// same rationale.

var setupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Interactive first-time setup wizard",
	Long: `Walk through server URL, authentication, org selection, and optional default policy,
then save credentials to ~/.chainsaw/config.yaml.

Use --yes to skip all confirmation prompts.
Progress is saved to ~/.chainsaw/.setup_progress so the wizard can resume after an error.`,
	RunE: runSetup,
}

func init() {
	setupCmd.Flags().Bool("yes", false, "Skip confirmation prompts")
	setupCmd.Flags().Bool("skip-persona", false, "Skip only the persona prompt (auth prompt still runs)")
	rootCmd.AddCommand(setupCmd)
}

// setupProgress is persisted to ~/.chainsaw/.setup_progress between steps.
// The auth token is intentionally not persisted here; it is held in memory only.
type setupProgress struct {
	Step        string    `json:"step"`
	ServerURL   string    `json:"server_url,omitempty"`
	AuthDone    bool      `json:"auth_done,omitempty"`
	OrgID       string    `json:"org_id,omitempty"`
	PersonaDone bool      `json:"persona_done,omitempty"`
	UpdatedAt   time.Time `json:"updated_at"`
}

func loadProgress() setupProgress {
	data, err := os.ReadFile(setupProgressPath())
	if err != nil {
		return setupProgress{}
	}
	var p setupProgress
	_ = json.Unmarshal(data, &p)
	return p
}

func saveProgress(p setupProgress) {
	p.UpdatedAt = time.Now().UTC()
	data, _ := json.MarshalIndent(p, "", "  ")
	_ = os.WriteFile(setupProgressPath(), data, 0o600)
}

func clearProgress() { _ = os.Remove(setupProgressPath()) }

func runSetup(cmd *cobra.Command, _ []string) error {
	yes, _ := cmd.Flags().GetBool("yes")
	skipPersona, _ := cmd.Flags().GetBool("skip-persona")
	prog := loadProgress()

	fmt.Println("=== Chainsaw Setup ===")
	if prog.Step != "" {
		fmt.Printf("Resuming from step: %s\n", prog.Step)
	} else {
		// First-run: keep it to a single welcome line. The user typed
		// `chainsaw setup` to point the CLI at a server — get them to
		// the prompt, not to a brand-philosophy preamble. The mental-
		// model catalog still lives behind `chainsaw introduce` for
		// users who actually want it.
		fmt.Println("Welcome — let's set up your Chainsaw client.")
	}
	fmt.Println()

	// token is kept in memory only — never written to the progress file.
	var token string

	// ── Step 1: Server URL ────────────────────────────────────────────────────
	if prog.ServerURL == "" {
		prog.Step = "server_url"
		saveProgress(prog)

		defaultURL := cfgServerURL()
		if defaultURL == "" {
			defaultURL = "http://localhost:8787"
		}
		prog.ServerURL = PromptString("Server URL", defaultURL)
		prog.ServerURL = strings.TrimRight(strings.TrimSpace(prog.ServerURL), "/")
		if prog.ServerURL == "" {
			return fmt.Errorf("server URL is required")
		}

		// Validate connectivity.
		client := NewAPIClient(prog.ServerURL, "")
		fmt.Printf("Connecting to %s …\n", prog.ServerURL)
		var health map[string]string
		if err := client.Get("/healthz", &health); err != nil {
			return fmt.Errorf("server not reachable: %w", err)
		}
		fmt.Printf("Server status: %s\n\n", health["status"])
		saveProgress(prog)
	}

	// ── Step 2: Authentication ────────────────────────────────────────────────
	// Always re-authenticate — we never persist the token on disk.
	if prog.AuthDone && prog.OrgID != "" {
		fmt.Println("Previous setup was partially completed. Please re-authenticate to continue.")
	}
	{
		prog.Step = "auth"
		saveProgress(prog)

		// Two methods only: browser-redirect (default, solves Turnstile
		// in the browser) and pre-minted API token paste (for operators
		// automating install). The password path is intentionally gone.
		defaultMethod := "browser (opens a sign-in page)"
		if !browserLikelyAvailable() {
			defaultMethod = "API key (paste existing)"
		}
		authMethod := PromptSelect("Authentication method",
			[]string{"browser (opens a sign-in page)", "API key (paste existing)"},
			defaultMethod)

		client := NewAPIClient(prog.ServerURL, "")

		switch authMethod {
		case "API key (paste existing)":
			fmt.Printf("Mint an API key at: %s/chainsaw/settings/api-keys/new\n", prog.ServerURL)
			fmt.Println("(An API key is the bearer token the CLI uses — distinct from the")
			fmt.Println(" client_credential that goes into .npmrc / pip.conf.)")
			token = PromptPassword("API key")
			if token == "" {
				return fmt.Errorf("API key cannot be empty")
			}
			if err := validateToken(client, token); err != nil {
				return fmt.Errorf("API key validation failed: %w", err)
			}
			fmt.Println("API key validated.")

		default: // browser flow
			var err error
			token, err = runBrowserAuth(cmd.Context(), os.Stdout, prog.ServerURL)
			if err != nil {
				return fmt.Errorf("browser login failed: %w", err)
			}
			// Browser flow returns an API key; /api/auth/me gives us the
			// org so we can short-circuit the org-selection step.
			var me struct {
				OrgID string `json:"org_id"`
				Email string `json:"email"`
				Role  string `json:"role"`
			}
			if err := NewAPIClient(prog.ServerURL, token).Get("/api/auth/me", &me); err != nil {
				return fmt.Errorf("token validation failed: %w", err)
			}
			if prog.OrgID == "" {
				prog.OrgID = me.OrgID
			}
			fmt.Printf("Logged in as %s (role: %s)\n\n", me.Email, me.Role)
		}
		prog.AuthDone = true
		saveProgress(prog)
	}

	// ── Step 3: Org selection / creation ─────────────────────────────────────
	authedClient := NewAPIClient(prog.ServerURL, token)

	if prog.OrgID == "" {
		prog.Step = "org"
		saveProgress(prog)

		type orgSummary struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			Slug string `json:"slug"`
		}
		var orgsResp struct {
			Orgs []orgSummary `json:"orgs"`
		}
		if err := authedClient.Get("/api/orgs", &orgsResp); err != nil {
			return fmt.Errorf("list orgs: %w", err)
		}

		if len(orgsResp.Orgs) == 0 {
			fmt.Println("No organisations found. Let's create one.")
			name := PromptString("Organisation name", "")
			slug := PromptString("Slug (URL-safe, e.g. acme-corp)", "")

			var createResp struct {
				Org orgSummary `json:"org"`
			}
			if err := authedClient.Post("/api/orgs", map[string]string{
				"name": name,
				"slug": slug,
			}, &createResp); err != nil {
				return fmt.Errorf("create org: %w", err)
			}
			prog.OrgID = createResp.Org.ID
			fmt.Printf("Created org %q (id: %s)\n\n", createResp.Org.Name, prog.OrgID)
		} else {
			options := make([]string, len(orgsResp.Orgs))
			for i, o := range orgsResp.Orgs {
				options[i] = fmt.Sprintf("%s (%s)", o.Name, o.ID)
			}
			options = append(options, "[create new org]")
			chosen := PromptSelect("Select organisation", options, options[0])

			if chosen == "[create new org]" {
				name := PromptString("Organisation name", "")
				slug := PromptString("Slug", "")
				var createResp struct {
					Org orgSummary `json:"org"`
				}
				if err := authedClient.Post("/api/orgs", map[string]string{
					"name": name,
					"slug": slug,
				}, &createResp); err != nil {
					return fmt.Errorf("create org: %w", err)
				}
				prog.OrgID = createResp.Org.ID
				fmt.Printf("Created org %q (id: %s)\n\n", createResp.Org.Name, prog.OrgID)
			} else {
				// Extract ID from "Name (id)" format.
				for _, o := range orgsResp.Orgs {
					if strings.Contains(chosen, o.ID) {
						prog.OrgID = o.ID
						break
					}
				}
			}
		}
		saveProgress(prog)
	}

	// ── Step 4: Persona (mental-model) ───────────────────────────────────────
	// Mirrors the dashboard's onboarding persona prompt. The value is
	// persisted server-side via POST /api/users/me/persona so future
	// chainsaw_introduce calls (over MCP or CLI) skip the nudge and
	// surface the persona-tailored recommended_path. Persona is UX-
	// only — it never gates permissions.
	// chosenPersona tracks the persona ID resolved during this run (or
	// "" for skipped / not-sure). It feeds the next-step block-command
	// printer at the end of the wizard so we can default to an
	// end_user_dev demo when no persona was chosen.
	var chosenPersona string
	if !prog.PersonaDone {
		prog.Step = "persona"
		saveProgress(prog)
		var err error
		chosenPersona, err = runSetupPersonaStep(authedClient, yes, skipPersona)
		if err != nil {
			// A persona mishap is never fatal — the user can still finish
			// setup and edit persona later. We log and move on.
			fmt.Printf("Warning: could not save persona: %v\n", err)
		}
		prog.PersonaDone = true
		saveProgress(prog)
	}

	// Show the persona-aware "try a real block" hint. B.4.4 expects the
	// closing message to contain an explicit ecosystem block command so
	// the user has a one-line demo path after setup finishes. We print
	// this regardless of --yes / --skip-persona; only the variant
	// changes with persona.
	printSetupNextStep(chosenPersona)

	// ── Step 5: Optional default policy ──────────────────────────────────────
	prog.Step = "policy"
	saveProgress(prog)

	if !yes {
		if PromptConfirm("Configure a default block policy now?") {
			if err := promptCreateDefaultPolicy(authedClient); err != nil {
				fmt.Printf("Warning: could not create policy: %v\n", err)
			}
		}
	}

	// ── Step 5: Summary + confirm + save ─────────────────────────────────────
	fmt.Println()
	fmt.Println("=== Summary ===")
	fmt.Printf("  Server URL : %s\n", prog.ServerURL)
	fmt.Printf("  Org ID     : %s\n", prog.OrgID)
	fmt.Printf("  Token      : %s…\n", tokenPreview(token))
	fmt.Println()

	if !yes && !PromptConfirmDefaultYes("Save configuration?") {
		fmt.Println("Aborted — no changes saved.")
		emit("cli.setup.abandoned", map[string]any{"step": "summary_confirm"})
		return nil
	}

	if err := saveConfig(prog.ServerURL, token, prog.OrgID); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	clearProgress()
	fmt.Printf("Configuration saved to %s\n", configFilePath())
	emit("cli.setup.completed", nil)
	return nil
}

func validateToken(client *APIClient, token string) error {
	c := NewAPIClient(client.baseURL, token)
	var me map[string]any
	return c.Get("/api/auth/me", &me)
}

func promptCreateDefaultPolicy(client *APIClient) error {
	name := PromptString("Policy name", "Default Block Policy")
	modeOptions := []string{"block", "monitor", "quarantine", "allow"}
	mode := PromptSelect("Mode", modeOptions, "block")

	body := map[string]any{
		"name":       name,
		"mode":       mode,
		"status":     "enabled",
		"precedence": 100,
	}
	var resp map[string]any
	if err := client.Post("/api/policies", body, &resp); err != nil {
		return err
	}
	fmt.Printf("Policy %q created.\n", name)
	return nil
}

// tokenPreview returns the first 12 chars of a token for display.
func tokenPreview(token string) string {
	if len(token) <= 12 {
		return token
	}
	return token[:12]
}

// runSetupPersonaStep asks the user which mental model best describes
// their role and persists the choice via POST /api/users/me/persona.
// Only the three persisted personas are offered (appsec, devsecops,
// enterprise_it) — end_user_dev and agent are documentation-only
// models that live in agenticux.MentalModels() but aren't valid
// users.persona values. "Skip" maps to a skipped=true POST so the
// dashboard + MCP onboarding nudge both stop bothering the user.
//
// Headless mode (--yes or no TTY): silently skip without prompting.
// Match the rest of the wizard's non-interactive contract — a CI run
// should complete setup without human input.
func runSetupPersonaStep(client *APIClient, yes, skipPersona bool) (string, error) {
	fmt.Println()
	fmt.Println("How will you be using Chainsaw?")
	fmt.Println("(the persona is UX-only; it never gates permissions).")

	if yes || skipPersona || !stdinIsTerminal() {
		return "", persistPersona(client, "", true)
	}

	// Option labels and copy match the dashboard's first-run persona
	// picker at ui_new/src/app/onboarding/persona/persona-picker.tsx —
	// the CLI/dashboard duality is the whole point of this step. The
	// "Not sure yet" option maps to skipped=true (no persona stored)
	// rather than its own persona value: matches dashboard semantics
	// and the server's known-persona enum (appsec, devsecops,
	// enterprise_it).
	options := []string{
		"Platform & Application Security  (CVE triage, SBOM insights, package risk)",
		"DevSecOps & Compliance           (policy gates, audit exports, CI/CD templates)",
		"Enterprise IT & Shared Services  (SSO, SCIM, SIEM webhooks, tenant-wide controls)",
		"Not sure yet                     (show all features)",
	}
	choice := PromptSelect("Pick one", options, options[3])

	var personaID string
	switch choice {
	case options[0]:
		personaID = agenticux.PersonaAppSec
	case options[1]:
		personaID = agenticux.PersonaDevSecOps
	case options[2]:
		personaID = agenticux.PersonaEnterpriseIT
	default:
		// "Not sure yet" — persist skip=true so future introduces stop
		// nudging and the dashboard shows the all-features view.
		return "", persistPersona(client, "", true)
	}
	return personaID, persistPersona(client, personaID, false)
}

// printSetupNextStep emits the closing "try a real block" message that
// the smoke spec B.4.4 looks for. The block command is hard-coded per
// persona (never generated at runtime): the typosquat demo `npm install
// lodahs` is the canonical end-user / appsec hook, devsecops gets a CI
// hint, and enterprise_it gets an audit-log evidence command. Anything
// unrecognised falls back to the lodahs demo so the smoke check passes
// even when a persona is skipped or unknown.
func printSetupNextStep(persona string) {
	const (
		typosquatCmd = "npm install lodahs"
		auditCmd     = "chainsaw audit logs --since 24h"
	)

	fmt.Println()
	fmt.Println("Next step — try a real block:")
	fmt.Println()

	switch persona {
	case agenticux.PersonaDevSecOps:
		fmt.Printf("    %s\n", typosquatCmd)
		fmt.Println()
		fmt.Println("    # CI hint: run the same check in GitHub Actions —")
		fmt.Println("    #   - run: chainsaw run")
		fmt.Println()
		fmt.Println("Chainsaw will refuse the install (typosquat of `lodash`). The refusal will")
		fmt.Println("appear in your audit log within 5s. Wire your package manager to the proxy")
		fmt.Println("first — see https://chain305.com/cli-download.")
	case agenticux.PersonaEnterpriseIT:
		fmt.Printf("    %s\n", auditCmd)
		fmt.Println()
		fmt.Println("Lists every block, allow, and policy decision in the last 24h — the tenant-")
		fmt.Println("wide audit feed you'll wire into SIEM. See https://chain305.com/cli-download")
		fmt.Println("for proxy + SIEM webhook setup.")
	default: // appsec, end_user_dev, skipped, or unknown — typosquat demo
		fmt.Printf("    %s\n", typosquatCmd)
		fmt.Println()
		fmt.Println("Chainsaw will refuse the install (typosquat of `lodash`). The refusal will")
		fmt.Println("appear in your audit log within 5s. Wire your package manager to the proxy")
		fmt.Println("first — see https://chain305.com/cli-download.")
	}
	fmt.Println()
}

// persistPersona POSTs to /api/users/me/persona. Matches the shape the
// server expects in handleMePersona: persona string pointer + skipped
// flag. We skip analytics inferredFlag — the CLI is always an explicit
// user choice, never inferred.
func persistPersona(client *APIClient, persona string, skipped bool) error {
	body := map[string]any{
		"skipped": skipped,
	}
	if persona != "" {
		body["persona"] = persona
	}
	var resp map[string]any
	if err := client.Post("/api/users/me/persona", body, &resp); err != nil {
		return err
	}
	switch {
	case persona != "":
		fmt.Printf("Persona saved: %s\n", persona)
	case skipped:
		fmt.Println("Skipped — the persona nudge won't reappear.")
	}
	return nil
}
