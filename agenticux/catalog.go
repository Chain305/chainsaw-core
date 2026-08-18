// Package agenticux owns the canonical data for Chain305's agent-facing
// UX: the two modes, five mental-model personas, vocabulary, and
// first-utterance routing heuristics. It exists so the MCP introduce
// tool, the CLI's `chainsaw introduce`, the /llms.txt generator, and
// the /for-agents/ landing page all read from the same source.
//
// The anti-goal is drift. Before this package was extracted, the server
// had its own copies of these constants in server_mcp.go and the CLI's
// help output guessed at mode framing independently. That produced an
// agent experience where Claude Code saw different persona labels from
// Cursor even though both called the same MCP server — because the CLI
// guidance a user read on their laptop didn't match the MCP catalog
// their agent saw. One package, one set of strings, every surface.
//
// Design notes:
//
//   - Everything here is data, not behaviour. No HTTP, no DB, no
//     imports from internal/server. The server + CLI + any future
//     consumer import this; this never imports them.
//
//   - JSON tags are preserved to match the pre-extraction shape from
//     server_mcp.go. Changing them is a public-API break — the MCP
//     introduce response is part of the agent contract.
//
//   - Persona IDs ("appsec", "devsecops", "enterprise_it") are the
//     canonical values written to users.persona. They match the
//     constants in internal/server/persona.go; keep them in lockstep.
package agenticux

// Heuristic is a first-utterance routing hint. Match is a human-readable
// description of the user-message shape; Do is the canonical sequence
// of tool calls or instructions the agent should perform.
//
// CLIDo and AgentOnly exist because this catalog has two audiences: an
// agent over MCP, and a human running `chainsaw introduce` in a
// terminal. "Call get_install_snippet(ecosystem=…)" is the right answer
// for one and gibberish for the other. Both fields are json:"-" so the
// MCP response shape is unchanged (see the package doc — the JSON is
// part of the agent contract).
type Heuristic struct {
	Match string `json:"match"`
	Do    string `json:"do"`

	// CLIDo is Do restated for a person at a terminal: chainsaw
	// commands instead of MCP tool calls. Empty means Do already
	// reads correctly for both audiences.
	CLIDo string `json:"-"`

	// AgentOnly marks a row that is only meaningful to an agent —
	// credential bootstrap, or instructions about how the agent should
	// phrase its own replies. `chainsaw introduce` skips these; the
	// MCP response still carries them.
	AgentOnly bool `json:"-"`
}

// VocabularyEntry is one glossary row. Term is the canonical name;
// Meaning is the definition the agent should echo to users; Synonyms
// are alternative forms the agent should normalise back to Term.
//
// CLIMeaning / AgentOnly work the same way as on Heuristic.
type VocabularyEntry struct {
	Term     string   `json:"term"`
	Meaning  string   `json:"meaning"`
	Synonyms []string `json:"synonyms,omitempty"`

	// CLIMeaning is Meaning with the wire detail an agent needs and a
	// human doesn't. Empty means Meaning serves both.
	CLIMeaning string `json:"-"`

	// AgentOnly hides the row from `chainsaw introduce`.
	AgentOnly bool `json:"-"`
}

// MentalModel is one persona viewed from the agent's perspective:
// what the user thinks they're doing, what they'll say, and what
// success looks like. Mode + Preset point the agent at the right
// downstream flow.
type MentalModel struct {
	Persona   string `json:"persona"`
	Head      string `json:"head"`
	Utterance string `json:"utterance"`
	Success   string `json:"success"`
	Mode      string `json:"mode,omitempty"`
	Preset    string `json:"preset,omitempty"`
}

// Mode is one of the two top-level workflows (A = configure the proxy,
// B = manage Chain305). Tag is "A" or "B"; Preset is the default API
// key preset that matches; Tools is a short list of the canonical tools
// for the mode.
type Mode struct {
	Tag        string   `json:"tag"`
	Title      string   `json:"title"`
	Summary    string   `json:"summary"`
	WhenToUse  string   `json:"when_to_use"`
	PresetName string   `json:"preset_name"`
	Tools      []string `json:"tool_examples"`
}

// Canonical persona IDs. Mirror the PersonaAppSec / PersonaDevSecOps /
// PersonaEnterpriseIT constants in internal/server/persona.go. The
// "end_user_dev" and "agent" IDs are documentation-only — they are
// surfaced to users and agents but never persisted to users.persona.
const (
	PersonaEndUserDev   = "end_user_dev"
	PersonaAppSec       = "appsec"
	PersonaDevSecOps    = "devsecops"
	PersonaEnterpriseIT = "enterprise_it"
	PersonaAgent        = "agent"
)

// PresetClientSetup / PresetManageReadonly / PresetManagePropose mirror
// the apikeys package's preset IDs. Duplicated here to avoid importing
// internal/apikeys from a catalog package — keep the strings identical.
const (
	PresetClientSetup    = "client-setup"
	PresetManageReadonly = "manage-readonly"
	PresetManagePropose  = "manage-propose"
)

// Modes returns the canonical Mode A / Mode B framing. Order is
// deliberate — A first because setup-path traffic dominates.
func Modes() []Mode {
	return []Mode{
		{
			Tag:   "A",
			Title: "Configure my project to install through Chain305",
			Summary: "End state: a client_credential is embedded in " +
				".npmrc / pip.conf / ~/.docker/config.json / " +
				"~/.m2/settings.xml so package installs flow through " +
				"the proxy and policy enforces.",
			WhenToUse: "The user wants `npm install` (or pip/maven/docker/etc.) " +
				"to go through Chain305. Default sub-flow: the human " +
				"mints the client_credential in the dashboard and " +
				"pastes it to you; you only edit config files.",
			PresetName: PresetClientSetup,
			Tools:      []string{"get_install_snippet", "setup_doctor", "list_my_repositories"},
		},
		{
			Tag:   "B",
			Title: "Manage Chain305 (policies, security state, dashboard equivalents)",
			Summary: "End state: you call the management API to read or edit " +
				"policies, view audit logs, simulate, check vulnerabilities, " +
				"generate SBOMs.",
			WhenToUse: "The user wants to inspect or change Chain305 itself. " +
				"Use manage-readonly if you only need to read; use " +
				"manage-propose to propose policy changes (which will " +
				"route through human approval unless the key explicitly " +
				"enables allow_mutations).",
			PresetName: PresetManageReadonly,
			Tools:      []string{"list_policies", "propose_policy", "get_audit_log", "check_vulnerabilities"},
		},
	}
}

// MentalModels returns the five personas with their mental models.
// Order is the canonical presentation order: end-user dev first (most
// common cold walk-in), specialists in the middle, agent-as-persona
// last so agents recognise themselves in the list.
func MentalModels() []MentalModel {
	return []MentalModel{
		{
			Persona:   PersonaEndUserDev,
			Head:      "I want `pip install` / `npm install` to go through Chain305.",
			Utterance: "\"set up chain305 for python,\" \"do it for me,\" \"install chain305 in this repo\"",
			Success:   "A working pip.conf / .npmrc / settings.xml / ~/.docker/config.json.",
			Mode:      "A",
			Preset:    PresetClientSetup,
		},
		{
			Persona:   PersonaAppSec,
			Head:      "I author the rules that block bad packages.",
			Utterance: "\"draft a CVSS policy,\" \"why was this CVE allowed?\"",
			Success:   "A policy proposal submitted for human approval.",
			Mode:      "B",
			Preset:    PresetManagePropose,
		},
		{
			Persona:   PersonaDevSecOps,
			Head:      "I plumb the proxy into fleets and CI runners.",
			Utterance: "\"mint a CI service token,\" \"add proxy to GitHub Actions\"",
			Success:   "CI runners + developer machines resolving packages via Chain305.",
			Mode:      "A",
			Preset:    PresetClientSetup,
		},
		{
			Persona:   PersonaEnterpriseIT,
			Head:      "Show me evidence — I report, I don't author.",
			Utterance: "\"export SBOM,\" \"pull yesterday's audit log\"",
			Success:   "A CycloneDX SBOM or audit CSV in hand.",
			Mode:      "B",
			Preset:    PresetManageReadonly,
		},
		{
			Persona: PersonaAgent,
			// Named the specific bot-check vendor until 2026-08. This
			// string is printed by `chainsaw introduce --personas` and
			// served in the unauthenticated MCP introduce response, so
			// it should not point at which control guards which door.
			Head:      "I'm headless — no browser, no cookies, no bot-check widget I can solve.",
			Utterance: "(no user utterance — this is the agent's own mental model)",
			Success:   "Fetched mcp.json, completed device-code flow, connected MCP, called chainsaw_introduce.",
			// Deliberately no Mode/Preset — the agent picks per user.
		},
	}
}

// Vocabulary returns the canonical glossary. Agents echo these terms
// verbatim; users see the same definitions on the landing page, in
// llms.txt, in chainsaw_introduce's MCP response, and in `chainsaw
// introduce` on the CLI.
func Vocabulary() []VocabularyEntry {
	return []VocabularyEntry{
		{
			Term:    "Chain305",
			Meaning: "The product and the company. Use this name in user-facing replies.",
			// "Use this name in your replies" is an instruction TO the
			// agent. A person reading a glossary needs the definition,
			// not the style rule.
			CLIMeaning: "The product, and the company behind it. Chain305 is the whole thing; Chainsaw is the proxy inside it.",
			Synonyms:   []string{"chain305.com"},
		},
		{
			Term:    "Chainsaw",
			Meaning: "The proxy component inside Chain305 — the piece that intercepts package installs and enforces policy. Paths: /chainproxy/*, /chainproxy/mcp.",
			// The path map is wire detail an agent needs to build
			// request URLs. A person reading a glossary does not —
			// their URLs come out of `chainsaw install-hook`.
			CLIMeaning: "The proxy component inside Chain305 — the piece your package installs go through, and the piece that enforces policy. It is also the name of this CLI.",
			Synonyms:   []string{"the proxy", "chain365 (common folder-name typo)"},
		},
		{
			Term:    "client_credential",
			Meaning: "The username/password-style secret that goes into .npmrc / pip.conf / ~/.docker/config.json. Held by the human. Agents NEVER hold these — you only help the human paste one into their config files.",
			// Same fact, stated as the user's rule rather than the
			// agent's: this one is yours to hold.
			CLIMeaning: "The username/password-style secret that goes into .npmrc / pip.conf / ~/.docker/config.json so your package installs authenticate to the proxy. `chainsaw install-hook` can write it for you. It stays yours — never hand it to an AI agent.",
			Synonyms:   []string{"client id and secret", "npm token", "pip credentials"},
		},
		{
			Term:       "API key",
			Meaning:    "The bearer token the agent uses for MCP and the management API. Minted via dashboard or device-code. Scoped to a preset (client-setup / manage-readonly / manage-propose / custom).",
			CLIMeaning: "The token the CLI and any MCP client use to reach the management API. Mint one in the dashboard or with `chainsaw auth login`; list and rotate them with `chainsaw token`. Each is scoped to a preset (client-setup / manage-readonly / manage-propose / custom) so it carries only the permissions it needs.",
			Synonyms:   []string{"bearer token", "management token", "agent credential"},
		},
		{
			// Billy is a product name, not a codename — it is the
			// label on the dashboard nav and on the `billy` plan
			// entitlement that `chainsaw features` prints. What the
			// old wording described ("the internal approval
			// workflow") was the thing Billy's proposals go THROUGH,
			// not Billy itself.
			Term:     "Billy",
			Meaning:  "The AI assistant inside the Chain305 dashboard. It can draft policy changes and other actions, but everything it proposes waits for a person to approve it before it takes effect.",
			Synonyms: []string{"the assistant", "Ask Billy"},
		},
	}
}

// RoutingHeuristics returns the canonical first-utterance routing table.
// Single source of truth for MCP's chainsaw_introduce response AND the
// human-readable table in /llms.txt AND `chainsaw introduce`. If a new
// ecosystem lands, update here once.
func RoutingHeuristics() []Heuristic {
	return []Heuristic{
		{
			Match: "user says 'set up for python' / 'configure npm' / 'add chain305 to my pip/maven/docker'",
			Do:    "Mode A; call list_my_repositories then get_install_snippet(ecosystem=...).",
			CLIDo: "Run `chainsaw setup` for the guided path, or `chainsaw install-hook <manager>` to wire one package manager on its own.",
		},
		{
			Match: "user says 'do it for me' / 'just set it up' / 'i don't know how to create the credentials'",
			// The reason for avoiding /api/login is stated as a
			// capability fact ("browser-only"), deliberately without
			// naming the anti-abuse control in front of it — this
			// catalog is served to unauthenticated callers.
			Do:    "Mode A; call chainsaw_onboard(skip=true) to silence persona nudge, then guide the user through the device-code flow at /chainproxy/api/auth/cli/device. Never POST /api/login — it is a browser-only form and cannot be driven headlessly.",
			CLIDo: "Run `chainsaw setup` — it mints the credentials and writes the config files for you. On a machine with no browser (CI, SSH), run `chainsaw auth login --device` and finish signing in from another device.",
		},
		{
			Match: "user says 'block this CVE' / 'block package X' / 'block MIT-licensed packages'",
			Do:    "Mode B with manage-propose preset; call list_policies then propose_policy. Mutations route through human approval by default.",
			CLIDo: "Run `chainsaw policy list` to see what is already in place, then `chainsaw policy create` to add a rule. New rules start in monitor mode unless you pass --mode block.",
		},
		{
			Match: "user says 'audit' / 'export SBOM' / 'who installed X' / 'show me the audit log'",
			Do:    "Mode B with manage-readonly preset; call get_audit_log with the right filters.",
			CLIDo: "Run `chainsaw audit view` for the activity log (--since, --actor, --action to narrow it), or `chainsaw sbom export` for a CycloneDX SBOM.",
		},
		{
			Match: "user says 'why is this blocked' / 'policy error on package X'",
			Do:    "Mode B with manage-readonly preset; call get_package_info(name,version) then list_policies to diagnose the matching rule.",
			CLIDo: "Run `chainsaw why <ecosystem> <package>@<version>` — it prints the decision, the rule that matched, and who to ask about it.",
		},
		{
			// Instructions about how the agent should phrase its own
			// replies. Nothing for a person to act on.
			Match:     "user types 'chain305' / 'chainsaw' / 'chain365' (common folder-name typo)",
			Do:        "Normalize: Chainsaw is the proxy component, Chain305 is the product. Don't correct the user; just use the canonical name in your own replies.",
			AgentOnly: true,
		},
		{
			// Credential bootstrap for a headless caller. A human at a
			// terminal does this with `chainsaw auth login`, which the
			// "do it for me" row above already covers.
			Match:     "agent has no bearer token yet",
			Do:        "Before anything else, fetch /.well-known/mcp.json for the discovery doc, then start /chainproxy/api/auth/cli/device (RFC 8628). Show the user the user_code and verification URL. Do not POST /api/login — it is a browser-only form.",
			AgentOnly: true,
		},
	}
}
