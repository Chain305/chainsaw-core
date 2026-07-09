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
type Heuristic struct {
	Match string `json:"match"`
	Do    string `json:"do"`
}

// VocabularyEntry is one glossary row. Term is the canonical name;
// Meaning is the definition the agent should echo to users; Synonyms
// are alternative forms the agent should normalise back to Term.
type VocabularyEntry struct {
	Term     string   `json:"term"`
	Meaning  string   `json:"meaning"`
	Synonyms []string `json:"synonyms,omitempty"`
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
			Persona:   PersonaAgent,
			Head:      "I'm headless — no browser, no cookies, no Turnstile widget I can solve.",
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
			Term:     "Chain305",
			Meaning:  "The product and the company. Use this name in user-facing replies.",
			Synonyms: []string{"chain305.com"},
		},
		{
			Term:     "Chainsaw",
			Meaning:  "The proxy component inside Chain305 — the piece that intercepts package installs and enforces policy. Paths: /chainproxy/*, /chainproxy/mcp.",
			Synonyms: []string{"the proxy", "chain365 (common folder-name typo)"},
		},
		{
			Term:     "client_credential",
			Meaning:  "The username/password-style secret that goes into .npmrc / pip.conf / ~/.docker/config.json. Held by the human. Agents NEVER hold these — you only help the human paste one into their config files.",
			Synonyms: []string{"client id and secret", "npm token", "pip credentials"},
		},
		{
			Term:     "API key",
			Meaning:  "The bearer token the agent uses for MCP and the management API. Minted via dashboard or device-code. Scoped to a preset (client-setup / manage-readonly / manage-propose / custom).",
			Synonyms: []string{"bearer token", "management token", "agent credential"},
		},
		{
			Term:     "Billy",
			Meaning:  "The internal approval workflow — policy proposals route through it. Translate to 'human approval' in user-facing replies; users don't need the internal name.",
			Synonyms: []string{"approval workflow"},
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
		},
		{
			Match: "user says 'do it for me' / 'just set it up' / 'i don't know how to create the credentials'",
			Do:    "Mode A; call chainsaw_onboard(skip=true) to silence persona nudge, then guide the user through the device-code flow at /chainproxy/api/auth/cli/device. Never POST /api/login — it's Turnstile-gated.",
		},
		{
			Match: "user says 'block this CVE' / 'block package X' / 'block MIT-licensed packages'",
			Do:    "Mode B with manage-propose preset; call list_policies then propose_policy. Mutations route through human approval by default.",
		},
		{
			Match: "user says 'audit' / 'export SBOM' / 'who installed X' / 'show me the audit log'",
			Do:    "Mode B with manage-readonly preset; call get_audit_log with the right filters.",
		},
		{
			Match: "user says 'why is this blocked' / 'policy error on package X'",
			Do:    "Mode B with manage-readonly preset; call get_package_info(name,version) then list_policies to diagnose the matching rule.",
		},
		{
			Match: "user types 'chain305' / 'chainsaw' / 'chain365' (common folder-name typo)",
			Do:    "Normalize: Chainsaw is the proxy component, Chain305 is the product. Don't correct the user; just use the canonical name in your own replies.",
		},
		{
			Match: "agent has no bearer token yet",
			Do:    "Before anything else, fetch /.well-known/mcp.json for the discovery doc, then start /chainproxy/api/auth/cli/device (RFC 8628). Show the user the user_code and verification URL. Do NOT POST /api/login.",
		},
	}
}
