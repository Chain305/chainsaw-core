package cli

// `chainsaw introduce` is the CLI twin of the MCP chainsaw_introduce
// tool. An agent connected over MCP gets the mode framing, vocabulary,
// mental models, and routing heuristics as structured JSON. A human
// running the CLI gets the same data rendered for a terminal — no
// auth, no network call, entirely offline.
//
// Why a local command when the same data is on the web and in MCP?
// Three reasons:
//
//  1. Pre-auth discovery. A new user running `chainsaw` for the first
//     time has no token and can't call the MCP tool. `chainsaw
//     introduce` works before `chainsaw setup` so the user picks the
//     right mode before authenticating.
//
//  2. Terminal fidelity. Markdown tables render poorly in 80 columns;
//     the CLI can word-wrap and indent specifically for a terminal
//     in ways the landing page and MCP JSON can't.
//
//  3. Single source of truth. This command reads internal/agenticux
//     — the same package the server's introduceVocabulary /
//     introduceRoutingHeuristics call. Drift between CLI and MCP is
//     a compile error, not a copy-paste bug.
//
// Flags (names chosen from the user's vocabulary, not the product's
// internal one — "mental models" is a design-doc phrase that made the
// first draft; users grep for --personas and --examples):
//   --json       emit the structured catalog for scripting (mirror of
//                the MCP response shape; agents can pipe `chainsaw
//                introduce --json` into jq without needing an API key)
//   --modes      show only the two-workflow picker
//   --personas   show only the persona section
//   --glossary   show only the term definitions
//   --examples   show only the "if a user says X, do Y" table

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/agenticux"
)

var introduceCmd = &cobra.Command{
	Use:     "introduce",
	GroupID: GrpConfig,
	Short:   "Show how people use Chain305 — personas, workflows, glossary, examples",
	Long: `Print a quick overview of how people use Chain305:

  • Two workflows — configure the proxy (Mode A) or manage policies (Mode B)
  • Five personas — which one sounds like you?
  • A glossary of the key terms (Chain305, client_credential, API key, …)
  • Examples — common things people say, and what to do next

Runs offline. No login, no network. Shows the same framing Chain305
surfaces everywhere else (landing page, docs, MCP), so whichever way
you come in, you see the same story.

Use --json for a machine-readable dump (useful in scripts, or for
agents that don't have an API key yet and want to pipe into jq).`,
	RunE: runIntroduce,
}

func init() {
	introduceCmd.Flags().Bool("json", false, "Emit JSON instead of human-readable text")
	introduceCmd.Flags().Bool("modes", false, "Show only the two workflows (Mode A / Mode B)")
	introduceCmd.Flags().Bool("personas", false, "Show only the personas")
	introduceCmd.Flags().Bool("glossary", false, "Show only the glossary of terms")
	introduceCmd.Flags().Bool("examples", false, "Show only the examples of common requests")
	rootCmd.AddCommand(introduceCmd)
}

// introduceSections is the shape `--json` emits. Matches the MCP
// introduce response's field names for the parts that don't depend on
// caller identity (no presets, no caller info, no persona nudge —
// those need the server).
type introduceSections struct {
	ProductName       string                      `json:"product_name"`
	Summary           string                      `json:"summary"`
	Modes             []agenticux.Mode            `json:"modes"`
	MentalModels      []agenticux.MentalModel     `json:"mental_models"`
	Vocabulary        []agenticux.VocabularyEntry `json:"vocabulary"`
	RoutingHeuristics []agenticux.Heuristic       `json:"routing_heuristics"`
}

func buildIntroduceSections() introduceSections {
	return introduceSections{
		ProductName: "Chain305",
		Summary: "Chain305 is a software supply-chain firewall for npm, PyPI, " +
			"Maven, Docker, and other registries. It proxies package installs, " +
			"evaluates policy on every artifact, and exposes a management API.",
		Modes:             agenticux.Modes(),
		MentalModels:      agenticux.MentalModels(),
		Vocabulary:        agenticux.Vocabulary(),
		RoutingHeuristics: agenticux.RoutingHeuristics(),
	}
}

func runIntroduce(cmd *cobra.Command, _ []string) error {
	jsonOut := useJSON(cmd)
	if jsonOut {
		enc := json.NewEncoder(outWriterOr(cmd, cmd.OutOrStdout()))
		enc.SetIndent("", "  ")
		return enc.Encode(buildIntroduceSections())
	}

	showModes, _ := cmd.Flags().GetBool("modes")
	showGlossary, _ := cmd.Flags().GetBool("glossary")
	showPersonas, _ := cmd.Flags().GetBool("personas")
	showExamples, _ := cmd.Flags().GetBool("examples")
	// If no section-flag is set, show everything.
	showAll := !showModes && !showGlossary && !showPersonas && !showExamples

	w := cmd.OutOrStdout()
	if showAll {
		fmt.Fprintln(w, "Chain305 — how people use it")
		fmt.Fprintln(w, strings.Repeat("=", 40))
		fmt.Fprintln(w, "Chain305 is a software supply-chain firewall. This is a quick")
		fmt.Fprintln(w, "tour of the personas, workflows, glossary, and common examples —")
		fmt.Fprintln(w, "same framing you'll see in the docs and on the web.")
		fmt.Fprintln(w)
	}

	if showAll || showPersonas {
		renderMentalModels(w)
	}
	if showAll || showModes {
		renderModes(w)
	}
	if showAll || showGlossary {
		renderVocabulary(w)
	}
	if showAll || showExamples {
		renderRoutingHeuristics(w)
	}

	if showAll {
		fmt.Fprintln(w, "Next steps")
		fmt.Fprintln(w, strings.Repeat("-", 40))
		fmt.Fprintln(w, "  • New to Chain305?  run `chainsaw setup`")
		fmt.Fprintln(w, "  • Already have an API key?  run `chainsaw auth login --token <KEY>`")
		fmt.Fprintln(w, "  • Running headless (CI, SSH, agent)?  add `--device` to auth login")
		fmt.Fprintln(w, "  • Want the JSON catalog?  run `chainsaw introduce --json`")
		fmt.Fprintln(w)
	}
	emit("cli.introduce.shown", nil)
	return nil
}

// wrapLines word-wraps at the given column, respecting an indent on
// every line after the first. Deliberately simple — we don't need to
// handle CJK widths or embedded ANSI.
func wrapLines(s string, width int, indent string) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var lines []string
	current := words[0]
	for _, word := range words[1:] {
		if len(current)+1+len(word) > width {
			lines = append(lines, current)
			current = word
		} else {
			current += " " + word
		}
	}
	lines = append(lines, current)
	// Prepend indent to lines after the first.
	for i := 1; i < len(lines); i++ {
		lines[i] = indent + lines[i]
	}
	return lines
}

func renderMentalModels(w io.Writer) {
	fmt.Fprintln(w, "Personas — which one sounds like you?")
	fmt.Fprintln(w, strings.Repeat("-", 40))
	fmt.Fprintln(w, "Five people walk into Chain305. Pick the role that matches — it")
	fmt.Fprintln(w, "decides which workflow you want and which key to mint.")
	fmt.Fprintln(w)
	for _, m := range agenticux.MentalModels() {
		label := personaLabel(m.Persona)
		fmt.Fprintf(w, "• %s\n", label)
		fmt.Fprintf(w, "    thinks:      %s\n", m.Head)
		fmt.Fprintf(w, "    asks for:    %s\n", m.Utterance)
		fmt.Fprintf(w, "    wants:       %s\n", m.Success)
		if m.Mode != "" {
			fmt.Fprintf(w, "    → Mode %s, preset %s\n", m.Mode, m.Preset)
		}
		fmt.Fprintln(w)
	}
}

func renderModes(w io.Writer) {
	fmt.Fprintln(w, "Workflows — what are you trying to do?")
	fmt.Fprintln(w, strings.Repeat("-", 40))
	fmt.Fprintln(w, "Two workflows. Pick the one that matches your goal; each has its")
	fmt.Fprintln(w, "own API-key preset so you only get the permissions you need.")
	fmt.Fprintln(w)
	for _, m := range agenticux.Modes() {
		fmt.Fprintf(w, "Mode %s — %s\n", m.Tag, m.Title)
		for _, line := range wrapLines(m.Summary, 72, "    ") {
			fmt.Fprintf(w, "    %s\n", line)
		}
		fmt.Fprintf(w, "    preset:    %s\n", m.PresetName)
		fmt.Fprintf(w, "    tools:     %s\n", strings.Join(m.Tools, ", "))
		fmt.Fprintln(w)
	}
}

func renderVocabulary(w io.Writer) {
	fmt.Fprintln(w, "Glossary — what the terms mean")
	fmt.Fprintln(w, strings.Repeat("-", 40))
	for _, v := range agenticux.Vocabulary() {
		fmt.Fprintf(w, "• %s\n", v.Term)
		for _, line := range wrapLines(v.Meaning, 72, "    ") {
			fmt.Fprintf(w, "    %s\n", line)
		}
		if len(v.Synonyms) > 0 {
			fmt.Fprintf(w, "    also called: %s\n", strings.Join(v.Synonyms, ", "))
		}
		fmt.Fprintln(w)
	}
}

func renderRoutingHeuristics(w io.Writer) {
	fmt.Fprintln(w, "Examples — common requests and what to do")
	fmt.Fprintln(w, strings.Repeat("-", 40))
	for _, h := range agenticux.RoutingHeuristics() {
		for _, line := range wrapLines("when "+h.Match, 72, "    ") {
			fmt.Fprintf(w, "  %s\n", line)
		}
		for _, line := range wrapLines("→ "+h.Do, 72, "      ") {
			fmt.Fprintf(w, "    %s\n", line)
		}
		fmt.Fprintln(w)
	}
}

// personaLabel converts a canonical persona ID into the human-readable
// label the CLI shows. Kept in the CLI (not agenticux) because it's a
// presentation decision — the MCP response uses the raw IDs so agents
// can pattern-match them without translation.
func personaLabel(id string) string {
	switch id {
	case agenticux.PersonaEndUserDev:
		return "End-user developer"
	case agenticux.PersonaAppSec:
		return "AppSec"
	case agenticux.PersonaDevSecOps:
		return "DevSecOps / Platform"
	case agenticux.PersonaEnterpriseIT:
		return "Enterprise IT / Governance"
	case agenticux.PersonaAgent:
		return "Agent-as-persona (that's you, if you're an AI)"
	default:
		return id
	}
}
