package cli

// `chainsaw intel signals` — lists the signal catalogue, grouped by
// category. Helpful both for policy authors (who want to know which IDs
// they can reference) and for operators who want to audit what the risk
// engine is evaluating on their behalf.
//
// THIS COMMAND DOES NOT REQUIRE A SERVER. It used to: runIntelSignals went
// through newV1Client, which refuses without a base URL and a token, so an
// unauthenticated user could not read a list of signal IDs. But the
// catalogue is static compiled-in data — the server handler
// (handleV1IntelSignals) does nothing but map risk.AllSignals() with no DB
// read and no org lookup, and this binary already links core/risk (pulled in
// via intelligence and githubactions), so the exact same table is sitting in
// the process that just refused to print it.
//
// What the round-trip DOES buy is the SERVER's catalogue, which is the one
// that will actually judge your packages. When the CLI and the server are on
// different builds those two tables can disagree. So:
//
//   - server configured and authenticated → ask the server (authoritative)
//   - otherwise, or with --local          → print the linked catalogue
//
// and either way the output SAYS which one it is. Presenting the local table
// as though it came from the server would be the one genuinely harmful
// outcome here: a policy author would go on to reference an ID the server has
// never heard of, and find out at enforcement time.

import (
	"context"
	"fmt"
	"io"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/risk"
)

// signalSource records where a rendered catalogue came from, so the renderer
// can label it and --json can carry it in a machine-readable field.
type signalSource string

const (
	signalSourceServer signalSource = "server"
	signalSourceLocal  signalSource = "local"
)

// localCatalogueNote is the one-line caveat printed under a local listing.
const localCatalogueNote = "No server was contacted. A server on a different build may register a different set."

var intelSignalsCmd = &cobra.Command{
	Use:   "signals",
	Short: "List registered signals grouped by category",
	Long: `Print every risk signal the engine can register, grouped by category and
sorted by severity within each group. Use --json to round-trip the full
catalogue (e.g. to generate policy templates).

Works offline. The catalogue is static data compiled into this binary, so no
server or token is needed. When a server IS configured and you are
authenticated, its catalogue is fetched instead — it is the one that will
actually judge your packages, and it can differ from this build's if the two
have drifted. The output always states which of the two you are looking at;
--local forces the compiled-in one.

Exit codes:
  0  catalogue printed (from either source)
  2  a configured server was contacted and failed
  3  auth was rejected by a configured server`,
	RunE: runIntelSignals,
}

func init() {
	intelSignalsCmd.Flags().Bool("local", false,
		"print the catalogue compiled into this CLI without contacting the server")
	intelCmd.AddCommand(intelSignalsCmd)
}

func runIntelSignals(cmd *cobra.Command, _ []string) error {
	localOnly, _ := cmd.Flags().GetBool("local")

	if !localOnly {
		// newV1Client's error means "no server URL" or "no token" — a
		// configuration state, not a failure. Fall back rather than refuse.
		// A network error from Signals() below is NOT treated the same way:
		// once you have pointed the CLI at a server, silently answering from
		// a different table because the server was unreachable would hide an
		// outage behind a plausible-looking answer. Say so, and point at
		// --local.
		if client, cerr := newV1Client(cmd); cerr == nil {
			// Bound the call so a black-holed server can't hang the CLI —
			// 10s, matching `intel health`. Context() is nil when RunE is
			// invoked directly (tests), so fall back to Background.
			base := cmd.Context()
			if base == nil {
				base = context.Background()
			}
			ctx, cancel := context.WithTimeout(base, 10*time.Second)
			defer cancel()

			sigs, env, err := client.Signals(ctx)
			if err != nil {
				fmt.Fprintln(cmd.ErrOrStderr(),
					"hint: 'chainsaw intel signals --local' prints the catalogue compiled into this CLI, with no server")
				return err
			}
			return emitSignals(cmd, sigs, signalSourceServer, env)
		}
	}

	return emitSignals(cmd, localSignals(), signalSourceLocal, nil)
}

// localSignals maps the compiled-in registry onto the same wire shape the
// server returns. Deliberately the same field-for-field mapping as
// server.handleV1IntelSignals so the two renderings are comparable; if that
// handler ever starts applying org weight overrides (it does not today — it
// emits raw ship defaults), this is the copy that will need a note saying so.
func localSignals() []v1SignalSummary {
	all := risk.AllSignals()
	out := make([]v1SignalSummary, 0, len(all))
	for _, s := range all {
		out = append(out, v1SignalSummary{
			ID:          s.ID,
			Category:    string(s.Category),
			Severity:    string(s.Severity),
			Weight:      s.Weight,
			Title:       s.Title,
			Description: s.Description,
		})
	}
	return out
}

// emitSignals renders the catalogue in whichever format was asked for,
// carrying the source label into both. env is nil for the local source.
func emitSignals(cmd *cobra.Command, sigs []v1SignalSummary, src signalSource, env *v1Envelope) error {
	if useJSON(cmd) {
		// "source" is additive: every key the server path emitted before is
		// still emitted with the same meaning, so existing consumers keep
		// working and only gain the ability to tell the two apart.
		payload := map[string]any{
			"source": string(src),
			"data":   sigs,
		}
		if env != nil {
			payload["apiVersion"] = env.APIVersion
			payload["engineVersion"] = env.EngineVersion
			payload["warnings"] = env.Warnings
			payload["meta"] = env.Meta
		} else {
			payload["engineVersion"] = risk.EngineVersion
			payload["cliVersion"] = resolveVersion().Version
			payload["warnings"] = []string{localCatalogueNote}
			payload["meta"] = v1Meta{ProcessedCount: len(sigs)}
		}
		return PrintJSONTo(cmd, payload)
	}

	renderSignals(cmd.OutOrStdout(), sigs, src, env)
	return nil
}

// sevRank mirrors risk.Severity.Rank() so we can sort without importing
// the risk package. Unknown → -1, sinks to the bottom of its group.
func sevRank(s string) int {
	switch s {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	case "info":
		return 0
	}
	return -1
}

// signalsHeader is the provenance line. It is printed FIRST and
// unconditionally: a reader who scrolls past it still has it in scrollback,
// and a reader who pipes to head still sees it.
func signalsHeader(sigs []v1SignalSummary, src signalSource, env *v1Envelope) string {
	if src == signalSourceLocal {
		return fmt.Sprintf("Signal catalogue — LOCAL: compiled into this CLI (chainsaw %s, risk engine v%s), %d signals\n%s\n",
			resolveVersion().Version, risk.EngineVersion, len(sigs), localCatalogueNote)
	}
	engine := ""
	if env != nil && env.EngineVersion != "" {
		engine = " v" + env.EngineVersion
	}
	return fmt.Sprintf("Signal catalogue — SERVER: risk engine%s, %d signals\n", engine, len(sigs))
}

func renderSignals(w io.Writer, sigs []v1SignalSummary, src signalSource, env *v1Envelope) {
	fmt.Fprintln(w, signalsHeader(sigs, src, env))

	// Group by category. Iterate in the stable categoryOrder so CLI
	// output doesn't churn run-to-run — a silent re-ordering would
	// frustrate diff-based review of policy authoring sessions.
	byCat := make(map[string][]v1SignalSummary, len(categoryOrder))
	for _, s := range sigs {
		byCat[s.Category] = append(byCat[s.Category], s)
	}
	// Any server-side category we don't know about goes under a
	// final "other" bucket so rollouts of new categories don't cause
	// signals to silently vanish from the CLI.
	knownCats := make(map[string]bool, len(categoryOrder))
	for _, c := range categoryOrder {
		knownCats[c] = true
	}
	extraCats := make([]string, 0)
	for c := range byCat {
		if !knownCats[c] {
			extraCats = append(extraCats, c)
		}
	}
	sort.Strings(extraCats)

	order := append([]string(nil), categoryOrder...)
	order = append(order, extraCats...)

	for _, cat := range order {
		list, ok := byCat[cat]
		if !ok || len(list) == 0 {
			continue
		}
		// Within a category, sort by severity desc then ID asc.
		sort.Slice(list, func(i, j int) bool {
			if a, b := sevRank(list[i].Severity), sevRank(list[j].Severity); a != b {
				return a > b
			}
			return list[i].ID < list[j].ID
		})
		label, known := categoryLabel[cat]
		if !known {
			label = cat
		}
		fmt.Fprintf(w, "%s (%d)\n", trimLabel(label), len(list))
		for _, s := range list {
			fmt.Fprintf(w, "  [%-8s] %-28s — %s (w=%.2f)\n",
				s.Severity, s.ID, s.Title, s.Weight)
		}
		fmt.Fprintln(w)
	}
}

// trimLabel strips the padding from categoryLabel — the padded form is
// tuned for column alignment in `intel package`, while the signals
// header looks cleaner without trailing spaces.
func trimLabel(s string) string {
	out := s
	for len(out) > 0 && out[len(out)-1] == ' ' {
		out = out[:len(out)-1]
	}
	return out
}
