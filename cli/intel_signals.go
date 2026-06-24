package cli

// `chainsaw intel signals` — lists the signal catalogue, grouped by
// category. Helpful both for policy authors (who want to know which IDs
// they can reference) and for operators who want to audit what the risk
// engine is evaluating on their behalf.

import (
	"context"
	"fmt"
	"os"
	"sort"

	"github.com/spf13/cobra"
)

var intelSignalsCmd = &cobra.Command{
	Use:   "signals",
	Short: "List registered signals grouped by category",
	Long: `Print every risk signal the server has registered, grouped by category
and sorted by severity within each group. Use --json to round-trip the
full catalogue (e.g. to generate policy templates).`,
	RunE: runIntelSignals,
}

func init() {
	intelCmd.AddCommand(intelSignalsCmd)
}

func runIntelSignals(cmd *cobra.Command, _ []string) error {
	client, err := newV1Client()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	ctx := context.Background()
	sigs, env, err := client.Signals(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if useJSON(cmd) {
		return PrintJSON(map[string]any{
			"apiVersion":    env.APIVersion,
			"engineVersion": env.EngineVersion,
			"data":          sigs,
			"warnings":      env.Warnings,
			"meta":          env.Meta,
		})
	}

	renderSignals(sigs)
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

func renderSignals(sigs []v1SignalSummary) {
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
		fmt.Printf("%s (%d)\n", trimLabel(label), len(list))
		for _, s := range list {
			fmt.Printf("  [%-8s] %-28s — %s (w=%.2f)\n",
				s.Severity, s.ID, s.Title, s.Weight)
		}
		fmt.Println()
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
