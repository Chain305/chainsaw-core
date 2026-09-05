package cli

// `chainsaw intel package <ecosystem> <name> <version>` — single-package
// lookup against GET /api/v1/intel/packages/{eco}/{name}/{version}. Text
// output renders the Verdict banner + per-category breakdown + resolution
// advice; --json emits the full v1 envelope so CI pipelines can treat the
// endpoint as a structured source.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/intelligence"
)

var intelPackageCmd = &cobra.Command{
	Use:   "package <ecosystem> <name> <version>",
	Short: "Fetch the risk evaluation for a single package version",
	Long: `Look up one package against the risk engine. Supports npm scoped names
and any ecosystem the server recognises.

Examples:
  chainsaw intel package npm lodash 4.17.21
  chainsaw intel package npm @babel/core 7.24.0
  chainsaw intel package pypi requests 2.32.3 --json

Exit codes:
  0  success (any verdict — the verdict is in the output, not the exit code)
  2  server unreachable, or it answered with an error
  3  no server configured, or not authenticated
  4  bad invocation`,
	Args: cobra.ExactArgs(3),
	RunE: runIntelPackage,
}

func init() {
	intelCmd.AddCommand(intelPackageCmd)
}

func runIntelPackage(cmd *cobra.Command, args []string) error {
	key := v1IntelKey{Ecosystem: args[0], Package: args[1], Version: args[2]}
	client, err := newV1Client(cmd)
	if err != nil {
		// Classify via Execute(): auth → 3, network/IO → 2 (invariant B).
		return err
	}
	ctx := context.Background()
	data, env, err := client.GetPackage(ctx, key)
	if err != nil {
		return err
	}

	if useJSON(cmd) {
		// Echo the complete envelope shape so downstream tooling sees
		// warnings + meta too, not just the stripped `data` block.
		return PrintJSONTo(cmd, map[string]any{
			"apiVersion":    env.APIVersion,
			"engineVersion": env.EngineVersion,
			"data": map[string]any{
				"report": json.RawMessage(data.Report),
				"risk":   data.Risk,
			},
			"warnings": env.Warnings,
			"meta":     env.Meta,
		})
	}

	printLatestResolutionNotice(os.Stdout, key, data.Risk)
	renderEvaluation(os.Stdout, data.Risk, federatedAbsenceNote(data.Report))
	return nil
}

// federatedAbsenceNote decodes just enough of the report to ask the one
// question the A7 display override needs: did a federated registry come
// back empty-handed for this coordinate? The predicate lives in
// core/intelligence so the CLI and the server cannot drift on what counts.
//
// A report we cannot parse yields no note, and the normal grade line is
// printed — a display nicety must never swallow the result.
func federatedAbsenceNote(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var rep intelligence.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return ""
	}
	note, _ := intelligence.FederatedRegistryAbsence(&rep)
	return note
}

// printLatestResolutionNotice tells the user which concrete version the
// verdict below actually describes, when the server dereferenced a
// dist-tag on their behalf (P8-45).
//
// This is not cosmetic. `chainsaw intel package npm lodash latest` now
// returns a scored verdict rather than NOT EVALUATED, and an ALLOW must
// never be attributed to a coordinate the user did not ask about: the tag
// moves, so the same command tomorrow describes different bytes. Printing
// the substitution is what keeps the answer attributable — and it is the
// only place the user's literal input still appears, because the stored
// report is deliberately keyed on the resolved version.
//
// Silent whenever the server answered about the coordinate that was asked
// for, which is every request that did not name a dist-tag.
func printLatestResolutionNotice(w io.Writer, asked v1IntelKey, eval *v1Evaluation) {
	if eval == nil {
		return
	}
	got := strings.TrimSpace(eval.Key.Version)
	if got == "" || got == strings.TrimSpace(asked.Version) {
		return
	}
	fmt.Fprintf(w, "Resolved %s → %s (the registry's current %q tag)\n\n",
		asked.Version, got, asked.Version)
}
