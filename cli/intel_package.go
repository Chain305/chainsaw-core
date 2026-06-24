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
	"os"

	"github.com/spf13/cobra"
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
  0  success (any verdict)
  2  HTTP / usage error`,
	Args: cobra.ExactArgs(3),
	RunE: runIntelPackage,
}

func init() {
	intelCmd.AddCommand(intelPackageCmd)
}

func runIntelPackage(cmd *cobra.Command, args []string) error {
	key := v1IntelKey{Ecosystem: args[0], Package: args[1], Version: args[2]}
	client, err := newV1Client()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	ctx := context.Background()
	data, env, err := client.GetPackage(ctx, key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if useJSON(cmd) {
		// Echo the complete envelope shape so downstream tooling sees
		// warnings + meta too, not just the stripped `data` block.
		return PrintJSON(map[string]any{
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

	renderEvaluation(os.Stdout, data.Risk)
	return nil
}
