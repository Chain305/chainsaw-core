package cli

// `chainsaw intel health` — quick one-shot against /api/v1/intel/health so
// operators can confirm the engine is reachable and on the expected
// version before running a scan.

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var intelHealthCmd = &cobra.Command{
	Use:   "health",
	Short: "Ping the risk engine and print its version + signal count",
	Long: `Verify the v1 risk-intelligence API is reachable. Prints engine version,
how many signals are registered, and the list of categories.

Exit codes:
  0  engine reachable and healthy
  2  HTTP / auth / unreachable`,
	RunE: runIntelHealth,
}

func init() {
	intelCmd.AddCommand(intelHealthCmd)
}

func runIntelHealth(cmd *cobra.Command, _ []string) error {
	client, err := newV1Client()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}
	ctx := context.Background()
	h, env, err := client.Health(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	if useJSON(cmd) {
		return PrintJSON(map[string]any{
			"apiVersion":    env.APIVersion,
			"engineVersion": env.EngineVersion,
			"data":          h,
			"warnings":      env.Warnings,
			"meta":          env.Meta,
		})
	}

	fmt.Printf("Engine: v%s\n", h.EngineVersion)
	fmt.Printf("Signals: %d\n", h.SignalCount)
	fmt.Printf("Categories: %s\n", strings.Join(h.Categories, ", "))
	return nil
}
