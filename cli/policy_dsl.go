package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/policy"
	"github.com/chain305/chainsaw-core/policy/dsl"
	"github.com/chain305/chainsaw-core/policyengine"
)

// `chainsaw policy eval` and `chainsaw policy gate` — the two
// surfaces for the unified DSL that don't require a running server.
// `eval` is the rule-author dev loop; `gate` is what every CI / git
// hook / k8s webhook calls into for a "block-or-allow" decision.

var policyDSLBundle string

// policyDSLLoader is the loader seam the CLI compiles bundles through.
// The dev-loop commands (`policy eval` / `policy gate`) use the free
// DefaultLoader — bundle provenance is the operator's responsibility in
// the local author loop. Depending on dsl.Loader here (not dsl.New
// directly) keeps the CLI swappable onto a verifying loader without
// touching these command bodies.
var policyDSLLoader dsl.Loader = dsl.DefaultLoader{}

var policyEvalCmd = &cobra.Command{
	Use:   "eval",
	Short: "Evaluate a Rego policy bundle against a JSON input fixture",
	Long: `Evaluate a chainsaw.policy Rego bundle against a JSON fixture in the canonical
input shape (internal/policy/schema/input.schema.json).

Designed for the rule-author dev loop:

  chainsaw policy eval --bundle ./policies --input fixtures/young-maintainer.json

Exit codes:
  0  decision is allow or monitor
  1  decision is block or quarantine
  2  evaluation error (syntax error in rego, malformed input, etc.)`,
	RunE: runPolicyEval,
}

var policyGateCmd = &cobra.Command{
	Use:   "gate <surface>",
	Short: "Run a policy decision for one of the six enforcement surfaces",
	Long: `Run the unified policy DSL decision for an enforcement surface.

Surface must be one of: pr, proxy, publish, promote, deploy, runtime.

This is the entry point every chainsaw CI / git hook / k8s webhook /
package-manager hook calls into. The same Rego rule in --bundle fires
at every surface where its input fields are populated.

  chainsaw policy gate proxy --bundle ./policies --input event.json
  chainsaw policy gate pr     --bundle ./policies --input pr.json

Exit codes match` + " `chainsaw policy eval`" + ` so callers can wire the same
exit-code → CI-status mapping at every surface.`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyGate,
}

func init() {
	policyEvalCmd.Flags().StringVar(&policyDSLBundle, "bundle", "", "Path to a directory or .rego file containing the policy bundle (required)")
	policyEvalCmd.Flags().String("input", "", "Path to a JSON input fixture (matches internal/policy/schema/input.schema.json) (required)")
	_ = policyEvalCmd.MarkFlagRequired("bundle")
	_ = policyEvalCmd.MarkFlagRequired("input")
	policyCmd.AddCommand(policyEvalCmd)

	policyGateCmd.Flags().StringVar(&policyDSLBundle, "bundle", "", "Path to a directory or .rego file containing the policy bundle (required)")
	policyGateCmd.Flags().String("input", "", "Path to a JSON input fixture (the surface stamps its own surface tag) (required)")
	// No local --json: runPolicyGate resolves the format through useJSON(cmd),
	// which reads the root persistent --json (root.go:624) and --format
	// (root.go:642) alike. A local bool shadowed the persistent one with
	// identical semantics while quietly making `--format json` a no-op on this
	// one command. Removing it is the opposite of the repo.go:90-98 case: there
	// the local flag changed MEANING, so it had to be renamed rather than
	// deleted; here it means exactly the same thing, so it is just redundant.
	_ = policyGateCmd.MarkFlagRequired("bundle")
	_ = policyGateCmd.MarkFlagRequired("input")
	policyCmd.AddCommand(policyGateCmd)
}

// runPolicyEval is the rule-authoring command. It loads the bundle,
// reads the input verbatim (no surface stamping), prints the decision.
func runPolicyEval(cmd *cobra.Command, _ []string) error {
	bundle, _ := cmd.Flags().GetString("bundle")
	inputPath, _ := cmd.Flags().GetString("input")

	eng, err := policyDSLLoader.Load(context.Background(), []string{bundle})
	if err != nil {
		// Name the bundle root and surface the loader's diagnostic verbatim;
		// the wrapped OPA error already carries the offending .rego file:line.
		return cliExitErr(2, "compile bundle %s: %v", bundle, err)
	}
	if eng.Empty() {
		return cliExitErr(2, "bundle %s contains no rego sources", bundle)
	}

	in, err := readInputFixture(inputPath)
	if err != nil {
		return cliExitErr(2, "read input: %v", err)
	}

	dec, err := eng.Decide(context.Background(), in)
	if err != nil {
		return cliExitErr(2, "evaluate: %v", err)
	}

	out, _ := json.MarshalIndent(dec, "", "  ")
	fmt.Fprintln(cmd.OutOrStdout(), string(out))

	// Y3/Y4 — a block is the EXPECTED enforcement outcome, so it keeps exit 1
	// (ExitBlocked) and every existing block-gating script is unchanged. It is
	// RETURNED so Execute() can flush telemetry: the bare os.Exit dropped the
	// whole batch, including the session-completed event that records the
	// block. Err is nil — the decision JSON above is the user-facing reason.
	switch dec.Action {
	case dsl.ActionBlock, dsl.ActionQuarantine:
		return &ExitCodeError{Code: ExitBlocked}
	}
	return nil
}

// runPolicyGate is the surface-aware command — the entry point every
// PR check / proxy fetch / publish hook / promotion gate / deploy
// admission webhook / runtime install hook ultimately calls.
func runPolicyGate(cmd *cobra.Command, args []string) error {
	surface := policy.SurfaceTag(args[0])
	valid := false
	for _, s := range policy.AllSurfaces() {
		if s == surface {
			valid = true
			break
		}
	}
	if !valid {
		// ExitUsage, not ExitOpError: an unrecognised surface name is a bad
		// argument shape, which exitcodes.go assigns to 4. Exiting 2 here told
		// CI "infrastructure trouble" for what is a typo in the invocation.
		return cliExitErr(ExitUsage, "unknown surface %q — must be one of: pr, proxy, publish, promote, deploy, runtime", string(surface))
	}

	bundle, _ := cmd.Flags().GetString("bundle")
	inputPath, _ := cmd.Flags().GetString("input")
	asJSON := useJSON(cmd)

	eng, err := policyDSLLoader.Load(context.Background(), []string{bundle})
	if err != nil {
		// Name the bundle root and surface the loader's diagnostic verbatim;
		// the wrapped OPA error already carries the offending .rego file:line.
		return cliExitErr(2, "compile bundle %s: %v", bundle, err)
	}

	in, err := readInputFixture(inputPath)
	if err != nil {
		return cliExitErr(2, "read input: %v", err)
	}
	in.Surface = surface

	facade := policyengine.New(policyengine.Config{DSL: eng})
	// The fixture IS the input. DecideInput hands `in` to OPA
	// unchanged, so `gate` and `eval` evaluate byte-identical
	// documents; the facade still stamps the bundle digest for audit.
	//
	// This used to detour through an inputToContext() copy that
	// rebuilt an EvaluationContext only for the facade to project it
	// straight back into an Input. The copy fell three fields behind
	// policy.Input — signalsUnavailable, releaseDate, buildRsExecutes —
	// so a fail-closed rule keyed on `input.signalsUnavailable` blocked
	// under `eval` and allowed under `gate`. Do not reintroduce a
	// translation layer here: TestPolicyGateInputFidelity fails if the
	// input OPA sees is not the input the fixture declared.
	dec, err := facade.DecideInput(context.Background(), in)
	if err != nil {
		return cliExitErr(2, "decide: %v", err)
	}

	if asJSON {
		// Honor --output (invariant C): JSON result to the file when set.
		out, _ := json.MarshalIndent(dec, "", "  ")
		fmt.Fprintln(outWriterOr(cmd, cmd.OutOrStdout()), string(out))
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "surface=%s action=%s violations=%d bundle=%s\n",
			dec.Surface, dec.Action, len(dec.Violations), shortDigest(dec.BundleDigest))
		for _, v := range dec.Violations {
			fmt.Fprintf(cmd.OutOrStdout(), "  - [%s] %s — %s\n", v.Action, v.RuleID, v.Message)
		}
	}

	// Same contract as runPolicyEval above: ExitBlocked(1), returned so the
	// telemetry batch survives. The surface/action/violations lines printed
	// above are the block reason, so Err stays nil.
	switch dec.Action {
	case dsl.ActionBlock, dsl.ActionQuarantine:
		return &ExitCodeError{Code: ExitBlocked}
	}
	return nil
}

func readInputFixture(path string) (policy.Input, error) {
	var in policy.Input
	data, err := os.ReadFile(path)
	if err != nil {
		return in, err
	}
	if err := json.Unmarshal(data, &in); err != nil {
		return in, fmt.Errorf("decode input: %w", err)
	}
	return in, nil
}

// cliExitErr builds the error a policy command returns for an operational
// failure at a specific exit code.
//
// Y3/Y4: it used to print to stderr and call os.Exit(code) from inside the
// RunE, which returned a zero error to cobra on a path that never actually
// returned — bypassing Execute()'s exit-code mapping and dropping the whole
// telemetry batch. The message is now carried on the error and printed by
// renderError, which keeps a single stderr format for every CLI failure; the
// "chainsaw policy:" prefix is preserved so existing log greps still match.
func cliExitErr(code int, format string, args ...any) error {
	return &ExitCodeError{Code: code, Err: fmt.Errorf("chainsaw policy: "+format, args...)}
}

func shortDigest(d string) string {
	if len(d) <= 12 {
		return d
	}
	return d[:12]
}
