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
	policyEvalCmd.Flags().String("input", "", "Path to a JSON input fixture (matches internal/policy/schema/input.schema.json)")
	_ = policyEvalCmd.MarkFlagRequired("bundle")
	_ = policyEvalCmd.MarkFlagRequired("input")
	policyCmd.AddCommand(policyEvalCmd)

	policyGateCmd.Flags().StringVar(&policyDSLBundle, "bundle", "", "Path to a directory or .rego file containing the policy bundle (required)")
	policyGateCmd.Flags().String("input", "", "Path to a JSON input fixture (the surface stamps its own surface tag)")
	policyGateCmd.Flags().Bool("json", false, "Emit the full decision as JSON to stdout")
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
		return cliExitErr(2, "compile bundle: %v", err)
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

	switch dec.Action {
	case dsl.ActionBlock, dsl.ActionQuarantine:
		os.Exit(1)
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
		return cliExitErr(2, "unknown surface %q — must be one of: pr, proxy, publish, promote, deploy, runtime", string(surface))
	}

	bundle, _ := cmd.Flags().GetString("bundle")
	inputPath, _ := cmd.Flags().GetString("input")
	asJSON, _ := cmd.Flags().GetBool("json")

	eng, err := policyDSLLoader.Load(context.Background(), []string{bundle})
	if err != nil {
		return cliExitErr(2, "compile bundle: %v", err)
	}

	in, err := readInputFixture(inputPath)
	if err != nil {
		return cliExitErr(2, "read input: %v", err)
	}
	in.Surface = surface

	facade := policyengine.New(policyengine.Config{DSL: eng})
	// Translate Input back into EvaluationContext: only the fields
	// the facade reads via ContextToInput need to be populated, but
	// for `gate` we treat the JSON input as the source of truth and
	// hand it straight to the dsl engine. Re-marshal once through
	// the facade's path so audit logging still names the bundle.
	dec, err := facade.Decide(context.Background(), surface, inputToContext(in))
	if err != nil {
		return cliExitErr(2, "decide: %v", err)
	}

	if asJSON {
		out, _ := json.MarshalIndent(dec, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "surface=%s action=%s violations=%d bundle=%s\n",
			dec.Surface, dec.Action, len(dec.Violations), shortDigest(dec.BundleDigest))
		for _, v := range dec.Violations {
			fmt.Fprintf(cmd.OutOrStdout(), "  - [%s] %s — %s\n", v.Action, v.RuleID, v.Message)
		}
	}

	switch dec.Action {
	case dsl.ActionBlock, dsl.ActionQuarantine:
		os.Exit(1)
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

// inputToContext is the inverse of policy.ContextToInput, used by the
// CLI gate command to bridge the on-disk JSON shape back into the
// EvaluationContext the facade expects. Only the fields the facade
// actually projects need to round-trip; the rest are zero-valued.
func inputToContext(in policy.Input) policy.EvaluationContext {
	return policy.EvaluationContext{
		Repository:                   in.Repository,
		RepositoryFormat:             in.RepositoryFormat,
		PackageName:                  in.PackageName,
		PackageVersion:               in.PackageVersion,
		ClientID:                     in.ClientID,
		ClientGroups:                 in.ClientGroups,
		RequestingIP:                 in.RequestingIP,
		RequestingCountry:            in.RequestingCountry,
		IsInternalPackage:            in.IsInternal,
		LicenseSPDX:                  in.LicenseSPDX,
		LicenseTags:                  in.LicenseTags,
		IsVulnerable:                 in.IsVulnerable,
		CVSSScore:                    in.CVSSScore,
		EPSSScore:                    in.EPSSScore,
		CVEs:                         in.CVEs,
		HasProvenance:                in.HasProvenance,
		ProvenanceStatus:             in.ProvenanceStatus,
		IsSuspectedTyposquat:         in.IsSuspectedTyposquat,
		IsKnownMalicious:             in.IsKnownMalicious,
		TrustScore:                   in.TrustScore,
		PublisherChanged:             in.PublisherChanged,
		SLSALevel:                    in.SLSALevel,
		AttestationBuilderID:         in.AttestationBuilderID,
		AttestationIssuer:            in.AttestationIssuer,
		AttestationSourceRepo:        in.AttestationSourceRepo,
		AttestationTransparencyLog:   in.AttestationTransparencyLog,
		AttestationCacheStale:        in.AttestationCacheStale,
		HasInstallScript:             in.HasInstallScript,
		InstallScriptFetchesRemote:   in.InstallScriptFetchesRemote,
		VersionAnomaly:               in.VersionAnomaly,
		VersionAnomalyFlags:          in.VersionAnomalyFlags,
		HasHiddenUnicode:             in.HasHiddenUnicode,
		HiddenUnicodeKinds:           in.HiddenUnicodeKinds,
		PublishVelocity24h:           in.PublishVelocity24h,
		DeprecatedByMaintainer:       in.DeprecatedByMaintainer,
		ShrinkwrapPresent:            in.ShrinkwrapPresent,
		ManifestConfusion:            in.ManifestConfusion,
		GitDependency:                in.GitDependency,
		HTTPTarballDependency:        in.HTTPTarballDependency,
		WildcardDependencyRange:      in.WildcardDependencyRange,
		BadDependencySemver:          in.BadDependencySemver,
		UsesEval:                     in.UsesEval,
		NetworkAccess:                in.NetworkAccess,
		ShellAccess:                  in.ShellAccess,
		FilesystemAccess:             in.FilesystemAccess,
		EnvVarAccess:                 in.EnvVarAccess,
		NativeBinaryPresent:          in.NativeBinaryPresent,
		HighEntropyStrings:           in.HighEntropyStrings,
		URLStrings:                   in.URLStrings,
		MinifiedCode:                 in.MinifiedCode,
		TrivialPackage:               in.TrivialPackage,
		TooManyFiles:                 in.TooManyFiles,
		NonExistentAuthor:            in.NonExistentAuthor,
		FirstTimeCollaborator:        in.FirstTimeCollaborator,
		SuspiciousRepoStars:          in.SuspiciousRepoStars,
		MaintainerAccountAgeDays:     in.MaintainerAccountAgeDays,
		ArtifactSubtype:              in.ArtifactSubtype,
		DangerousPickle:              in.DangerousPickle,
		UnsafeSerializationFormat:    in.UnsafeSerializationFormat,
		ModelCardInjection:           in.ModelCardInjection,
		AgentToolDangerousCapability: in.AgentToolDangerousCapability,
		MCPServerDeclared:            in.MCPServerDeclared,
		PromptTemplateInjection:      in.PromptTemplateInjection,
		ChecksumUnavailable:          in.ChecksumUnavailable,
	}
}

func cliExitErr(code int, format string, args ...any) error {
	fmt.Fprintf(os.Stderr, "chainsaw policy: "+format+"\n", args...)
	os.Exit(code)
	return nil
}

func shortDigest(d string) string {
	if len(d) <= 12 {
		return d
	}
	return d[:12]
}
