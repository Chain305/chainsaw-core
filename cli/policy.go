package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

// policyItem mirrors the policy.Policy JSON returned by the server.
type policyItem struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Precedence  int             `json:"precedence"`
	Mode        string          `json:"mode"`
	Status      string          `json:"status"`
	CreatedAt   time.Time       `json:"createdAt"`
	UpdatedAt   time.Time       `json:"updatedAt"`
	Conditions  json.RawMessage `json:"conditions,omitempty"`
	Scope       json.RawMessage `json:"scope,omitempty"`
	Identifier  json.RawMessage `json:"identifier,omitempty"`
}

var policyCmd = &cobra.Command{
	Use:   "policy",
	Short: "Manage release policies",
	Long: `Manage release policies for your org — list, create, simulate, and back them up.

Examples:
  chainsaw policy list
  chainsaw policy create --name block-criticals --mode block --condition '{"cvssMin": 9.0}'
  chainsaw policy simulate lodash@4.17.11
  chainsaw policy export --format yaml --output policies.yaml`,
}

// ── list ──────────────────────────────────────────────────────────────────────

var policyListCmd = &cobra.Command{
	Use:   "list",
	Short: "List policies for the current org",
	RunE:  runPolicyList,
}

func init() {
	// --json is a persistent root flag (see root.go); no need to redeclare
	// locally. cmd.Flags().GetBool("json") on the subcommand picks it up.
	policyCmd.AddCommand(policyListCmd)
}

func runPolicyList(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	var resp struct {
		Policies []policyItem `json:"policies"`
	}
	if err := client.Get("/api/policies", &resp); err != nil {
		return err
	}
	emit("cli.policy.listed", nil)

	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(resp.Policies)
	}

	if len(resp.Policies) == 0 {
		fmt.Println("No policies found.")
		return nil
	}
	rows := make([][]string, len(resp.Policies))
	for i, p := range resp.Policies {
		rows[i] = []string{
			p.ID,
			p.Name,
			p.Mode,
			string(p.Status),
			fmt.Sprintf("%d", p.Precedence),
			p.UpdatedAt.Format("2006-01-02"),
		}
	}
	PrintTable([]string{"ID", "NAME", "MODE", "STATUS", "PRIORITY", "UPDATED"}, rows)
	return nil
}

// ── create ────────────────────────────────────────────────────────────────────

var policyCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new policy",
	RunE:  runPolicyCreate,
}

func init() {
	policyCreateCmd.Flags().String("name", "", "Policy name (required)")
	policyCreateCmd.Flags().String("mode", "monitor", "Action mode: allow|monitor|block|quarantine")
	policyCreateCmd.Flags().String("status", "enabled", "Initial status: enabled|disabled")
	policyCreateCmd.Flags().Int("precedence", 100, "Evaluation precedence (lower = higher priority)")
	policyCreateCmd.Flags().String("description", "", "Human-readable description")
	// --condition accepts a JSON object that maps to the Conditions struct, e.g.:
	//   '{"cvssMin": 7.0, "isKnownMalicious": true}'
	policyCreateCmd.Flags().String("condition", "", "Conditions as a JSON object (see docs)")
	addSupplyChainConditionFlags(policyCreateCmd)
	policyCreateCmd.Flags().Bool("json", false, "Print created policy as JSON")
	_ = policyCreateCmd.MarkFlagRequired("name")
	policyCmd.AddCommand(policyCreateCmd)
}

// validVersionAnomalyKinds enumerates the accepted values for the
// versionAnomalyKinds condition. Kept in sync with
// internal/supplychain/metadiff.Flag* — change there, change here.
var validVersionAnomalyKinds = map[string]struct{}{
	"semver_regression":    {},
	"major_skip":           {},
	"timestamp_regression": {},
}

// validHiddenUnicodeKinds enumerates the accepted values for the
// hiddenUnicodeKinds condition. Kept in sync with
// internal/hiddenunicode.Kind* — change there, change here.
var validHiddenUnicodeKinds = map[string]struct{}{
	"zero_width":    {},
	"bidi_override": {},
	"tag":           {},
}

// addSupplyChainConditionFlags registers the convenience flags for the
// 13-PR supply-chain condition set on a cobra command. Shared across
// `policy create` (and available to future `policy update` if added)
// to keep the flag UX in lockstep with the JSON schema.
func addSupplyChainConditionFlags(cmd *cobra.Command) {
	cmd.Flags().Bool("has-install-script", false, "Condition: package declares an install/postinstall lifecycle script")
	cmd.Flags().Bool("install-script-fetches-remote", false, "Condition: install script body references curl/wget/fetch/etc.")
	cmd.Flags().Bool("publisher-changed", false, "Condition: publisher/maintainer set changed vs the prior persisted version")
	cmd.Flags().Bool("version-anomaly", false, "Condition: metadiff flagged any version-sequence anomaly")
	cmd.Flags().String("version-anomaly-kinds", "", "Comma-separated subset: semver_regression,major_skip,timestamp_regression")
	cmd.Flags().Bool("has-hidden-unicode", false, "Condition: artifact contains >=threshold hidden/unicode payload runes")
	cmd.Flags().String("hidden-unicode-kinds", "", "Comma-separated subset: zero_width,bidi_override,tag")
	cmd.Flags().Bool("publish-velocity-anomaly", false, "Condition: publisher exceeded publish velocity threshold in 24h")
	cmd.Flags().Int("publish-velocity-threshold-24h", 0, "Override default 24h publish-velocity threshold (>=1)")
}

// parseCSVKinds splits a comma-separated flag value, trims whitespace,
// lowercases, and de-dupes. Empty input returns nil.
func parseCSVKinds(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, piece := range strings.Split(raw, ",") {
		v := strings.ToLower(strings.TrimSpace(piece))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

// validateKinds returns an error listing any values not in valid. Used
// to fail fast on typos in --version-anomaly-kinds /
// --hidden-unicode-kinds rather than silently creating a condition
// that will never match.
func validateKinds(flagName string, kinds []string, valid map[string]struct{}) error {
	if len(kinds) == 0 {
		return nil
	}
	var bad []string
	for _, k := range kinds {
		if _, ok := valid[k]; !ok {
			bad = append(bad, k)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	allowed := make([]string, 0, len(valid))
	for v := range valid {
		allowed = append(allowed, v)
	}
	sort.Strings(allowed)
	return fmt.Errorf("--%s: unknown value(s) %s; allowed: %s",
		flagName, strings.Join(bad, ", "), strings.Join(allowed, ", "))
}

// applySupplyChainConditionFlags folds the dedicated convenience flags
// into the conditions map that will be posted to the server. It
// preserves any keys already set by --condition (JSON) so operators can
// mix both styles on one invocation.
//
// Precedence rule: the convenience flag wins when both are provided for
// the same condition — the per-flag form is more specific and
// explicitly visible in the invocation history.
func applySupplyChainConditionFlags(cmd *cobra.Command, conditions map[string]any) error {
	if conditions == nil {
		return fmt.Errorf("conditions map is nil") // programmer error
	}

	applyBool := func(flag, key string) {
		if !cmd.Flags().Changed(flag) {
			return
		}
		v, _ := cmd.Flags().GetBool(flag)
		conditions[key] = v
	}

	applyBool("has-install-script", "hasInstallScript")
	applyBool("install-script-fetches-remote", "installScriptFetchesRemote")
	applyBool("publisher-changed", "publisherChanged")
	applyBool("version-anomaly", "versionAnomaly")
	applyBool("has-hidden-unicode", "hasHiddenUnicode")
	applyBool("publish-velocity-anomaly", "publishVelocityAnomaly")

	if cmd.Flags().Changed("version-anomaly-kinds") {
		raw, _ := cmd.Flags().GetString("version-anomaly-kinds")
		kinds := parseCSVKinds(raw)
		if err := validateKinds("version-anomaly-kinds", kinds, validVersionAnomalyKinds); err != nil {
			return err
		}
		conditions["versionAnomalyKinds"] = kinds
	}
	if cmd.Flags().Changed("hidden-unicode-kinds") {
		raw, _ := cmd.Flags().GetString("hidden-unicode-kinds")
		kinds := parseCSVKinds(raw)
		if err := validateKinds("hidden-unicode-kinds", kinds, validHiddenUnicodeKinds); err != nil {
			return err
		}
		conditions["hiddenUnicodeKinds"] = kinds
	}
	if cmd.Flags().Changed("publish-velocity-threshold-24h") {
		n, _ := cmd.Flags().GetInt("publish-velocity-threshold-24h")
		if n < 1 {
			return fmt.Errorf("--publish-velocity-threshold-24h must be >= 1 (got %d)", n)
		}
		conditions["publishVelocityThreshold24h"] = n
	}
	return nil
}

func runPolicyCreate(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	name, _ := cmd.Flags().GetString("name")
	mode, _ := cmd.Flags().GetString("mode")
	status, _ := cmd.Flags().GetString("status")
	prec, _ := cmd.Flags().GetInt("precedence")
	desc, _ := cmd.Flags().GetString("description")
	condJSON, _ := cmd.Flags().GetString("condition")

	body := map[string]any{
		"name":        name,
		"mode":        mode,
		"status":      status,
		"precedence":  prec,
		"description": desc,
	}

	// Build up a conditions map by first parsing --condition (JSON) and
	// then overlaying the dedicated convenience flags. Keeping a single
	// map lets both input styles compose on one invocation without
	// losing fields from either side.
	conditions := map[string]any{}
	if condJSON != "" {
		if err := json.Unmarshal([]byte(condJSON), &conditions); err != nil {
			return fmt.Errorf("--condition is not valid JSON: %w", err)
		}
	}
	if err := applySupplyChainConditionFlags(cmd, conditions); err != nil {
		return err
	}
	if len(conditions) > 0 {
		body["conditions"] = conditions
	}

	var resp struct {
		Policy policyItem `json:"policy"`
	}
	if err := client.Post("/api/policies", body, &resp); err != nil {
		return err
	}

	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		_ = PrintJSON(resp.Policy)
	} else {
		fmt.Printf("Created policy %s (id: %s, mode: %s)\n", resp.Policy.Name, resp.Policy.ID, resp.Policy.Mode)
	}
	emit("cli.policy.created", map[string]any{"policy_kind": resp.Policy.Mode})
	return nil
}

// ── delete ────────────────────────────────────────────────────────────────────

var policyDeleteCmd = &cobra.Command{
	Use:   "delete <policy-id>",
	Short: "Delete a policy",
	Args:  cobra.ExactArgs(1),
	RunE:  runPolicyDelete,
}

func init() {
	policyDeleteCmd.Flags().Bool("yes", false, "Skip confirmation prompt")
	policyDeleteCmd.Flags().Bool("dry-run", false, "Preview what would be deleted without actually deleting")
	policyCmd.AddCommand(policyDeleteCmd)
	rootCmd.AddCommand(policyCmd)
}

func runPolicyDelete(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id := args[0]

	// Fetch the policy name to make the confirmation message meaningful.
	var getResp struct {
		Policy policyItem `json:"policy"`
	}
	if err := client.Get("/api/policies/"+id, &getResp); err != nil {
		return fmt.Errorf("fetch policy: %w", err)
	}

	dryRun, _ := cmd.Flags().GetBool("dry-run")
	out := cmd.OutOrStdout()

	if dryRun {
		// Thread X-Chainsaw-Dry-Run through the shared client. Server will
		// enforce RBAC first and then, if permitted, return a 200 preview
		// body with dry_run=true. A 403 here is still a real 403 — we want
		// the operator to see the permission failure even in dry-run mode.
		dryClient := client.WithHeader(DryRunHeader, "true")
		var preview struct {
			DryRun bool       `json:"dry_run"`
			Would  string     `json:"would"`
			Target policyItem `json:"target"`
		}
		if err := dryClient.DeleteInto("/api/policies/"+id, &preview); err != nil {
			return err
		}
		fmt.Fprintf(out, "Would delete policy %q (id=%s, mode=%s, status=%s)\n",
			preview.Target.Name, preview.Target.ID, preview.Target.Mode, preview.Target.Status)
		return nil
	}

	yes, _ := cmd.Flags().GetBool("yes")
	if !yes {
		if !PromptConfirm(fmt.Sprintf("Delete policy %q (%s)?", getResp.Policy.Name, id)) {
			fmt.Println("Aborted.")
			return nil
		}
	}

	if err := client.Delete("/api/policies/" + id); err != nil {
		return err
	}
	fmt.Printf("Deleted policy %s\n", id)
	emit("cli.policy.deleted", nil)
	return nil
}

// ── enable / disable ──────────────────────────────────────────────────────────

var policyEnableCmd = &cobra.Command{
	Use:          "enable <policy-id>",
	Short:        "Enable a policy",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runPolicySetStatus("enabled"),
}

var policyDisableCmd = &cobra.Command{
	Use:          "disable <policy-id>",
	Short:        "Disable a policy",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runPolicySetStatus("disabled"),
}

func init() {
	policyCmd.AddCommand(policyEnableCmd, policyDisableCmd)
}

func runPolicySetStatus(status string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		client := newClient()
		if client.baseURL == "" {
			return errServerNotConfigured(cmd)
		}
		id := args[0]
		var resp struct {
			Policy policyItem `json:"policy"`
		}
		if err := client.Patch("/api/policies/"+id, map[string]string{"status": status}, &resp); err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		if useJSON(cmd) {
			return PrintJSON(resp.Policy)
		}
		printSuccess(out, cmd, fmt.Sprintf("Policy %q (%s) is now %s", resp.Policy.Name, id, status))
		return nil
	}
}

// ── simulate ──────────────────────────────────────────────────────────────────

var policySimulateCmd = &cobra.Command{
	Use:          "simulate <package@version>",
	Short:        "Test whether a package would be blocked by current policies",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runPolicySimulate,
}

func init() {
	policySimulateCmd.Flags().Bool("json", false, "Output as JSON")
	policyCmd.AddCommand(policySimulateCmd)
}

type policyIdentifier struct {
	TargetPackageName    string `json:"targetPackageName,omitempty"`
	TargetPackageRepo    string `json:"targetPackageRepo,omitempty"`
	TargetPackageVersion string `json:"targetPackageVersion,omitempty"`
}

type policyConditionsSummary struct {
	IsVulnerable         *bool    `json:"isVulnerable,omitempty"`
	PackageAge           *int     `json:"packageAge,omitempty"`
	CVSSMin              *float64 `json:"cvssMin,omitempty"`
	CVSSMax              *float64 `json:"cvssMax,omitempty"`
	EPSSMin              *float64 `json:"epssMin,omitempty"`
	EPSSMax              *float64 `json:"epssMax,omitempty"`
	PackageLicense       []string `json:"packageLicense,omitempty"`
	HasProvenance        *bool    `json:"hasProvenance,omitempty"`
	IsSuspectedTyposquat *bool    `json:"isSuspectedTyposquat,omitempty"`
	IsKnownMalicious     *bool    `json:"isKnownMalicious,omitempty"`
	TrustScoreMin        *int     `json:"trustScoreMin,omitempty"`
	TrustScoreMax        *int     `json:"trustScoreMax,omitempty"`
	ReservedNamespaces   []string `json:"reservedNamespaces,omitempty"`

	// Supply-chain condition surface added in the 13-PR consolidation.
	// Mirrors internal/policy.Conditions — kept as pointer bools so the
	// simulate view can distinguish "rule has no opinion" from "rule
	// wants false" and render accordingly.
	HasInstallScript            *bool    `json:"hasInstallScript,omitempty"`
	InstallScriptFetchesRemote  *bool    `json:"installScriptFetchesRemote,omitempty"`
	PublisherChanged            *bool    `json:"publisherChanged,omitempty"`
	VersionAnomaly              *bool    `json:"versionAnomaly,omitempty"`
	VersionAnomalyKinds         []string `json:"versionAnomalyKinds,omitempty"`
	HasHiddenUnicode            *bool    `json:"hasHiddenUnicode,omitempty"`
	HiddenUnicodeKinds          []string `json:"hiddenUnicodeKinds,omitempty"`
	PublishVelocityAnomaly      *bool    `json:"publishVelocityAnomaly,omitempty"`
	PublishVelocityThreshold24h *int     `json:"publishVelocityThreshold24h,omitempty"`
}

type simulateResult struct {
	Package    string `json:"package"`
	Version    string `json:"version"`
	Outcome    string `json:"outcome"` // "allow"|"block"|"quarantine"|"monitor"|"no_match"
	MatchedID  string `json:"matched_id,omitempty"`
	PolicyName string `json:"policy_name,omitempty"`
	Mode       string `json:"mode,omitempty"`
	Reason     string `json:"reason,omitempty"`
	Note       string `json:"note,omitempty"`
	// Conditions is the human-readable list of active conditions on the
	// matched policy. Populated so operators can see at-a-glance which
	// supply-chain guards are in play — especially useful for the
	// 13-PR conditions where the surface is wider than the legacy
	// CVSS/EPSS view.
	Conditions []string `json:"conditions,omitempty"`
}

func runPolicySimulate(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	input := args[0]
	pkg, version, _ := strings.Cut(input, "@")
	pkg = strings.TrimSpace(pkg)
	version = strings.TrimSpace(version)
	if pkg == "" {
		return fmt.Errorf("invalid format — expected <package@version> or <package>")
	}

	var listResp struct {
		Policies []policyItem `json:"policies"`
	}
	if err := client.Get("/api/policies", &listResp); err != nil {
		return err
	}

	result := simulateResult{
		Package: pkg,
		Version: version,
		Outcome: "no_match",
		Note:    "Condition evaluation (CVSS, EPSS, vulnerability, trust score) requires server-side data not available to the CLI. Only identifier-based matching is shown.",
	}

	for _, p := range listResp.Policies {
		if p.Status != "enabled" {
			continue
		}
		// Parse identifier
		var ident policyIdentifier
		if len(p.Identifier) > 0 {
			_ = json.Unmarshal(p.Identifier, &ident)
		}
		if !identifierMatches(ident, pkg, version) {
			continue
		}
		// Parse conditions to describe what would trigger
		var conds policyConditionsSummary
		if len(p.Conditions) > 0 {
			_ = json.Unmarshal(p.Conditions, &conds)
		}
		hasRuntimeConditions := conds.IsVulnerable != nil || conds.CVSSMin != nil ||
			conds.CVSSMax != nil || conds.EPSSMin != nil || conds.EPSSMax != nil ||
			conds.IsKnownMalicious != nil || conds.HasProvenance != nil ||
			conds.IsSuspectedTyposquat != nil || conds.TrustScoreMin != nil ||
			conds.TrustScoreMax != nil || len(conds.PackageLicense) > 0 ||
			len(conds.ReservedNamespaces) > 0 ||
			conds.HasInstallScript != nil || conds.InstallScriptFetchesRemote != nil ||
			conds.PublisherChanged != nil ||
			conds.VersionAnomaly != nil || len(conds.VersionAnomalyKinds) > 0 ||
			conds.HasHiddenUnicode != nil || len(conds.HiddenUnicodeKinds) > 0 ||
			conds.PublishVelocityAnomaly != nil || conds.PublishVelocityThreshold24h != nil

		if hasRuntimeConditions {
			result.Outcome = "conditional"
			result.Reason = "identifier matches; runtime conditions (CVSS, EPSS, etc.) require server evaluation"
		} else {
			result.Outcome = p.Mode
		}
		result.MatchedID = p.ID
		result.PolicyName = p.Name
		result.Mode = p.Mode
		result.Conditions = summarizeConditions(conds)
		break
	}

	out := cmd.OutOrStdout()
	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	fmt.Fprintf(out, "Package:  %s\n", pkg)
	if version != "" {
		fmt.Fprintf(out, "Version:  %s\n", version)
	}
	fmt.Fprintf(out, "Outcome:  %s\n", result.Outcome)
	if result.MatchedID != "" {
		fmt.Fprintf(out, "Policy:   %s (%s)\n", result.PolicyName, result.MatchedID)
		fmt.Fprintf(out, "Mode:     %s\n", result.Mode)
	}
	if result.Reason != "" {
		fmt.Fprintf(out, "Reason:   %s\n", result.Reason)
	}
	if len(result.Conditions) > 0 {
		fmt.Fprintf(out, "Conditions:\n")
		for _, c := range result.Conditions {
			fmt.Fprintf(out, "  - %s\n", c)
		}
	}
	fmt.Fprintf(out, "Note:     %s\n", result.Note)
	return nil
}

// summarizeConditions renders a policy's Conditions as a deterministic,
// human-readable slice of "<key>=<value>" strings for use in the
// simulate text/JSON output. Only fields that are actually set are
// included — nil pointer bools and empty slices are skipped — so an
// empty slice means "identifier-only policy, fires on every match".
func summarizeConditions(c policyConditionsSummary) []string {
	var out []string
	appendBool := func(name string, p *bool) {
		if p != nil {
			out = append(out, fmt.Sprintf("%s=%v", name, *p))
		}
	}
	appendInt := func(name string, p *int) {
		if p != nil {
			out = append(out, fmt.Sprintf("%s=%d", name, *p))
		}
	}
	appendFloat := func(name string, p *float64) {
		if p != nil {
			out = append(out, fmt.Sprintf("%s=%g", name, *p))
		}
	}
	appendSlice := func(name string, v []string) {
		if len(v) > 0 {
			out = append(out, fmt.Sprintf("%s=[%s]", name, strings.Join(v, ",")))
		}
	}

	appendBool("isVulnerable", c.IsVulnerable)
	appendInt("packageAge", c.PackageAge)
	appendFloat("cvssMin", c.CVSSMin)
	appendFloat("cvssMax", c.CVSSMax)
	appendFloat("epssMin", c.EPSSMin)
	appendFloat("epssMax", c.EPSSMax)
	appendSlice("packageLicense", c.PackageLicense)
	appendBool("hasProvenance", c.HasProvenance)
	appendBool("isSuspectedTyposquat", c.IsSuspectedTyposquat)
	appendBool("isKnownMalicious", c.IsKnownMalicious)
	appendInt("trustScoreMin", c.TrustScoreMin)
	appendInt("trustScoreMax", c.TrustScoreMax)
	appendSlice("reservedNamespaces", c.ReservedNamespaces)

	appendBool("hasInstallScript", c.HasInstallScript)
	appendBool("installScriptFetchesRemote", c.InstallScriptFetchesRemote)
	appendBool("publisherChanged", c.PublisherChanged)
	appendBool("versionAnomaly", c.VersionAnomaly)
	appendSlice("versionAnomalyKinds", c.VersionAnomalyKinds)
	appendBool("hasHiddenUnicode", c.HasHiddenUnicode)
	appendSlice("hiddenUnicodeKinds", c.HiddenUnicodeKinds)
	appendBool("publishVelocityAnomaly", c.PublishVelocityAnomaly)
	appendInt("publishVelocityThreshold24h", c.PublishVelocityThreshold24h)

	return out
}

// identifierMatches returns true if the policy identifier matches the given package/version.
// An empty identifier matches everything.
func identifierMatches(ident policyIdentifier, pkg, version string) bool {
	if ident.TargetPackageName != "" &&
		!strings.EqualFold(ident.TargetPackageName, pkg) {
		return false
	}
	if ident.TargetPackageVersion != "" && version != "" &&
		ident.TargetPackageVersion != version &&
		ident.TargetPackageVersion != "*" {
		return false
	}
	return true
}

// ── export ────────────────────────────────────────────────────────────────────

var policyExportCmd = &cobra.Command{
	Use:          "export",
	Short:        "Export all policies as YAML or JSON for backup",
	SilenceUsage: true,
	RunE:         runPolicyExport,
}

func init() {
	policyExportCmd.Flags().String("format", "yaml", "Output format: yaml|json")
	policyExportCmd.Flags().String("output", "", "Write to file instead of stdout")
	policyCmd.AddCommand(policyExportCmd)
}

func runPolicyExport(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	var listResp struct {
		Policies []json.RawMessage `json:"policies"`
	}
	if err := client.Get("/api/policies", &listResp); err != nil {
		return err
	}

	format, _ := cmd.Flags().GetString("format")
	outputFile, _ := cmd.Flags().GetString("output")

	var data []byte
	var err error
	switch strings.ToLower(format) {
	case "json":
		data, err = json.MarshalIndent(listResp.Policies, "", "  ")
	default:
		// Convert JSON → YAML via round-trip
		var policies []any
		for _, raw := range listResp.Policies {
			var p any
			if jerr := json.Unmarshal(raw, &p); jerr == nil {
				policies = append(policies, p)
			}
		}
		data, err = yaml.Marshal(policies)
	}
	if err != nil {
		return fmt.Errorf("marshal policies: %w", err)
	}

	if outputFile != "" {
		if werr := os.WriteFile(outputFile, data, 0o644); werr != nil {
			return fmt.Errorf("write file: %w", werr)
		}
		printSuccess(cmd.OutOrStdout(), cmd, fmt.Sprintf("Exported %d policies to %s", len(listResp.Policies), outputFile))
		return nil
	}
	_, err = cmd.OutOrStdout().Write(data)
	return err
}

// ── rollout (D.17 / US-30 — staged monitor→block) ────────────────────────────
//
// Two sub-commands wired here so the operator can drive the rollout
// from the CLI without round-tripping the dashboard:
//
//   chainsaw policy rollout status            — list monitor policies + stats
//   chainsaw policy flip-to-block <policy-id> — atomic flip with audit
//
// Both endpoints (/api/policies/{id}/rollout, /api/policies/{id}/flip-to-block)
// are added by internal/server/policy_rollout_api.go. The CLI is thin —
// no business logic, just shaping the request/response for terminal
// output.

// rolloutItem mirrors the rolloutResponse wire shape in
// internal/server/policy_rollout_api.go. Kept local rather than imported
// so the CLI package doesn't pick up a transitive dependency on the
// server package.
type rolloutItem struct {
	PolicyID           string `json:"policyId"`
	Stage              string `json:"stage"`
	MonitorDays        int    `json:"monitorDays"`
	WouldBlockCount30d int    `json:"wouldBlockCount30d"`
	PermittedCount30d  int    `json:"permittedCount30d,omitempty"`
	LastEvaluatedAt    string `json:"lastEvaluatedAt"`
	WindowDays         int    `json:"windowDays"`
}

var policyRolloutCmd = &cobra.Command{
	Use:   "rollout",
	Short: "Staged monitor→block rollout for policies",
	Long: `Inspect and advance the monitor→block rollout for policies.

Examples:
  chainsaw policy rollout status                  # list monitor policies + stats
  chainsaw policy flip-to-block <id> --yes        # atomic flip with audit`,
}

var policyRolloutStatusCmd = &cobra.Command{
	Use:          "status",
	Short:        "List monitor-mode policies and their would-block stats",
	SilenceUsage: true,
	RunE:         runPolicyRolloutStatus,
}

func init() {
	policyRolloutStatusCmd.Flags().Bool("json", false, "Output as JSON")
	policyRolloutCmd.AddCommand(policyRolloutStatusCmd)
	policyCmd.AddCommand(policyRolloutCmd)
}

func runPolicyRolloutStatus(cmd *cobra.Command, _ []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	// First list policies, then fan-out one rollout request per
	// monitor-mode row. The fan-out is sequential by design — the policy
	// count for any single org is small (typically <50) and a serial
	// loop keeps the CLI output deterministic for snapshot tests.
	var listResp struct {
		Policies []policyItem `json:"policies"`
	}
	if err := client.Get("/api/policies", &listResp); err != nil {
		return err
	}

	type row struct {
		Policy  policyItem  `json:"policy"`
		Rollout rolloutItem `json:"rollout"`
	}
	rows := make([]row, 0)
	for _, p := range listResp.Policies {
		if p.Mode != "monitor" {
			continue
		}
		var stats rolloutItem
		if err := client.Get("/api/policies/"+p.ID+"/rollout", &stats); err != nil {
			// Don't fail the whole report — surface a sentinel value
			// for this row so the operator sees what's missing.
			fmt.Fprintf(cmd.ErrOrStderr(), "warn: rollout for %s: %v\n", p.ID, err)
			continue
		}
		rows = append(rows, row{Policy: p, Rollout: stats})
	}

	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(rows)
	}
	if len(rows) == 0 {
		fmt.Println("No monitor-mode policies found.")
		return nil
	}
	tableRows := make([][]string, len(rows))
	for i, r := range rows {
		tableRows[i] = []string{
			r.Policy.ID,
			r.Policy.Name,
			fmt.Sprintf("%d", r.Rollout.MonitorDays),
			fmt.Sprintf("%d", r.Rollout.WouldBlockCount30d),
			fmt.Sprintf("%d", r.Rollout.WindowDays),
		}
	}
	PrintTable([]string{"ID", "NAME", "MONITOR_DAYS", "WOULD_BLOCK_30D", "WINDOW"}, tableRows)
	return nil
}

var policyFlipToBlockCmd = &cobra.Command{
	Use:          "flip-to-block <policy-id>",
	Short:        "Flip a monitor-mode policy to block (with would-block preview)",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runPolicyFlipToBlock,
}

func init() {
	policyFlipToBlockCmd.Flags().Bool("yes", false, "Skip confirmation prompt")
	policyFlipToBlockCmd.Flags().Bool("json", false, "Output as JSON")
	policyCmd.AddCommand(policyFlipToBlockCmd)
}

func runPolicyFlipToBlock(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}
	id := args[0]
	out := cmd.OutOrStdout()

	// Fetch the preview stats first so the operator sees the would-block
	// count BEFORE confirming. This is the same number the dashboard
	// modal shows on the "Flip to Block?" CTA — keeping the two surfaces
	// in lockstep avoids the "the UI said X but the CLI did Y" class of
	// surprises.
	var preview rolloutItem
	if err := client.Get("/api/policies/"+id+"/rollout", &preview); err != nil {
		return fmt.Errorf("preview rollout: %w", err)
	}
	fmt.Fprintf(out, "Policy: %s\n", id)
	fmt.Fprintf(out, "Current stage:           %s\n", preview.Stage)
	fmt.Fprintf(out, "Days in monitor:         %d\n", preview.MonitorDays)
	fmt.Fprintf(out, "Would-block (last %dd):  %d\n", preview.WindowDays, preview.WouldBlockCount30d)

	yes, _ := cmd.Flags().GetBool("yes")
	if !yes {
		if !PromptConfirm(fmt.Sprintf("Flip policy %s from monitor → block?", id)) {
			fmt.Fprintln(out, "Aborted.")
			return nil
		}
	}

	var resp struct {
		Policy  policyItem  `json:"policy"`
		Preview rolloutItem `json:"preview"`
	}
	if err := client.Post("/api/policies/"+id+"/flip-to-block", nil, &resp); err != nil {
		return fmt.Errorf("flip: %w", err)
	}
	asJSON, _ := cmd.Flags().GetBool("json")
	if asJSON {
		return PrintJSON(resp)
	}
	printSuccess(out, cmd, fmt.Sprintf("Policy %s flipped to %s (recorded with %d would-block evidence)",
		id, resp.Policy.Mode, resp.Preview.WouldBlockCount30d))
	emit("cli.policy.flipped_to_block", map[string]any{
		"policy_id":             id,
		"would_block_count_30d": resp.Preview.WouldBlockCount30d,
	})
	return nil
}

// ── import ────────────────────────────────────────────────────────────────────

var policyImportCmd = &cobra.Command{
	Use:          "import <file>",
	Short:        "Import policies from a YAML or JSON file",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runPolicyImport,
}

func init() {
	policyImportCmd.Flags().Bool("dry-run", false, "Show what would be imported without creating anything")
	policyCmd.AddCommand(policyImportCmd)
}

func runPolicyImport(cmd *cobra.Command, args []string) error {
	client := newClient()
	if client.baseURL == "" {
		return errServerNotConfigured(cmd)
	}

	file := args[0]
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	var policies []map[string]any
	ext := strings.ToLower(filepath.Ext(file))
	if ext == ".json" {
		err = json.Unmarshal(data, &policies)
	} else {
		err = yaml.Unmarshal(data, &policies)
	}
	if err != nil {
		return fmt.Errorf("parse %s: %w", file, err)
	}

	dryRun, _ := cmd.Flags().GetBool("dry-run")
	out := cmd.OutOrStdout()

	if dryRun {
		fmt.Fprintf(out, "Would import %d policies (dry-run):\n", len(policies))
		for _, p := range policies {
			fmt.Fprintf(out, "  - %v (mode: %v, status: %v)\n", p["name"], p["mode"], p["status"])
		}
		return nil
	}

	created, skipped := 0, 0
	for _, p := range policies {
		// Strip server-assigned fields so the server generates new ones.
		delete(p, "id")
		delete(p, "createdAt")
		delete(p, "updatedAt")

		var resp map[string]any
		if cerr := client.Post("/api/policies", p, &resp); cerr != nil {
			fmt.Fprintf(out, "  skip %v: %v\n", p["name"], cerr)
			skipped++
			continue
		}
		created++
	}
	printSuccess(out, cmd, fmt.Sprintf("Imported %d policies (%d skipped)", created, skipped))
	return nil
}
