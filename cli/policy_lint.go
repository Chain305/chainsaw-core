package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/chain305/chainsaw-core/policy"
)

// `chainsaw policy lint` — a proactive scanner that flags policies
// vulnerable to the recent Wave-3 codesmell standalone-gate demotions
// and the Wave-A three-state boundary cleanup. Read-only; never talks
// to the server. Walks JSON/YAML files on disk and reports findings
// in deterministic file:line order so the output is diffable.
//
// This is intentionally separate from the validatePolicy save-time
// guard in internal/policy/store.go: the validator rejects bad
// policies as they're written, but operators have hundreds of files
// already on disk that the validator never sees until someone tries
// to import them. The lint subcommand is the discoverability layer.

const (
	lintFindingError   = "error"
	lintFindingWarning = "warning"

	lintExitClean   = 0
	lintExitWarning = 1
	lintExitError   = 2
)

// lintFinding describes one issue found in one rule. The shape is
// stable so `--format json` consumers (CI gates, dashboards) can
// depend on it.
type lintFinding struct {
	File       string `json:"file"`
	Line       int    `json:"line"`
	Rule       string `json:"rule"`
	Severity   string `json:"severity"`
	Type       string `json:"type"`
	Message    string `json:"message"`
	Suggestion string `json:"suggestion,omitempty"`
}

// lintReport is the top-level JSON shape emitted by --format json.
type lintReport struct {
	Files    int           `json:"files"`
	Rules    int           `json:"rules"`
	Errors   int           `json:"errors"`
	Warnings int           `json:"warnings"`
	Findings []lintFinding `json:"findings"`
}

var policyLintCmd = &cobra.Command{
	Use:   "lint",
	Short: "Scan policy files for rules vulnerable to recent semantic changes",
	Long: `Scan policy JSON/YAML files for rules that depend on semantics that have
recently shifted under them.

Two checks run today:

  1. Standalone codesmell (ERROR): a rule that gates ONLY on one of the
     five demoted Wave-3 codesmell signals (UsesEval, NetworkAccess,
     ShellAccess, FilesystemAccess, EnvVarAccess) with no identifier,
     scope, or other condition. The save-time validator already rejects
     these — lint is the discovery tool for files already on disk.

  2. Three-state nil-as-false reliance (WARNING): a rule that gates on
     RepoArchived=false or FirstTimeCollaborator=false. Now that those
     fields are *bool, "false" means "confirmed false" — not "unknown
     or false" as the old two-state shape allowed. Operators may have
     intended either reading; lint flags the call site so they can
     verify intent.

Exit codes: 0 clean, 1 warnings only, 2 any errors.`,
	RunE: runPolicyLint,
}

func init() {
	policyLintCmd.Flags().String("input", "", "Policy file or directory to scan (recursive for dirs)")
	policyLintCmd.Flags().String("format", "text", "Output format: text|json")
	policyCmd.AddCommand(policyLintCmd)
}

func runPolicyLint(cmd *cobra.Command, _ []string) error {
	input, _ := cmd.Flags().GetString("input")
	format, _ := cmd.Flags().GetString("format")
	if strings.TrimSpace(input) == "" {
		return errors.New("--input <file-or-dir> is required")
	}

	files, err := collectPolicyFiles(input)
	if err != nil {
		return err
	}

	var (
		findings []lintFinding
		ruleCnt  int
	)
	for _, f := range files {
		fres, rules, ferr := lintPolicyFile(f)
		if ferr != nil {
			// Parse errors surface as findings rather than aborting
			// the whole scan — one malformed file shouldn't hide
			// findings in the rest.
			findings = append(findings, lintFinding{
				File:     f,
				Line:     1,
				Rule:     "<file>",
				Severity: lintFindingError,
				Type:     "parse-error",
				Message:  ferr.Error(),
			})
			continue
		}
		ruleCnt += rules
		findings = append(findings, fres...)
	}

	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		if findings[i].Line != findings[j].Line {
			return findings[i].Line < findings[j].Line
		}
		return findings[i].Rule < findings[j].Rule
	})

	report := lintReport{
		Files:    len(files),
		Rules:    ruleCnt,
		Findings: findings,
	}
	for _, f := range findings {
		switch f.Severity {
		case lintFindingError:
			report.Errors++
		case lintFindingWarning:
			report.Warnings++
		}
	}

	out := cmd.OutOrStdout()
	switch strings.ToLower(format) {
	case "json":
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(report); err != nil {
			return err
		}
	default:
		printLintText(out, report)
	}

	switch {
	case report.Errors > 0:
		os.Exit(lintExitError)
	case report.Warnings > 0:
		os.Exit(lintExitWarning)
	}
	return nil
}

func printLintText(out interface{ Write(p []byte) (int, error) }, r lintReport) {
	fmt.Fprintf(out, "Scanned %d file(s), %d rule(s)\n", r.Files, r.Rules)
	fmt.Fprintf(out, "Findings: %d error(s), %d warning(s)\n\n", r.Errors, r.Warnings)
	if len(r.Findings) == 0 {
		fmt.Fprintln(out, "No findings — policies are clean against the current rule set.")
		return
	}
	for _, f := range r.Findings {
		fmt.Fprintf(out, "%s:%d  [%s] %s — %s\n", f.File, f.Line, strings.ToUpper(f.Severity), f.Rule, f.Message)
		if f.Suggestion != "" {
			fmt.Fprintf(out, "    -> %s\n", f.Suggestion)
		}
	}
}

// collectPolicyFiles enumerates JSON/YAML files under the given path.
// A single file is returned as-is; a directory is walked recursively
// and filtered by extension. Output is sorted so the scan order is
// deterministic.
func collectPolicyFiles(input string) ([]string, error) {
	info, err := os.Stat(input)
	if err != nil {
		return nil, fmt.Errorf("stat %s: %w", input, err)
	}
	if !info.IsDir() {
		return []string{input}, nil
	}
	var files []string
	werr := filepath.WalkDir(input, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".json" || ext == ".yaml" || ext == ".yml" {
			files = append(files, path)
		}
		return nil
	})
	if werr != nil {
		return nil, werr
	}
	sort.Strings(files)
	return files, nil
}

// rawPolicyDoc is the on-disk shape we accept: either a single policy
// object or an array of them. We decode into yaml.Node first so we can
// recover line numbers for findings, then normalize each node into a
// policy.Policy via JSON round-trip (keeps tag handling identical to
// the server's import path).
type rawPolicyDoc struct {
	policies []rawPolicyEntry
}

type rawPolicyEntry struct {
	policy policy.Policy
	line   int
	name   string
}

func lintPolicyFile(path string) ([]lintFinding, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("read: %w", err)
	}
	doc, err := parsePolicyDoc(data, path)
	if err != nil {
		return nil, 0, err
	}
	var findings []lintFinding
	for _, e := range doc.policies {
		findings = append(findings, lintPolicy(path, e)...)
	}
	return findings, len(doc.policies), nil
}

// parsePolicyDoc decodes a policy bundle as YAML (which is a strict
// superset of JSON for our purposes — yaml.v3 reads both). Using
// yaml.Node first lets us pull line numbers per entry; we then JSON
// round-trip into the typed Policy for field access.
func parsePolicyDoc(data []byte, path string) (*rawPolicyDoc, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if len(root.Content) == 0 {
		return &rawPolicyDoc{}, nil
	}
	top := root.Content[0]

	var entries []*yaml.Node
	switch top.Kind {
	case yaml.SequenceNode:
		entries = append(entries, top.Content...)
	case yaml.MappingNode:
		entries = append(entries, top)
	default:
		return nil, fmt.Errorf("parse %s: unsupported top-level kind %v", path, top.Kind)
	}

	out := &rawPolicyDoc{}
	for _, n := range entries {
		// JSON-round-trip via yaml.Marshal → json.Unmarshal so
		// tag/case handling matches store.go's import path.
		yb, err := yaml.Marshal(n)
		if err != nil {
			return nil, fmt.Errorf("re-marshal entry at %s:%d: %w", path, n.Line, err)
		}
		// Convert YAML → generic any → JSON → typed Policy. yaml.v3
		// emits map[string]any with string keys for our shapes, so
		// json.Marshal works directly.
		var any any
		if err := yaml.Unmarshal(yb, &any); err != nil {
			return nil, fmt.Errorf("decode entry at %s:%d: %w", path, n.Line, err)
		}
		jb, err := json.Marshal(any)
		if err != nil {
			return nil, fmt.Errorf("encode entry at %s:%d: %w", path, n.Line, err)
		}
		var p policy.Policy
		if err := json.Unmarshal(jb, &p); err != nil {
			return nil, fmt.Errorf("typed decode at %s:%d: %w", path, n.Line, err)
		}
		name := p.Name
		if name == "" {
			name = p.ID
		}
		if name == "" {
			name = "<unnamed>"
		}
		out.policies = append(out.policies, rawPolicyEntry{policy: p, line: n.Line, name: name})
	}
	return out, nil
}

// lintPolicy applies all checks to a single policy and returns the
// findings. Pure function — easy to table-test.
func lintPolicy(file string, e rawPolicyEntry) []lintFinding {
	var out []lintFinding
	if f := checkStandaloneCodesmell(file, e); f != nil {
		out = append(out, *f)
	}
	out = append(out, checkThreeStateNilAsFalse(file, e)...)
	return out
}

// checkStandaloneCodesmell mirrors rejectStandaloneContextOnlyConditions
// in internal/policy/store.go: a policy whose ONLY signal is one of
// the five demoted codesmell conditions (with no identifier, scope, or
// other condition) is an error.
func checkStandaloneCodesmell(file string, e rawPolicyEntry) *lintFinding {
	used := policy.ConditionsUsedBy(e.policy.Conditions)
	if len(used) == 0 {
		return nil
	}
	var contextOnly []policy.ConditionType
	hasOther := false
	for _, c := range used {
		if policy.IsContextOnlyCondition(c) {
			contextOnly = append(contextOnly, c)
		} else {
			hasOther = true
		}
	}
	if len(contextOnly) == 0 || hasOther {
		return nil
	}
	if hasIdentifier(e.policy.Identifier) || hasScope(e.policy.Scope) {
		return nil
	}
	names := make([]string, len(contextOnly))
	for i, c := range contextOnly {
		names[i] = string(c)
	}
	sort.Strings(names)
	return &lintFinding{
		File:     file,
		Line:     e.line,
		Rule:     e.name,
		Severity: lintFindingError,
		Type:     "standalone-codesmell",
		Message: fmt.Sprintf(
			"rule gates only on demoted context-only condition(s): %s",
			strings.Join(names, ", "),
		),
		Suggestion: "pair with another condition (e.g. HasInstallScript, IsKnownMalicious), an identifier (target package), a scope (target client/group), or use the signal via trustscore/composite expressions",
	}
}

// checkThreeStateNilAsFalse warns on rules that condition on
// RepoArchived=false or FirstTimeCollaborator=false. Post-cleanup
// these match only confirmed-false rather than "unknown or false";
// the warning surfaces the call site so operators can verify intent.
func checkThreeStateNilAsFalse(file string, e rawPolicyEntry) []lintFinding {
	var out []lintFinding
	if v := e.policy.Conditions.FirstTimeCollaborator; v != nil && !*v {
		out = append(out, lintFinding{
			File:       file,
			Line:       e.line,
			Rule:       e.name,
			Severity:   lintFindingWarning,
			Type:       "three-state-nil-as-false",
			Message:    "rule gates on firstTimeCollaborator=false; post Wave-A this matches confirmed-false only, not unknown",
			Suggestion: "if you intended to also fire on unknown-collaborator, omit the field (nil ≡ any) or model the unknown case explicitly via two paired rules",
		})
	}
	// RepoArchived currently lives on the input/risk side, not the
	// Conditions struct — the lint output documents that. We still
	// scan the raw entry name for an explicit 'repoArchived' tag so
	// pre-Wave-A user-authored conditions surface a finding.
	if rawHasField(e, "repoArchived") {
		out = append(out, lintFinding{
			File:       file,
			Line:       e.line,
			Rule:       e.name,
			Severity:   lintFindingWarning,
			Type:       "three-state-nil-as-false",
			Message:    "rule references repoArchived; post Wave-A this is *bool — verify whether the rule should also fire on unknown",
			Suggestion: "if you intended to also fire on unknown-archived, omit the field or model the unknown case explicitly",
		})
	}
	return out
}

// rawHasField re-marshals the policy to JSON and looks for the named
// key. Cheap, since policies are tiny, and avoids a second parse pass.
func rawHasField(e rawPolicyEntry, key string) bool {
	jb, err := json.Marshal(e.policy)
	if err != nil {
		return false
	}
	// Substring search is fine — the Conditions struct field names
	// are namespaced enough that the false-positive risk is
	// negligible at our scale.
	return strings.Contains(string(jb), `"`+key+`":`)
}

func hasIdentifier(id policy.Identifier) bool {
	return strings.TrimSpace(id.TargetPackageName) != "" ||
		strings.TrimSpace(id.TargetPackageRepo) != "" ||
		strings.TrimSpace(id.TargetPackageVersion) != ""
}

func hasScope(s policy.Scope) bool {
	return len(s.TargetClient) > 0 || len(s.TargetGroup) > 0 ||
		len(s.TargetRepos) > 0 || len(s.TargetRequestingCountry) > 0 ||
		len(s.TargetRequestingIP) > 0
}
