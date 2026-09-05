package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
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

	// lintTypeMatchAllThreshold / lintTypeNeverFiresThreshold are the two
	// finding types the range classifier produces, one per
	// policy.RangeEffect. match-all-threshold is the name lint has
	// published since A1 and is unchanged; never-fires-threshold is new,
	// because until this change lint had no way to say it.
	lintTypeMatchAllThreshold   = "match-all-threshold"
	lintTypeNeverFiresThreshold = "never-fires-threshold"
)

// policyScanIncompleteExitCode — the policy tree could not be fully inspected:
// a directory or a candidate policy file could not be read, so the result set
// is incomplete and a clean report would be a lie.
//
// It has to be its OWN number. `policy lint` publishes 2 for "your policies
// have errors", and root.go's classifyCLIError maps every unclassified
// operational failure to ExitOpError(2) as well — so before this existed, a CI
// gate wired per docs/policy-audit.md could not tell "your policies are bad"
// from "the scan never ran". 12 follows exitcodes.go's contract that codes >=10
// are command-specific outcomes; it is deliberately NOT one of the shared
// >=10 constants (ExitSoakNotCleared 10, ExitIntelBlock 11,
// ExitManifestParseError 30), which carry unrelated meanings.
//
// Shared by `policy lint` and `policy preflight`: both walk the same tree with
// the same collector, so one number means one thing on both surfaces.
const policyScanIncompleteExitCode = 12

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
//
// Files counts the files actually LINTED, not the files the walker saw —
// anything the sweep declined lands in Skipped with a reason, so the two
// numbers always reconcile.
type lintReport struct {
	Files    int           `json:"files"`
	Rules    int           `json:"rules"`
	Errors   int           `json:"errors"`
	Warnings int           `json:"warnings"`
	Skipped  []policySkip  `json:"skipped,omitempty"`
	Findings []lintFinding `json:"findings"`
}

// policySkip records one path the collector or the parser declined to lint,
// and why. The list is emitted in both renderings: a lint that could not read
// part of the tree has to SAY so — reporting clean would be the same silent
// under-report scan_repo.go's report.Unreadable exists to prevent.
type policySkip struct {
	Path   string `json:"path"`
	Reason string `json:"reason"`
	// Unreadable separates COVERAGE LOSS from deliberate filtering. True: the
	// path might have held policies and we could not tell (permission denied,
	// IO error) — this escalates the exit code. False: we read it and it is
	// simply not a policy document (a tsconfig.json a directory sweep walked
	// past) — informational only.
	Unreadable bool `json:"unreadable"`
}

// unreadablePolicySkips returns only the coverage-loss subset — the skips that
// mean "we could not tell what was there", not "we looked and it wasn't ours".
func unreadablePolicySkips(skips []policySkip) []policySkip {
	var out []policySkip
	for _, s := range skips {
		if s.Unreadable {
			out = append(out, s)
		}
	}
	return out
}

var policyLintCmd = &cobra.Command{
	Use:   "lint",
	Short: "Scan policy files for rules vulnerable to recent semantic changes",
	Long: `Scan policy JSON/YAML files for rules that depend on semantics that have
recently shifted under them.

Three checks run today:

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

  3. Degenerate numeric thresholds (ERROR or WARNING): a bounded
     condition (cvssMin/Max, epssMin/Max, trustScoreMin/Max,
     requireSlsaLevel, packageAge, cooldownDays, or a min above its
     paired max) whose value the evaluator can never satisfy, or always
     satisfies. ERROR when the value is outside the range the API
     enforces on save (cvssMin: 999); WARNING when it is legal but
     degenerate (cvssMin: 0 matches every package, including ones with
     no CVE). This is the same classifier "chainsaw policy audit" runs
     over live rows, so a file and the row it becomes cannot disagree.

Pointing --input at a DIRECTORY is a sweep: the walker skips .git,
node_modules, vendor, .gradle, target, build, dist and .venv/venv, and any
JSON/YAML it picks up that is not a policy document (package.json,
tsconfig.json, .github/workflows/*.yml) is reported as skipped rather than
as a malformed policy — and does not count toward the rule total. Naming a
file explicitly keeps the strict reading: an unparseable file you asked for
is an error.

Exit codes:
  0  clean
  1  warnings only
  2  any errors — your policies have problems
  12 the tree could not be fully inspected (a directory or a candidate
     policy file could not be read), so the result is INCOMPLETE and must
     not be read as clean. Distinct from 2 on purpose: a CI gate has to be
     able to tell "your policies are bad" from "the scan never ran".`,
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

	set, err := collectPolicyFiles(input)
	if err != nil {
		return err
	}

	// Findings starts as an EMPTY slice, not nil. A clean tree is the common
	// case for a command built to gate CI, and a nil slice marshals as
	// `"findings": null` — `report.findings.map(...)` throws TypeError and
	// `jq '.findings[]'` errors with "Cannot iterate over null", so the JSON
	// broke on exactly the automated path `policy lint --format json` exists
	// for. `omitempty` is deliberately NOT the fix: dropping the key breaks
	// the same consumers a different way. The non-empty shape is untouched —
	// append to an empty slice produces the identical array. (Skipped is a
	// different case and stays nil: it is `json:"skipped,omitempty"`, so nil
	// is OMITTED rather than rendered as null.)
	var (
		findings = []lintFinding{}
		ruleCnt  int
		linted   int
	)
	skipped := append([]policySkip(nil), set.Skipped...)
	// A file the operator NAMED is read strictly; a file a directory sweep
	// merely walked past is not. That distinction is the whole fix for the
	// false-positive gate break: `--input tsconfig.json` is still an error,
	// `--input .` over a repo containing one is not.
	explicit := !set.Swept
	for _, f := range set.Files {
		res, ferr := lintOnePolicyFile(f, explicit)
		if ferr != nil {
			// Parse errors surface as findings rather than aborting
			// the whole scan — one malformed file shouldn't hide
			// findings in the rest. Only reachable for an explicitly
			// named file; a sweep routes the same failure to res.skip.
			findings = append(findings, lintFinding{
				File:     f,
				Line:     1,
				Rule:     "<file>",
				Severity: lintFindingError,
				Type:     "parse-error",
				Message:  ferr.Error(),
			})
			linted++
			continue
		}
		if res.skip != nil {
			skipped = append(skipped, *res.skip)
		}
		if res.rules == 0 && res.skip != nil {
			continue
		}
		linted++
		ruleCnt += res.rules
		findings = append(findings, res.findings...)
	}
	sort.SliceStable(skipped, func(i, j int) bool { return skipped[i].Path < skipped[j].Path })

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
		Files:    linted,
		Rules:    ruleCnt,
		Skipped:  skipped,
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

	// S9b — honor --output for BOTH formats. `policy lint` shadows --format
	// with its own text|json vocabulary, which exempts it from root.go's
	// --output validator on the stated grounds that a --format-shadowing
	// command routes its result through a sink honouring --output. It did not:
	// both branches wrote to cmd.OutOrStdout(), so `policy lint --output R`
	// created no file and printed the findings to stdout. cmd.OutOrStdout()
	// stays the no-file fallback so tests capturing via cmd.SetOut still work.
	out := outWriterOr(cmd, cmd.OutOrStdout())
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

	// Y3/Y4 — returned, not os.Exit'd. The two bare exits left the process
	// before Execute() reached markSessionEnd + flushTelemetry, so the only
	// two outcomes worth recording (findings present) dropped the whole
	// telemetry batch including cli.session.completed and its exit_code. The
	// NUMBERS are unchanged — ExitCodeError carries arbitrary codes, and
	// `policy lint --help` publishes "0 clean, 1 warnings only, 2 any errors".
	// Err stays nil so renderError adds nothing to the findings list already
	// printed.
	//
	// The ladder's middle rung is new. Precedence mirrors pr-scan's
	// (exitcodes.go: "a real BLOCK outranks it"): a genuine policy ERROR still
	// wins, because it is true and actionable and the skipped paths are named
	// in the report either way. But INCOMPLETE outranks warnings-only — exit 1
	// tells a CI gate "warnings, carry on", which is exactly the green light a
	// half-read tree must not get.
	switch {
	case report.Errors > 0:
		return &ExitCodeError{Code: lintExitError}
	case len(unreadablePolicySkips(report.Skipped)) > 0:
		return &ExitCodeError{Code: policyScanIncompleteExitCode}
	case report.Warnings > 0:
		return &ExitCodeError{Code: lintExitWarning}
	}
	return nil
}

func printLintText(out interface{ Write(p []byte) (int, error) }, r lintReport) {
	fmt.Fprintf(out, "Scanned %d file(s), %d rule(s)\n", r.Files, r.Rules)
	fmt.Fprintf(out, "Findings: %d error(s), %d warning(s)\n\n", r.Errors, r.Warnings)
	printPolicySkips(out, r.Skipped)
	if len(r.Findings) == 0 {
		if len(unreadablePolicySkips(r.Skipped)) > 0 {
			// Never the bare "clean" line when part of the tree was
			// unreadable — that sentence is what a CI gate quotes back.
			fmt.Fprintln(out, "No findings in what could be read — but the scan is INCOMPLETE (see above).")
			return
		}
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

// printPolicySkips renders the skip list: the deliberate filtering first
// (short, informational), then the coverage loss (always fully listed —
// that is the part a gate has to see).
func printPolicySkips(out io.Writer, skips []policySkip) {
	if len(skips) == 0 {
		return
	}
	unreadable := unreadablePolicySkips(skips)
	if n := len(skips) - len(unreadable); n > 0 {
		fmt.Fprintf(out, "Not policy documents, skipped: %d\n", n)
		shown := 0
		for _, s := range skips {
			if s.Unreadable {
				continue
			}
			if shown == policySkipListCap {
				fmt.Fprintf(out, "    ... and %d more\n", n-shown)
				break
			}
			fmt.Fprintf(out, "    %s — %s\n", s.Path, s.Reason)
			shown++
		}
	}
	if len(unreadable) > 0 {
		fmt.Fprintf(out, "Could not be read — this scan is INCOMPLETE: %d path(s)\n", len(unreadable))
		for _, s := range unreadable {
			fmt.Fprintf(out, "    %s — %s\n", s.Path, s.Reason)
		}
	}
	fmt.Fprintln(out)
}

// policySkipListCap bounds the informational half of the skip list. A repo
// sweep can walk past a lot of stray JSON; the coverage-loss half is never
// capped.
const policySkipListCap = 10

// policyFileSet is what collectPolicyFiles returns: the candidate files, the
// paths it declined and why, and whether the input was a directory SWEEP or an
// explicitly named file. Callers key strictness off Swept — see
// loadPolicyEntries.
type policyFileSet struct {
	Files   []string
	Skipped []policySkip
	Swept   bool
}

// policyScanSkipDir mirrors the exclusion list in scan_repo.go's walker (see
// core/cli/scan_repo.go, the `d.IsDir()` branch). Without it a sweep of an
// ordinary project descends into node_modules and reads thousands of
// package.json files as policy bundles.
func policyScanSkipDir(name string) bool {
	switch name {
	case ".git", "node_modules", "vendor", ".gradle", "target", "build", "dist", ".venv", "venv":
		return true
	}
	return false
}

// policySkipReason turns a walk/read error into a one-line human reason.
// Permission denial is the common case on Windows home directories
// (AppData\Local\...) and root-owned caches on POSIX, and it used to abort the
// entire command on the first hit.
func policySkipReason(err error) string {
	switch {
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	case errors.Is(err, fs.ErrNotExist):
		return "disappeared during the scan"
	default:
		return flattenErr(err)
	}
}

// flattenErr collapses a multi-line parser error into one line so the skip
// list stays one-path-per-row.
func flattenErr(err error) string {
	return strings.Join(strings.Fields(err.Error()), " ")
}

// collectPolicyFiles enumerates JSON/YAML files under the given path.
// A single file is returned as-is; a directory is walked recursively,
// filtered by extension, and pruned by policyScanSkipDir. Output is sorted so
// the scan order is deterministic.
//
// The walk TOLERATES errors instead of returning them verbatim. It used to
// `return err` from the WalkDir callback, so the first unreadable directory —
// one Razer folder under a Windows AppData tree — killed the whole command and
// produced no partial results at all. Every tolerated entry is RECORDED as an
// unreadable skip, which is what escalates the exit code; the failure mode we
// are replacing must not be swapped for a silent one.
//
// The only remaining hard error is a bad --input itself (same reasoning as
// scan_repo.go's pre-walk Stat: a typo must not read as "nothing to lint").
func collectPolicyFiles(input string) (policyFileSet, error) {
	info, err := os.Stat(input)
	if err != nil {
		return policyFileSet{}, fmt.Errorf("stat %s: %w", input, err)
	}
	if !info.IsDir() {
		return policyFileSet{Files: []string{input}}, nil
	}
	set := policyFileSet{Swept: true}
	_ = filepath.WalkDir(input, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			set.Skipped = append(set.Skipped, policySkip{
				Path:       path,
				Reason:     policySkipReason(err),
				Unreadable: true,
			})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if path != input && policyScanSkipDir(d.Name()) {
				return fs.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".json" || ext == ".yaml" || ext == ".yml" {
			set.Files = append(set.Files, path)
		}
		return nil
	})
	sort.Strings(set.Files)
	sort.SliceStable(set.Skipped, func(i, j int) bool { return set.Skipped[i].Path < set.Skipped[j].Path })
	return set, nil
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
	// raw is the entry's JSON bytes as authored, BEFORE typing. Kept so
	// checks can see keys the typed struct does not model — see
	// rawHasField.
	raw  []byte
	line int
	name string
}

// policyShapeKeys are the JSON keys that mark a document as a POLICY rather
// than some other JSON/YAML a directory sweep happened to walk past. A
// document carrying none of them is not linted and does not count toward the
// rule total.
//
// The list is deliberately generous: a false accept costs one over-counted
// rule with no conditions (checkStandaloneCodesmell needs a decoded condition
// set to fire, and rawHasField needs a literal repoArchived key, so neither
// can invent a finding), while a false REJECT would hide a real policy. Erring
// toward accepting is the safe direction here.
var policyShapeKeys = []string{"conditions", "mode", "routing", "identifier", "precedence"}

// looksLikePolicyEntry tests the entry's ORIGINAL JSON bytes — the same bytes
// rawHasField reads, before typing drops unknown keys.
func looksLikePolicyEntry(raw []byte) bool {
	s := string(raw)
	for _, k := range policyShapeKeys {
		if strings.Contains(s, `"`+k+`":`) {
			return true
		}
	}
	return false
}

// loadPolicyEntries reads and parses one file into policy entries. It is the
// single seam `policy lint` and `policy preflight` share, so the two commands
// cannot drift on what counts as a policy.
//
// explicit=true (the operator NAMED this file): every failure is an error. An
// unparseable file you asked for is a real problem and must stay one.
//
// explicit=false (a directory sweep walked past it): an unreadable or
// unparseable or non-policy file is a *policySkip, not an error. This is the
// bigger of the two defects being fixed — a sweep of an ordinary project
// counted package.json as a policy, inflated the rule total with it, and
// emitted a hard ERROR (exit 2) on tsconfig.json, breaking the CI gate
// docs/policy-audit.md tells operators to wire up.
//
// A non-nil skip and a non-empty entry list can be returned together: that is
// a real policy bundle with some non-policy entries in it.
func loadPolicyEntries(path string, explicit bool) ([]rawPolicyEntry, *policySkip, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if explicit {
			return nil, nil, fmt.Errorf("read: %w", err)
		}
		// Coverage LOSS, not filtering: this file matched the policy
		// extension filter, so it is a CANDIDATE we could not evaluate.
		// Same rule as scan_repo.go — only candidates escalate, which
		// keeps ordinary permission noise elsewhere in the tree quiet.
		return nil, &policySkip{Path: path, Reason: policySkipReason(err), Unreadable: true}, nil
	}
	doc, err := parsePolicyDoc(data, path)
	if err != nil {
		if explicit {
			return nil, nil, err
		}
		// The skip row already names the path; parsePolicyDoc repeats it in
		// the message, so trim it back out rather than printing it twice.
		detail := strings.TrimPrefix(flattenErr(err), "parse "+path+": ")
		return nil, &policySkip{
			Path:   path,
			Reason: "not a policy document (" + detail + ")",
		}, nil
	}
	if explicit {
		return doc.policies, nil, nil
	}
	kept := make([]rawPolicyEntry, 0, len(doc.policies))
	for _, e := range doc.policies {
		if looksLikePolicyEntry(e.raw) {
			kept = append(kept, e)
		}
	}
	switch {
	case len(kept) == 0:
		return nil, &policySkip{Path: path, Reason: "not a policy document (no policy fields)"}, nil
	case len(kept) < len(doc.policies):
		return kept, &policySkip{
			Path: path,
			Reason: fmt.Sprintf("%d of %d entries are not policy documents",
				len(doc.policies)-len(kept), len(doc.policies)),
		}, nil
	}
	return kept, nil, nil
}

// lintFileResult is one file's contribution to the report.
type lintFileResult struct {
	findings []lintFinding
	rules    int
	skip     *policySkip
}

func lintOnePolicyFile(path string, explicit bool) (lintFileResult, error) {
	entries, skip, err := loadPolicyEntries(path, explicit)
	if err != nil {
		return lintFileResult{}, err
	}
	res := lintFileResult{skip: skip, rules: len(entries)}
	for _, e := range entries {
		res.findings = append(res.findings, lintPolicy(path, e)...)
	}
	return res, nil
}

// lintPolicyFile is the strict (explicitly-named-file) entry point.
func lintPolicyFile(path string) ([]lintFinding, int, error) {
	res, err := lintOnePolicyFile(path, true)
	if err != nil {
		return nil, 0, err
	}
	return res.findings, res.rules, nil
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
		out.policies = append(out.policies, rawPolicyEntry{policy: p, raw: jb, line: n.Line, name: name})
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
	out = append(out, checkMatchAllThreshold(file, e)...)
	return out
}

// checkMatchAllThreshold reports every numeric condition the evaluator can
// never satisfy, or always satisfies.
//
// It delegates the whole decision to policy.AuditPolicyRanges — the same
// function `chainsaw policy audit` and Store.AuditRanges call — for the same
// reason checkStandaloneCodesmell delegates to
// policy.StandaloneContextOnlyViolation: a policy FILE and the live ROW it
// becomes must not classify the same threshold differently. Only the
// rendering into lint's finding shape is local.
//
// The look-alike this replaced was a hand-rolled two-field check: it flagged
// `cvssMin: 0` and `epssMin: 0` and nothing else, so seven of the classifier's
// nine bounded fields were invisible on the file path, and the whole
// never-fires half of the classification (`cvssMin: 999` — a value
// Store.Create refuses outright) linted clean. It also could not tell a
// match-all that decides the policy's whole behaviour from one sitting beside
// a real narrowing condition, because AND-ed conditions were not in its model.
//
// No value is reported twice. The classifier reports a min>max pair on the MIN
// field alone (never once per half), and it compares a pair only when both
// halves are individually legal — which is disjoint from the per-field check,
// since that one fires only on a value at or outside its signal's domain. Lint
// adds no range check of its own on top, so one bad threshold stays one
// finding; TestPolicyLint_RangeAuditAgreesWithClassifier pins it.
func checkMatchAllThreshold(file string, e rawPolicyEntry) []lintFinding {
	audit := policy.AuditPolicyRanges("", []policy.Policy{e.policy})
	out := make([]lintFinding, 0, len(audit))
	for _, a := range audit {
		out = append(out, lintFinding{
			File:       file,
			Line:       e.line,
			Rule:       e.name,
			Severity:   lintSeverityForRangeAudit(a.Severity),
			Type:       lintTypeForRangeEffect(a.Effect),
			Message:    rangeAuditMessage(a),
			Suggestion: a.Suggestion,
		})
	}
	return out
}

// lintSeverityForRangeAudit maps the classifier's severity onto lint's.
//
// The two vocabularies coincide today — both are exactly {error, warning},
// and they mean the same thing: error is a value Store.Create would refuse,
// warning is a legal value that is nevertheless degenerate. The mapping is
// still written out rather than passed through, so a severity added to the
// classifier later cannot arrive as a string lint's exit ladder does not
// count: runPolicyLint's tally switch matches only the two constants, and an
// unrecognised third value would print in the findings list while leaving the
// exit code at 0. Anything unrecognised therefore lands on WARNING — reported
// and non-zero, never silently clean, and never escalated to a CI-breaking
// error on lint's guess.
func lintSeverityForRangeAudit(severity string) string {
	if severity == policy.RangeAuditSeverityError {
		return lintFindingError
	}
	return lintFindingWarning
}

// lintTypeForRangeEffect names the finding after what the value DOES, which
// is the distinction an operator acts on: a never-fires rule is dead and a
// match-all rule is over-broad, and the two need opposite edits.
func lintTypeForRangeEffect(effect string) string {
	if effect == policy.RangeEffectNeverFires {
		return lintTypeNeverFiresThreshold
	}
	return lintTypeMatchAllThreshold
}

// rangeAuditMessage renders one classifier finding as a lint message.
//
// The consequence is the classifier's own sentence, verbatim: it is derived
// from the evaluator's compare and from this policy's kind, mode and status,
// so quoting it is what keeps lint and audit saying the same thing about the
// same policy. Only the "rule sets <field>: <value>" lead-in is lint's, and
// it uses the classifier's dotted field name so a finding can be grepped
// across both surfaces.
func rangeAuditMessage(a policy.RangeAuditFinding) string {
	lead := fmt.Sprintf("rule sets %s: %s", a.Field, formatRangeValue(a.Value))
	if a.Consequence == "" {
		// Defensive: the classifier returns an empty consequence only for an
		// effect it has no sentence for. Say what is known rather than
		// emitting a finding with no reason attached.
		return fmt.Sprintf("%s, which is outside the valid range (%s)", lead, a.ValidRange)
	}
	return lead + " — " + a.Consequence
}

// formatRangeValue renders a threshold the way it was authored: 0, 7, 0.1,
// 999 — no trailing zeros, no exponent for the magnitudes these fields take.
func formatRangeValue(v float64) string {
	return strconv.FormatFloat(v, 'g', -1, 64)
}

// checkStandaloneCodesmell reports the same finding the save-time validator
// rejects on: a policy whose ONLY signal is one of the five demoted codesmell
// conditions, with no other condition, identifier, or scope.
//
// It delegates the whole decision to policy.StandaloneContextOnlyViolation —
// the same function core/policy/store.go's
// rejectStandaloneContextOnlyConditions calls — so the two surfaces cannot
// disagree; only the message formatting is local. The look-alike this replaced
// carried its own copy of the old ConditionsUsedBy-based predicate and
// inherited its false rejections, so `chainsaw policy lint` reported errors on
// valid policies before the operator ever reached the API.
func checkStandaloneCodesmell(file string, e rawPolicyEntry) *lintFinding {
	contextOnly := policy.StandaloneContextOnlyViolation(e.policy.Conditions, e.policy.Identifier, e.policy.Scope)
	if len(contextOnly) == 0 {
		return nil
	}
	names := make([]string, len(contextOnly))
	for i, c := range contextOnly {
		names[i] = string(c)
	}
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

// rawHasField searches the entry's ORIGINAL JSON bytes for the named
// key — the bytes parsePolicyDoc produced from the user's YAML/JSON
// before typing them.
//
// It used to re-marshal e.policy, the TYPED struct. That could never
// find repoArchived: encoding/json drops unknown keys on the way in, and
// policy.Conditions has no repoArchived field (it lives on the
// intelligence/risk side), so the round trip deleted exactly the key the
// check was looking for. The check advertised in the command's Long help
// was dead code from the day it was written.
//
// Substring search is fine — the condition key names are namespaced
// enough that the false-positive risk is negligible at our scale.
func rawHasField(e rawPolicyEntry, key string) bool {
	if len(e.raw) == 0 {
		return false
	}
	return strings.Contains(string(e.raw), `"`+key+`":`)
}

// The local hasIdentifier / hasScope look-alikes that used to live here
// are gone. They accepted "*" as a pairing while the save-time validator
// (policy.HasMeaningfulIdentifier / HasMeaningfulScope, over
// hasMeaningfulValue) rejects "", "*" and "all" alike — so a policy
// whose only pairing was a wildcard identifier linted "clean" and was
// then rejected by rejectStandaloneContextOnlyConditions on POST. This
// file's whole reason to exist is catching that rejection first, so it
// now calls the validator's own predicates. One implementation, no
// drift.
