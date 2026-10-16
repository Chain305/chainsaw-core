package cli

// `chainsaw pr-scan` diffs manifest/lockfile changes between two git refs and
// flags newly added or upgraded dependencies for supply-chain review.  It is
// the CLI companion to the Chainsaw Guard GitHub Action and closes the gap
// between the existing bypass-file scanner and Socket.dev's per-package PR
// comment behaviour.
//
// Exit codes:
//
//	0  clean (no warn/block findings)
//	10 one or more warning-level findings
//	20 one or more blocking findings
//	30 one or more monitored manifests failed to parse (deps may be dropped)
//
// With --strict, warn-level findings are treated as blocking (exit 20).
//
// Note: pr-scan evaluates added/upgraded dependencies with offline heuristics
// only — it does not consult the server. Run `chainsaw scan` for full signals.
//
// The heuristics themselves only ever emit severity "warn". Exit 20 without
// --strict comes from the policy decision point (policy.SurfacePR — see the
// "Policy decision point" section below), where an operator rule raises a
// specific signal to block while the rest stay warn.
//
// Supported ecosystems (covers ~90 % of real-world PRs):
//   - npm:      package.json, package-lock.json, npm-shrinkwrap.json,
//     pnpm-lock.yaml, yarn.lock
//   - pip:      requirements.txt, Pipfile.lock, poetry.lock, uv.lock
//   - rubygems: Gemfile.lock
//   - go:       go.sum
//
// TODO: add maven (pom.xml), gradle (build.gradle), nuget (*.csproj /
// packages.lock.json), cargo (Cargo.lock), composer (composer.lock),
// cocoapods (Podfile.lock), swift (Package.resolved), docker, apt, yum.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/depparser/origin"
	gosum "github.com/chain305/chainsaw-core/depparser/parser/golang/sum"
	"github.com/chain305/chainsaw-core/depparser/parser/nodejs/nodesource"
	npmlock "github.com/chain305/chainsaw-core/depparser/parser/nodejs/npm"
	"github.com/chain305/chainsaw-core/depparser/parser/nodejs/pnpm"
	"github.com/chain305/chainsaw-core/depparser/parser/nodejs/yarn"
	"github.com/chain305/chainsaw-core/depparser/parser/python/pipenv"
	"github.com/chain305/chainsaw-core/depparser/parser/python/poetry"
	"github.com/chain305/chainsaw-core/depparser/parser/python/requirements"
	uvlock "github.com/chain305/chainsaw-core/depparser/parser/python/uv"
	"github.com/chain305/chainsaw-core/depparser/parser/ruby/bundler"
	ftypes "github.com/chain305/chainsaw-core/fanal"
	"github.com/chain305/chainsaw-core/githubactions"
	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/policy"
	"github.com/chain305/chainsaw-core/policy/dsl"
	"github.com/chain305/chainsaw-core/policyengine"
	"github.com/chain305/chainsaw-core/risk"
	"github.com/chain305/chainsaw-core/typosquat"
)

// pr-scan exit codes — distinct from the doctor matrix so a CI step that
// combines both gets a predictable non-zero without ambiguity.
const (
	prScanExitOK       = 0
	prScanExitWarning  = 10
	prScanExitBlocking = 20
	// Aliased to the shared constant so "dependencies were dropped" is one
	// number with one meaning across the CLI — `scan --path` returns the same
	// 30 for the same condition (see exitcodes.go). The value is unchanged.
	prScanExitParseError = ExitManifestParseError
)

// prScanSignal is a single supply-chain signal attached to a coordinate.
type prScanSignal struct {
	ID       string `json:"id"`
	Severity string `json:"severity"` // "warn" or "block"
	Reason   string `json:"reason"`
}

// prScanEntry is one added or upgraded dependency in the report.
type prScanEntry struct {
	Ecosystem       string  `json:"ecosystem"`
	Name            string  `json:"name"`
	Version         string  `json:"version"`
	PreviousVersion *string `json:"previous_version"`
	// Origin is set only for a package the lockfile builds from somewhere
	// other than the public registry (see nonRegistryDep). Such a row is
	// not assessed: one prScanNotAssessedSignalID signal, verdict "warn".
	Origin  string         `json:"origin,omitempty"`
	Signals []prScanSignal `json:"signals"`
	Verdict string         `json:"verdict"` // "allow", "warn", or "block"
}

// prScanSummary is the aggregate counters at the bottom of the report.
type prScanSummary struct {
	Added       int `json:"added"`
	Upgraded    int `json:"upgraded"`
	Blocking    int `json:"blocking"`
	Warnings    int `json:"warnings"`
	ParseErrors int `json:"parse_errors,omitempty"`
}

// prScanReport is the top-level JSON output document.
type prScanReport struct {
	Schema   string        `json:"schema"`
	Mode     string        `json:"mode"`
	Base     string        `json:"base"`
	Head     string        `json:"head"`
	Added    []prScanEntry `json:"added"`
	Upgraded []prScanEntry `json:"upgraded"`
	Summary  prScanSummary `json:"summary"`
}

func init() {
	cmd := &cobra.Command{
		Use:     "pr-scan",
		GroupID: GrpScan,
		Short:   "Diff manifest/lockfile changes and flag added or upgraded dependencies",
		Long: `Compares manifest and lockfile files between two git refs and reports every
newly added or upgraded dependency coordinate (name@version). For each
coordinate the offline signal engine emits supply-chain signals; the final
verdict is "allow", "warn", or "block".

Changed GitHub Actions workflows (.github/workflows/*.yml, action.yml) are
inspected too: every added or changed uses: ref gets the scan-actions
signals (action.*), and a known-compromised action blocks.

Intended as a required-status-check companion to chainsaw scan-repo: scan-repo
catches committed bypass config; pr-scan catches newly introduced packages.

Verdicts use offline heuristics only — run "chainsaw scan" for full signals.

Exit codes:
  0   clean — no warn or block findings
  10  one or more warning-level findings
  20  one or more blocking findings (also exit 20 with --strict + any warning)
  30  one or more monitored manifests failed to parse (dependencies dropped)`,
		RunE: runPRScan,
	}
	cmd.Flags().String("base", "", "Base git ref or SHA to diff from (required)")
	cmd.Flags().String("head", "HEAD", "Head git ref or SHA to diff to (default: HEAD)")
	cmd.Flags().String("repo-path", ".", "Path to the git repository")
	// P8-27 — no local --json. The root persistent --json (root.go) is
	// documented as sugar for --format=json and both useJSON and resolveFormat
	// read it, so the shadow was redundant; it is also the mechanism behind
	// scan-remote's S1 gate-disarm, so it does not get to survive here on the
	// grounds that pr-scan's own gate happens to be format-independent.
	cmd.Flags().String("output-file", "", "Write the report to this path (JSON by default; SARIF with --format=sarif)")
	cmd.Flags().Bool("strict", false, "Escalate warnings to blocking (exit 20 instead of 10)")
	_ = cmd.MarkFlagRequired("base")
	rootCmd.AddCommand(cmd)
}

func runPRScan(cmd *cobra.Command, _ []string) error {
	base, _ := cmd.Flags().GetString("base")
	head, _ := cmd.Flags().GetString("head")
	repoPath, _ := cmd.Flags().GetString("repo-path")
	outputFile, _ := cmd.Flags().GetString("output-file")
	strict, _ := cmd.Flags().GetBool("strict")

	absRepo, err := filepath.Abs(repoPath)
	if err != nil {
		return fmt.Errorf("resolve repo-path: %w", err)
	}

	// Resolve the base/head refs to full SHAs for stable report identity.
	baseSHA, err := resolveRef(absRepo, base)
	if err != nil {
		return fmt.Errorf("resolve base ref %q: %w", base, err)
	}
	headSHA, err := resolveRef(absRepo, head)
	if err != nil {
		return fmt.Errorf("resolve head ref %q: %w", head, err)
	}

	report, exitCode, buildErr := buildPRScanReport(baseSHA, headSHA, absRepo)
	if buildErr != nil {
		return buildErr
	}

	// Write output. SARIF (P1.6) is a distinct, opt-in representation selected
	// only by --format=sarif; it is mutually exclusive with the legacy JSON
	// (--json / --output-file) and text paths, which stay byte-compatible.
	if resolveFormat(cmd) == "sarif" {
		// C10: --output-file is pr-scan's OWN flag; the persistent --output that
		// outWriter honours is a different one. Before this, `--format=sarif
		// --output-file results.sarif` wrote the document to stdout, created no
		// file, and reported success — the following upload-sarif step then
		// failed on a missing file or uploaded a stale artifact. Render into a
		// buffer and write the file explicitly rather than handing a deferred
		// *os.File to the encoder: os.WriteFile has no unflushed-buffer window
		// at all, so the document CI consumes can never be truncated. (This
		// used to also be load-bearing because runPRScan ended in os.Exit,
		// which skips deferred Close; that exit now goes through Execute()
		// — see the return below — but the explicit write stays.)
		if outputFile != "" {
			var buf bytes.Buffer
			if err := writePRScanSARIF(&buf, report); err != nil {
				return fmt.Errorf("write sarif: %w", err)
			}
			if err := os.WriteFile(outputFile, buf.Bytes(), 0o644); err != nil {
				return fmt.Errorf("write output file: %w", err)
			}
		} else if err := writePRScanSARIF(outWriter(cmd), report); err != nil {
			return fmt.Errorf("write sarif: %w", err)
		}
	} else {
		jsonOut := useJSON(cmd) || outputFile != ""
		if outputFile != "" {
			data, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal report: %w", err)
			}
			if err := os.WriteFile(outputFile, append(data, '\n'), 0o644); err != nil {
				return fmt.Errorf("write output file: %w", err)
			}
		}
		if jsonOut && outputFile == "" {
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			_ = enc.Encode(report)
		} else if !jsonOut {
			printPRScanReport(cmd, report)
		}
	}

	// Apply --strict escalation.
	if strict && exitCode == prScanExitWarning {
		exitCode = prScanExitBlocking
	}

	// Y3/Y4 — return the code instead of calling os.Exit. A bare os.Exit here
	// never returned to Execute(), so the entire telemetry batch (including
	// the cli.session.completed carrying exit_code and error_class) was
	// dropped on every non-clean pr-scan — measured as 0 session-completed
	// events for an exit-10 run. The custom 10/20/30 values are unchanged:
	// ExitCodeError carries an arbitrary code. Err stays nil so renderError
	// prints nothing on top of the report the command already emitted.
	if exitCode != prScanExitOK {
		return &ExitCodeError{Code: exitCode}
	}
	return nil
}

// buildPRScanReport is the testable core: resolves changed manifests, diffs
// them, evaluates signals, and returns the completed report + exit code.
// The repoPath must already be an absolute path; baseSHA/headSHA must be
// fully resolved git object identifiers.
func buildPRScanReport(baseSHA, headSHA, absRepo string) (prScanReport, int, error) {
	report := prScanReport{
		Schema:   "chainsaw.pr-scan/v1",
		Mode:     "offline-heuristics",
		Base:     baseSHA,
		Head:     headSHA,
		Added:    []prScanEntry{},
		Upgraded: []prScanEntry{},
	}

	// C5: compare against the MERGE BASE, not the base tip, so the report
	// describes what this PR changed rather than what base changed underneath
	// it. report.Base keeps the caller's --base for identity; diffBase is the
	// commit both the file list and the base CONTENT reads are taken from.
	diffBase := prScanDiffBase(absRepo, baseSHA, headSHA)

	// Find changed manifest/lockfile paths.
	changedFiles, err := gitDiffFiles(absRepo, diffBase, headSHA)
	if err != nil {
		return report, prScanExitOK, fmt.Errorf("git diff: %w", err)
	}

	// Track manifests we failed to parse — a parse failure silently drops the
	// manifest's deps, so we must never report exit 0 when one occurred.
	parseFailures := 0

	for _, rel := range changedFiles {
		eco, ok := classifyManifest(rel)
		workflow := !ok && isWorkflowFile(rel)
		if !ok && !workflow {
			continue
		}

		baseContent, _ := gitFileAtRef(absRepo, diffBase, rel)
		// baseContent may be nil — file newly created at head.

		headContent, err := gitFileAtRef(absRepo, headSHA, rel)
		if err != nil {
			// C1: a REAL git failure on a monitored path that the diff says
			// changed is not the same thing as a removal. We cannot know what
			// the PR did to this manifest, so it must count against the exit
			// code exactly like a parse failure — never a silent exit 0.
			fmt.Fprintf(os.Stderr, "pr-scan: read %s at head: %v\n", rel, err)
			parseFailures++
			continue
		}
		if headContent == nil {
			// File genuinely absent at head — removed by this PR. Removals are
			// risk-reduction, so there is nothing to evaluate.
			continue
		}

		if workflow {
			added, upgraded, parseErr := diffWorkflow(rel, baseContent, headContent)
			if parseErr != nil {
				fmt.Fprintf(os.Stderr, "pr-scan: parse %s: %v\n", rel, parseErr)
				parseFailures++
				continue
			}
			report.Added = append(report.Added, added...)
			report.Upgraded = append(report.Upgraded, upgraded...)
			continue
		}

		added, upgraded, parseErr := diffManifest(eco, rel, baseContent, headContent)
		if parseErr != nil {
			// Best-effort: log and continue, but record the failure so the
			// exit code reflects that this manifest's deps were dropped.
			fmt.Fprintf(os.Stderr, "pr-scan: parse %s: %v\n", rel, parseErr)
			parseFailures++
			continue
		}

		for _, e := range added {
			report.Added = append(report.Added, evaluatePREntry(e))
		}
		for _, e := range upgraded {
			report.Upgraded = append(report.Upgraded, evaluatePREntry(e))
		}
	}

	// Sort for deterministic output.
	// Origin breaks the tie between a fork and its registry namesake.
	sort.Slice(report.Added, func(i, j int) bool {
		a, b := report.Added[i], report.Added[j]
		return a.Ecosystem+a.Name+"\x00"+a.Origin < b.Ecosystem+b.Name+"\x00"+b.Origin
	})
	sort.Slice(report.Upgraded, func(i, j int) bool {
		a, b := report.Upgraded[i], report.Upgraded[j]
		return a.Ecosystem+a.Name+"\x00"+a.Origin < b.Ecosystem+b.Name+"\x00"+b.Origin
	})

	// Build summary.
	report.Summary.Added = len(report.Added)
	report.Summary.Upgraded = len(report.Upgraded)
	report.Summary.ParseErrors = parseFailures
	for _, e := range append(report.Added, report.Upgraded...) {
		switch e.Verdict {
		case "block":
			report.Summary.Blocking++
		case "warn":
			report.Summary.Warnings++
		}
	}

	// Determine exit code.
	exitCode := prScanExitOK
	if report.Summary.Blocking > 0 {
		exitCode = prScanExitBlocking
	} else if report.Summary.Warnings > 0 {
		exitCode = prScanExitWarning
	}

	// A dropped manifest must never report exit 0/10. Escalate to the
	// parse-error code, but let a real block (20) still outrank it.
	if parseFailures > 0 && exitCode < prScanExitBlocking {
		exitCode = prScanExitParseError
	}

	return report, exitCode, nil
}

// resolveRef converts any git ref (branch name, tag, HEAD~N, full SHA, etc.)
// to a canonical full-length commit SHA by running `git rev-parse`.
//
// C14: --end-of-options stops a user-supplied --base/--head that starts with
// "-" from being parsed as a rev-parse OPTION. Without it, `--base
// --show-toplevel` printed a path, resolveRef's only check ("non-empty") passed,
// and that path flowed into the diff as if it were a SHA. --verify + ^{commit}
// tightens the contract further: the ref must resolve to exactly one commit, so
// the Action's silent shallow-checkout failure (base.sha absent from a
// fetch-depth:1 clone) becomes a clear error instead of a confusing diff.
func resolveRef(repoPath, ref string) (string, error) {
	out, err := runGit(repoPath, "rev-parse", "--verify", "--end-of-options", ref+"^{commit}")
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(out)
	if sha == "" {
		return "", fmt.Errorf("empty output from git rev-parse %s", ref)
	}
	return sha, nil
}

// prScanDiffBase resolves the commit a PR should be compared AGAINST: the merge
// base of base and head.
//
// C5: pr-scan used to diff base's TIP against head (two-dot). That reports every
// change made on base since the branch forked as though the PR made it —
// verified in the wild as "lodash upgraded 4.17.21 → 4.17.20", a downgrade the
// PR never touched, and symmetrically it hides a dependency added to base after
// the fork point. GitHub's "Files changed" (and every other PR review surface)
// is three-dot / merge-base.
//
// This returns the base COMMIT rather than composing a `base...head` diff
// expression on purpose: buildPRScanReport also reads each manifest's base
// CONTENT with `git show <base>:<path>`, and that read has to move to the merge
// base too. Fixing only the file list would leave the version numbers wrong.
//
// A shallow clone (actions/checkout's default fetch-depth: 1) may not have the
// merge base in its object store. Rather than hard-fail the gate, fall back to
// the caller's base and say so — a noisier report beats no report — with the
// one-line fix named.
func prScanDiffBase(repoPath, base, head string) string {
	out, err := runGit(repoPath, "merge-base", base, head)
	if err == nil {
		if sha := strings.TrimSpace(out); sha != "" {
			return sha
		}
	}
	fmt.Fprintf(os.Stderr, "pr-scan: could not compute the merge base of %s and %s (%v); "+
		"comparing against the base tip instead "+glyphs().dash+" the report may list changes this PR "+
		"did not make. Add `fetch-depth: 0` to the checkout step to fix.\n",
		base, head, err)
	return base
}

// gitDiffFiles returns the list of files that differ between base and head.
//
// C1: -z is mandatory. git's default core.quotePath=true wraps any path with a
// non-ASCII, control, or quote byte in literal double quotes with octal escapes,
// so `日本/package.json` arrived as `"\346\227\245\346\234\254/package.json"`;
// filepath.Base then yielded `package.json"`, classifyManifest missed, and the
// manifest was dropped with no counter and no stderr line — exit 0 on a PR that
// added malware. -z is preferred over -c core.quotePath=false because only -z
// also survives a literal newline inside a filename.
func gitDiffFiles(repoPath, base, head string) ([]string, error) {
	out, err := runGit(repoPath, "diff", "-z", "--name-only", base, head)
	if err != nil {
		return nil, err
	}
	var files []string
	// -z emits NUL-terminated, UNQUOTED paths. Do not TrimSpace an entry: a
	// leading or trailing space is a legal part of a filename, and trimming it
	// would reintroduce the drop this flag exists to prevent.
	for _, entry := range strings.Split(out, "\x00") {
		if entry != "" {
			files = append(files, entry)
		}
	}
	return files, nil
}

// gitFileAtRef returns the raw bytes of a file at a specific git ref using
// `git show <ref>:<path>`. Returns (nil, nil) when the file does not exist at
// that ref (e.g. newly created files at base).
func gitFileAtRef(repoPath, ref, relPath string) ([]byte, error) {
	object := ref + ":" + relPath
	cmd := exec.Command("git", "show", object)
	cmd.Dir = repoPath
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		// Exit code 128 means the path doesn't exist at that ref — treat as nil.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 128 {
			return nil, nil
		}
		return nil, fmt.Errorf("git show %s: %w", object, err)
	}
	return stdout.Bytes(), nil
}

// runGit executes a git command in repoPath and returns combined stdout.
func runGit(repoPath string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = repoPath
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %w (stderr: %s)", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// manifestKind is the canonical parser key for a manifest/lockfile type.
type manifestKind string

const (
	kindNPMPackageJSON  manifestKind = "npm:package.json"
	kindNPMPackageLock  manifestKind = "npm:package-lock.json"
	kindNPMShrinkwrap   manifestKind = "npm:npm-shrinkwrap.json"
	kindPNPMLock        manifestKind = "npm:pnpm-lock.yaml"
	kindYarnLock        manifestKind = "npm:yarn.lock"
	kindPipRequirements manifestKind = "pip:requirements.txt"
	kindPipfileLock     manifestKind = "pip:Pipfile.lock"
	kindPoetryLock      manifestKind = "pip:poetry.lock"
	kindUVLock          manifestKind = "pip:uv.lock"
	kindGemfileLock     manifestKind = "rubygems:Gemfile.lock"
	kindGoSum           manifestKind = "go:go.sum"
	kindCargoLock       manifestKind = "cargo:Cargo.lock"
)

// manifestClassifier maps file base-names (and sometimes partial paths) to
// their manifest kind.  The classifier intentionally handles both repo-root
// and monorepo sub-tree paths.
func classifyManifest(relPath string) (manifestKind, bool) {
	base := filepath.Base(relPath)
	switch base {
	case "package.json":
		return kindNPMPackageJSON, true
	case "package-lock.json":
		return kindNPMPackageLock, true
	case "npm-shrinkwrap.json":
		return kindNPMShrinkwrap, true
	case "pnpm-lock.yaml":
		return kindPNPMLock, true
	case "yarn.lock":
		return kindYarnLock, true
	case "Pipfile.lock":
		return kindPipfileLock, true
	case "poetry.lock":
		return kindPoetryLock, true
	case "uv.lock":
		return kindUVLock, true
	case "Gemfile.lock":
		return kindGemfileLock, true
	case "go.sum":
		return kindGoSum, true
	case "Cargo.lock":
		return kindCargoLock, true
	}
	// requirements.txt, requirements-dev.txt, etc.
	if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
		return kindPipRequirements, true
	}
	return "", false
}

// coordinate is a (name, version) pair parsed from a manifest.
type coordinate struct {
	Ecosystem string
	Name      string
	Version   string
}

// rawEntry is an intermediate struct before signal evaluation.
type rawEntry struct {
	Ecosystem       string
	Name            string
	Version         string
	PreviousVersion *string
	Origin          string // non-empty: not from the public registry (nonRegistryDep)
	Hash            string // nonRegistryDep.Hash
	// SourceChange is "source changed: <base> → <head>" when this row is a
	// dependency whose source differs from base (markSourceChanges).
	SourceChange string
}

// diffManifest returns lists of added and upgraded coordinates by comparing
// base and head content. baseContent may be nil (file newly added at head).
func diffManifest(kind manifestKind, relPath string, baseContent, headContent []byte) (added, upgraded []rawEntry, err error) {
	eco := strings.SplitN(string(kind), ":", 2)[0]

	var baseCoords, headCoords map[string]string // name → version
	var baseNonReg, headNonReg []nonRegistryDep  // packages not from the public registry
	switch kind {
	case kindNPMPackageLock, kindNPMShrinkwrap:
		baseCoords, err = parsePackageLockJSON(baseContent)
		if err != nil {
			return nil, nil, fmt.Errorf("%s base: %w", relPath, err)
		}
		headCoords, err = parsePackageLockJSON(headContent)
		if err != nil {
			return nil, nil, fmt.Errorf("%s head: %w", relPath, err)
		}
		// Git, tarball and undeclared-registry packages, which the map
		// above leaves out; workspace members are first-party: no row.
		if _, baseNonReg, err = parsePackageLockCoordinates(baseContent); err != nil {
			return nil, nil, fmt.Errorf("%s base: %w", relPath, err)
		}
		if _, headNonReg, err = parsePackageLockCoordinates(headContent); err != nil {
			return nil, nil, fmt.Errorf("%s head: %w", relPath, err)
		}
		baseNonReg, headNonReg = npmNonLocal(baseNonReg), npmNonLocal(headNonReg)
	case kindNPMPackageJSON:
		baseCoords, baseNonReg, err = parsePackageJSONDeps(baseContent)
		if err != nil {
			return nil, nil, fmt.Errorf("%s base: %w", relPath, err)
		}
		headCoords, headNonReg, err = parsePackageJSONDeps(headContent)
		if err != nil {
			return nil, nil, fmt.Errorf("%s head: %w", relPath, err)
		}
	case kindPNPMLock, kindYarnLock:
		// Coordinates, not a name->version map: one lockfile holds a name at
		// several versions, and a fork beside its registry namesake.
		parse := parseYarnLock
		if kind == kindPNPMLock {
			parse = parsePNPMLock
		}
		baseMulti, baseNonReg, err := parse(baseContent)
		if err != nil {
			return nil, nil, fmt.Errorf("%s base: %w", relPath, err)
		}
		headMulti, headNonReg, err := parse(headContent)
		if err != nil {
			return nil, nil, fmt.Errorf("%s head: %w", relPath, err)
		}
		added, upgraded = diffLockCoordinates(eco, baseMulti, headMulti)
		// Workspace / link / file: packages are first-party: no row.
		baseNonReg, headNonReg = npmNonLocal(baseNonReg), npmNonLocal(headNonReg)
		nrAdded, nrUpgraded := diffNonRegistry(eco, baseNonReg, headNonReg)
		added, upgraded = markSourceChanges(eco, withRegistry(baseNonReg, baseMulti, nil), withRegistry(headNonReg, headMulti, nil),
			append(added, nrAdded...), append(upgraded, nrUpgraded...))
		return added, upgraded, nil
	case kindPipRequirements:
		baseCoords, baseNonReg = parsePipRequirementsSources(baseContent)
		headCoords, headNonReg = parsePipRequirementsSources(headContent)
	case kindPipfileLock, kindPoetryLock, kindUVLock:
		// One name can be locked at several versions (uv forks by marker),
		// so these diff as coordinates, like Cargo.lock. Local packages (the
		// editable project, path dependencies) are first-party: no row.
		file := strings.SplitN(string(kind), ":", 2)[1]
		baseMulti, baseNonReg, _, err := parsePythonLock(file, baseContent)
		if err != nil {
			return nil, nil, fmt.Errorf("%s base: %w", relPath, err)
		}
		headMulti, headNonReg, _, err := parsePythonLock(file, headContent)
		if err != nil {
			return nil, nil, fmt.Errorf("%s head: %w", relPath, err)
		}
		added, upgraded = diffLockCoordinates(eco, baseMulti, headMulti)
		nrAdded, nrUpgraded := diffNonRegistry(eco, baseNonReg, headNonReg)
		added, upgraded = markSourceChanges(eco, withRegistry(baseNonReg, baseMulti, nil), withRegistry(headNonReg, headMulti, nil),
			append(added, nrAdded...), append(upgraded, nrUpgraded...))
		return added, upgraded, nil
	case kindGemfileLock:
		if baseCoords, baseNonReg, err = parseGemfileLock(baseContent); err != nil {
			return nil, nil, fmt.Errorf("%s base: %w", relPath, err)
		}
		if headCoords, headNonReg, err = parseGemfileLock(headContent); err != nil {
			return nil, nil, fmt.Errorf("%s head: %w", relPath, err)
		}
	case kindGoSum:
		baseSum, err := parseGoSum(baseContent)
		if err != nil {
			return nil, nil, fmt.Errorf("%s base: %w", relPath, err)
		}
		headSum, err := parseGoSum(headContent)
		if err != nil {
			return nil, nil, fmt.Errorf("%s head: %w", relPath, err)
		}
		// No source changes: go.sum names module paths only, and a Go module
		// is fetched from its path (a go.mod replace is not diffed here).
		added, upgraded = diffLockCoordinates(eco, baseSum, headSum)
		return added, upgraded, nil
	case kindCargoLock:
		// Sourceless (workspace/path) crates are first-party: no row.
		baseMulti, baseNonReg, _ := parseCargoLock(baseContent)
		headMulti, headNonReg, _ := parseCargoLock(headContent)
		added, upgraded = diffLockCoordinates(eco, baseMulti, headMulti)
		nrAdded, nrUpgraded := diffNonRegistry(eco, baseNonReg, headNonReg)
		added, upgraded = markSourceChanges(eco, withRegistry(baseNonReg, baseMulti, nil), withRegistry(headNonReg, headMulti, nil),
			append(added, nrAdded...), append(upgraded, nrUpgraded...))
		return added, upgraded, nil
	default:
		return nil, nil, nil
	}

	if baseCoords == nil {
		baseCoords = map[string]string{}
	}

	for name, headVer := range headCoords {
		baseVer, existed := baseCoords[name]
		if !existed {
			added = append(added, rawEntry{Ecosystem: eco, Name: name, Version: headVer})
		} else if headVer != baseVer {
			prev := baseVer
			upgraded = append(upgraded, rawEntry{Ecosystem: eco, Name: name, Version: headVer, PreviousVersion: &prev})
		}
	}
	nrAdded, nrUpgraded := diffNonRegistry(eco, baseNonReg, headNonReg)
	added, upgraded = markSourceChanges(eco, withRegistry(baseNonReg, nil, baseCoords), withRegistry(headNonReg, nil, headCoords),
		append(added, nrAdded...), append(upgraded, nrUpgraded...))
	return added, upgraded, nil
}

// withRegistry is every dependency of one side of a diff with its source:
// nonReg as they are, and the registry packages (coords or m) with Origin ""
// — the public registry, or a mirror the user vouches for, which the
// parsers already count as the registry.
func withRegistry(nonReg []nonRegistryDep, coords []lockCoordinate, m map[string]string) []nonRegistryDep {
	out := append([]nonRegistryDep(nil), nonReg...)
	for _, c := range coords {
		out = append(out, nonRegistryDep{Name: c.Name, Version: c.Version})
	}
	names := make([]string, 0, len(m))
	for n := range m {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, nonRegistryDep{Name: n, Version: m[n]})
	}
	return out
}

// sourceKey is what "the same source" means for markSourceChanges: "" for
// the registry; the host for another registry (a version bump there moves
// the tarball URL, not the source; a different host is a different
// registry); the label otherwise — a repository with its ref, a tarball
// URL, a path — so a moved commit is a changed source.
func sourceKey(eco, src string) string {
	if src == "" {
		return ""
	}
	if origin.Classify(eco, src) == origin.RegistryOther {
		if h := origin.Host(src); h != "" {
			return "registry " + h
		}
	}
	return origin.Label(src)
}

// sourceLabel names a source in a "source changed" reason (originLabel).
func sourceLabel(eco, src string) string {
	if src == "" {
		return "the public registry"
	}
	return originLabel(eco, src)
}

// originLabel prints a lockfile origin in a reason: the host alone for a
// registry-protocol source (a private registry's access token rides in its
// PATH, dl.cloudsmith.io/<token>/…, where Sanitize cannot see it), and
// origin.Label otherwise — a git source keeps the repository and ref a
// reviewer needs.
func originLabel(eco, src string) string {
	if origin.Classify(eco, src) == origin.RegistryOther {
		if h := origin.Host(src); h != "" {
			return h
		}
	}
	return origin.Label(src)
}

// markSourceChanges finds the dependencies whose SOURCE changed between base
// and head: registry -> repository/URL/private registry, the reverse (the
// dependency-confusion direction: a private package now resolved publicly),
// or one non-registry source for another (another repository, a moved ref,
// another registry host), whether or not the version moved.
//
// Every such change is already a row: the diffs key on source, so the head
// package is an "added" row (drawing sc.new_dep, as if it were new). It is
// not given a second row: the added row whose name had a source in base that
// head dropped becomes an UPGRADE from that base version, with SourceChange
// set. A source head still has (a fork added beside its registry namesake)
// is a new dependency, not a change. Each dropped base source is claimed
// once. base and head are every dependency of each side (withRegistry); the
// row's Origin stays the head origin, which is what policy evaluates.
func markSourceChanges(eco string, base, head []nonRegistryDep, added, upgraded []rawEntry) ([]rawEntry, []rawEntry) {
	type nameSource struct{ name, key string }
	inHead := make(map[nameSource]bool, len(head))
	for _, d := range head {
		inHead[nameSource{d.Name, sourceKey(eco, d.Origin)}] = true
	}
	dropped := map[string][]nonRegistryDep{}
	for _, d := range base {
		if !inHead[nameSource{d.Name, sourceKey(eco, d.Origin)}] {
			dropped[d.Name] = append(dropped[d.Name], d)
		}
	}
	if len(dropped) == 0 {
		return added, upgraded
	}
	kept := make([]rawEntry, 0, len(added))
	for _, e := range added {
		ds := dropped[e.Name]
		if len(ds) == 0 {
			kept = append(kept, e)
			continue
		}
		dropped[e.Name] = ds[1:]
		prev := ds[0].Version
		e.PreviousVersion = &prev
		e.SourceChange = "source changed: " + sourceLabel(eco, ds[0].Origin) + " → " + sourceLabel(eco, e.Origin)
		upgraded = append(upgraded, e)
	}
	return kept, upgraded
}

// diffNonRegistry diffs packages from outside the public registry on (name,
// origin), never on name alone: a fork and its registry namesake are two
// packages. The origin carries the git revision, so a moved rev is a new row
// even at the same version.
func diffNonRegistry(eco string, base, head []nonRegistryDep) (added, upgraded []rawEntry) {
	baseVer := make(map[string]string, len(base))
	for _, d := range base {
		baseVer[d.Name+"\x00"+d.Origin] = d.Version
	}
	for _, d := range head {
		prev, existed := baseVer[d.Name+"\x00"+d.Origin]
		if !existed {
			added = append(added, rawEntry{Ecosystem: eco, Name: d.Name, Version: d.Version, Origin: d.Origin, Hash: d.Hash})
		} else if d.Version != prev {
			upgraded = append(upgraded, rawEntry{Ecosystem: eco, Name: d.Name, Version: d.Version, PreviousVersion: &prev, Origin: d.Origin, Hash: d.Hash})
		}
	}
	return added, upgraded
}

// diffLockCoordinates diffs lockfiles that hold one name at several versions
// (Cargo.lock: syn 1.x beside syn 2.x). A head coordinate absent from base is
// an UPGRADE when base had that name at a version head dropped (the version
// it replaced), otherwise an ADDITION — a second major line next to the old
// one is a new dependency, not a bump.
func diffLockCoordinates(eco string, base, head []lockCoordinate) (added, upgraded []rawEntry) {
	inBase, inHead, replaced := map[lockCoordinate]bool{}, map[lockCoordinate]bool{}, map[lockCoordinate]bool{}
	baseVers := map[string][]string{}
	for _, c := range base {
		inBase[c] = true
		baseVers[c.Name] = append(baseVers[c.Name], c.Version)
	}
	for _, c := range head {
		inHead[c] = true
	}
	for _, c := range head {
		if inBase[c] {
			continue
		}
		e := rawEntry{Ecosystem: eco, Name: c.Name, Version: c.Version}
		for _, v := range baseVers[c.Name] {
			if prev := (lockCoordinate{Name: c.Name, Version: v}); !inHead[prev] && !replaced[prev] {
				// Each dropped version is replaced once; Cargo.lock lists
				// versions ascending, so the lowest new one claims it.
				replaced[prev] = true
				e.PreviousVersion = &v
				break
			}
		}
		if e.PreviousVersion == nil {
			added = append(added, e)
		} else {
			upgraded = append(upgraded, e)
		}
	}
	return added, upgraded
}

// ---------------------------------------------------------------------------
// Manifest parsers
// ---------------------------------------------------------------------------

// utf8BOM is the UTF-8 byte-order mark.
//
// C3: npm 10.9.8 parses a BOM-prefixed package.json without complaint; Go's
// encoding/json rejects it ("invalid character 'ï'"). Three bytes at the head of
// the file — invisible in a GitHub diff view — were therefore enough to make
// pr-scan drop the whole manifest. Stripping it is not cosmetic: it closes a
// working, attacker-usable gate bypass. Applied to every JSON manifest parser so
// the class cannot come back through a sibling.
var utf8BOM = []byte{0xEF, 0xBB, 0xBF}

func stripUTF8BOM(data []byte) []byte { return bytes.TrimPrefix(data, utf8BOM) }

// prScanNestedLockNames enables G5b part B: deriving a package-lock entry's name
// from the LAST "node_modules/" segment of its path rather than the first, so a
// transitively-deduped entry like "node_modules/foo/node_modules/electorn" is
// scanned as "electorn" instead of the un-matchable "foo/node_modules/electorn".
//
// DEFAULT OFF — this is a measurement gate, not an oversight.
//
// Part B newly exposes every TRANSITIVE dependency to the offline typosquat
// ladder, a surface that had never been measured. The measurement was run
// (TestParsePackageLockJSON_NestedNamesTyposquatFPRate, which executes whether or
// not this constant is set) over 1,200 real popular npm names from
// seeds/npm_popular.txt laid out in create-react-app- and Next.js-shaped nested
// trees:
//
//	22 sc.typosquat_low signals / 1,200 real packages = 1.83%
//	0 blocking verdicts (pr-scan has no "block" severity at all — see C4)
//
// The hits are dominated by the curated seed's very short names once the npm
// scope is stripped: @babel/core, @eslint/core, @aws-sdk/core → "core", distance
// 1 from "cors"; ms, qs, jws, @types/qs → distance 1 from "ws"; gaxios → axios.
//
// Two facts matter for whoever makes the call:
//   - This rate is NOT new. The same ladder already runs at the same rate on
//     direct dependencies, which ship today.
//   - Part B does not add report ROWS. A nested entry already produced a row
//     (with a garbled name) and already drew sc.new_dep. Part B fixes the name
//     and adds a typosquat check to a row that was there either way.
//
// So the delta is ~1.8% of newly-added transitive deps gaining one extra warn
// line. That is a product decision about pr-scan's noise floor on a MERGE GATE,
// which is exactly the shape of the 742-FP incident, so it is not being made
// inside a bug-fix change. Flip this to true to enable; the measurement test is
// the live signal either way.
const prScanNestedLockNames = false

// lockEntryNameNested resolves a package-lock path to the name npm actually
// installs there: whatever follows the LAST node_modules/ boundary. Everything
// before it is the dedup location, not the identity.
//
// Split out from lockEntryName so the FP measurement can exercise part B's
// behaviour regardless of prScanNestedLockNames.
func lockEntryNameNested(path string) string {
	if idx := strings.LastIndex(path, "node_modules/"); idx >= 0 {
		return path[idx+len("node_modules/"):]
	}
	return ""
}

// lockNameMode selects how a package-lock "packages" key becomes a name.
//
// The two consumers of this parser want different answers, and conflating them
// was a live defect. pr-scan produces REPORT ROWS and its row identity is
// deliberately the first-node_modules form (see prScanNestedLockNames: changing
// it moves the noise floor on a merge gate, which is a product decision that is
// gated on measurement). The GUARD produces a lookup key into npm's own cache,
// where the only name that exists is the one npm installs.
//
// Feeding the guard the report name produced coordinates like
// "node-sass-legacy/node_modules/color-convert", which cannot match any cache
// key — a GUARANTEED O(1) miss on every nested entry, dropping straight into
// the fallback scan whose basename matching was the false-allow in BLOCKER 3.
// The measurement gate on pr-scan's rows says nothing about the guard surface
// it was wired into.
type lockNameMode uint8

const (
	// lockNamesReport is pr-scan's row identity — the shipped behaviour,
	// gated by prScanNestedLockNames. Do not change it here.
	lockNamesReport lockNameMode = iota
	// lockNamesInstalled is the name npm actually installs at that path,
	// which is the only name a cache lookup or a registry fetch can use.
	lockNamesInstalled
)

// lockEntryName resolves a package-lock "packages" key to a package name for
// pr-scan's report rows.
func lockEntryName(path string) string { return lockEntryNameFor(lockNamesReport, path) }

// lockEntryNameFor resolves a package-lock "packages" key under an explicit
// mode. Returns "" when the entry has no installed identity (a workspace root
// or a local path with no node_modules boundary) — such an entry has no
// registry tarball, so the guard has nothing to look up and skipping it is the
// honest answer rather than inventing a coordinate.
func lockEntryNameFor(mode lockNameMode, path string) string {
	if mode == lockNamesInstalled {
		return lockEntryNameNested(path)
	}
	if prScanNestedLockNames {
		return lockEntryNameNested(path)
	}
	return strings.TrimPrefix(path, "node_modules/")
}

// parsePackageLockJSON extracts the flat name→version map from
// package-lock.json v2/v3. Falls back to a best-effort v1 parse (dependencies
// key).
//
// Thin wrapper over parsePackageLockIntegrityJSON for the callers that only
// want coordinates (pr-scan's diff comparison). The guard's install path wants
// the integrity strings too — see packageSpec.Integrity.
func parsePackageLockJSON(data []byte) (map[string]string, error) {
	versions, _, err := parsePackageLockIntegrityJSON(data)
	return versions, err
}

// parsePackageLockIntegrityJSON parses package-lock.json v2/v3 (with a v1
// fallback) into name→version AND "<name>@<version>"→integrity.
//
// The integrity map is the point. Every lockfile entry npm resolves from a
// registry carries an "integrity" field — the SRI string ("sha512-<base64>")
// npm itself verifies the tarball against before unpacking. The guard used to
// throw it away at this boundary, which left the byte-acquisition layer with no
// expected digest that lives OUTSIDE the package-manager cache it reads from.
// See packageSpec.Integrity for the attack that gap enables and for the
// coverage limit (lockfile-driven installs only).
//
// KEYED ON name@version, NOT name, deliberately. A lockfile routinely holds the
// same package at several paths and several VERSIONS (nested duplicate trees).
// The version map is last-writer-wins over randomised Go map iteration, so a
// name-keyed integrity map could pair the surviving version with a DIFFERENT
// entry's digest — manufacturing a digest mismatch on a perfectly clean
// install. Keying on the coordinate makes the pairing exact by construction.
//
// A coordinate that appears twice with DIFFERENT integrity strings is poisoned
// to "" (no anchor) rather than resolved by a coin flip: an anchor that might
// be the wrong one is worse than no anchor, because it produces a degraded
// signal on a package nobody tampered with.
//
// Entries with no integrity (a `file:`/`link:` local path, a git dependency, a
// workspace root) are simply absent from the map; "" downstream means "no
// anchor", never "verified".
//
// The name-resolution MODE is the caller's, not this function's: pr-scan's
// report rows and the guard's cache-lookup coordinates are different questions
// about the same file. See lockNameMode.
func parsePackageLockIntegrityJSON(data []byte) (map[string]string, map[string]string, error) {
	return parsePackageLockIntegrityJSONMode(data, lockNamesReport)
}

// parsePackageLockIntegrityJSONMode is parsePackageLockIntegrityJSON with the
// name-resolution mode made explicit. The guard's install path passes
// lockNamesInstalled; every pr-scan caller keeps lockNamesReport.
func parsePackageLockIntegrityJSONMode(data []byte, mode lockNameMode) (map[string]string, map[string]string, error) {
	if data == nil {
		return nil, nil, nil
	}
	var root struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			// G5b part A: an aliased dependency records the REAL package in
			// "name" while the map key holds the alias
			// ("node_modules/react": {"name": "electorn"}). Reading only the key
			// scans the innocent alias and never the package npm installs.
			Name      string `json:"name"`
			Version   string `json:"version"`
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Resolved  string `json:"resolved"`
			Integrity string `json:"integrity"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(stripUTF8BOM(data), &root); err != nil {
		return nil, nil, err
	}
	out := make(map[string]string)
	integrity := make(map[string]string)
	record := func(name, version, sri string) {
		if sri == "" {
			return
		}
		k := lockIntegrityKey(name, version)
		if prev, seen := integrity[k]; seen && prev != sri {
			integrity[k] = "" // conflicting anchors: no anchor, see the doc above
			return
		}
		integrity[k] = sri
	}
	if len(root.Packages) > 0 {
		for path, pkg := range root.Packages {
			if pkg.Version == "" || path == "" {
				continue
			}
			// Registry packages only. A workspace member or file: directory
			// (no node_modules/ in its path, nothing remote resolved) is
			// first-party code, and a git, tarball or undeclared-registry
			// package is not its npm namesake: parsePackageLockCoordinates
			// reports those. A registry tarball URL names the package npm
			// fetches, which is the coordinate (nodesource.Tarball, as the
			// depparser parser the guard uses re-keys it).
			real := pkg.Name
			if real == "" {
				real = lockEntryNameNested(path)
			}
			fetched, version, o := nodesource.Tarball(real, pkg.Version, pkg.Resolved)
			if (!strings.Contains(path, "node_modules/") && !npmlock.IsRemote(pkg.Resolved)) || !npmOriginIsRegistry(o) {
				continue
			}
			name := pkg.Name
			if name == "" {
				name = lockEntryNameFor(mode, path)
			}
			if fetched != real {
				name = fetched
			}
			pkg.Version = version
			if name == "" {
				continue
			}
			out[name] = pkg.Version
			record(name, pkg.Version, pkg.Integrity)
		}
	} else {
		for key, dep := range root.Dependencies {
			name, version := dep.Name, dep.Version
			if name == "" {
				name = key
			}
			if target, ok := strings.CutPrefix(version, "npm:"); ok { // alias "npm:bar@1.2.3"
				if i := strings.LastIndex(target, "@"); i > 0 {
					name, version = target[:i], target[i+1:]
				}
			}
			// A v1 git/file/URL dependency records its spec as the version;
			// like a non-registry `resolved`, it is not a registry package.
			if version == "" || strings.ContainsAny(version, ":/") {
				continue
			}
			var o string
			if name, version, o = nodesource.Tarball(name, version, dep.Resolved); !npmOriginIsRegistry(o) {
				continue
			}
			out[name] = version
			record(name, version, dep.Integrity)
		}
	}
	return out, integrity, nil
}

// lockIntegrityKey builds the coordinate key the lockfile-integrity map uses.
// One function so the writer (parsePackageLockIntegrityJSON) and the reader
// (depsToSpecs) cannot drift on the separator.
func lockIntegrityKey(name, version string) string { return name + "@" + version }

// lockCoordinate is one installed (name, version) pair with the lockfile's
// own integrity string for exactly that pair.
type lockCoordinate struct {
	Name      string
	Version   string
	Integrity string
}

// parsePackageLockCoordinates parses a package-lock.json / npm-shrinkwrap.json
// with core/depparser (the parser the server's lockfile scan uses) and splits
// it with npmLockSplit:
//
//   - registry: every installed coordinate from the public registry, a
//     declared registry mirror or the user's own Chainsaw repository, with
//     the lockfile's integrity as its anchor;
//   - nonRegistry: git, tarball URL and undeclared-registry packages, never
//     checked as their npm namesakes, and local code ("file:<path>":
//     workspace members, file: dependencies — npmLockSpecs makes those
//     Local, npmNonLocal drops them from pr-scan).
//
// Not collapsed by name. A real npm tree installs the SAME NAME AT SEVERAL
// VERSIONS routinely (40 such names in a measured ui_new lockfile); the old
// map form dropped ~5% of installed coordinates and, because Go randomises
// map iteration, picked a different survivor each run — a byte scan whose
// coverage was a coin flip. registry is sorted.
//
// Conflicting integrity strings for ONE coordinate collapse to no anchor
// rather than a coin flip: a wrong anchor manufactures a digest mismatch on a
// clean install, which is worse than no anchor at all. An integrity
// depparser cannot decode is no anchor either.
//
// An error comes back WITH every package that did parse (npm.Parse reads
// entry by entry): the guard checks those and reports the file as not
// fully read; pr-scan counts the failure.
func parsePackageLockCoordinates(data []byte) (registry []lockCoordinate, nonRegistry []nonRegistryDep, err error) {
	if data == nil {
		return nil, nil, nil
	}
	pkgs, err := npmlock.Parse(bytes.NewReader(stripUTF8BOM(data)))
	all, nonRegistry := npmLockSplit(pkgs)
	byCoord := make(map[string]int, len(all))
	for _, c := range all {
		k := lockIntegrityKey(c.Name, c.Version)
		i, seen := byCoord[k]
		if !seen {
			byCoord[k] = len(registry)
			registry = append(registry, c)
			continue
		}
		switch cur := &registry[i]; {
		case cur.Integrity == "":
			cur.Integrity = c.Integrity // a copy with no integrity (bundled) adds nothing
		case c.Integrity != "" && c.Integrity != cur.Integrity:
			cur.Integrity = "" // conflicting anchors for one coordinate
		}
	}
	sort.Slice(registry, func(i, j int) bool {
		if registry[i].Name != registry[j].Name {
			return registry[i].Name < registry[j].Name
		}
		return registry[i].Version < registry[j].Version
	})
	return registry, nonRegistry, err
}

// splitLockIntegrityKey reverses lockIntegrityKey. It splits on the LAST
// "@" so a scoped name (@babel/core@7.24.0) round-trips; splitting on the
// first would yield ("", "babel/core@7.24.0").
func splitLockIntegrityKey(key string) (name, version string, ok bool) {
	at := strings.LastIndex(key, "@")
	if at <= 0 || at == len(key)-1 {
		return "", "", false
	}
	return key[:at], key[at+1:], true
}

// parsePackageJSONDeps extracts declared dependencies from package.json
// (dependencies + devDependencies). Versions may be semver ranges here, not
// resolved; useful for detecting new entries.
//
// C3: this used to return a bare nil on an unmarshal error while every sibling
// returned a counted error, so one malformed package.json (e.g. `"devDependencies":
// []`, an array where an object belongs) dropped the ENTIRE file — real
// dependencies block included — and the report said added: 0, parse_errors: 0,
// exit 0. Returning the error routes it through buildPRScanReport's parseFailures
// counter and the exit-30 escalation.
//
// A git or URL spec ("x": "github:o/r", "git+https://…", "o/r", a tarball
// URL) is returned in nonRegistry, never as the registry's x.
func parsePackageJSONDeps(data []byte) (map[string]string, []nonRegistryDep, error) {
	if data == nil {
		return nil, nil, nil
	}
	var root struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(stripUTF8BOM(data), &root); err != nil {
		return nil, nil, err
	}
	out := make(map[string]string)
	var nonRegistry []nonRegistryDep
	for _, deps := range []map[string]string{root.Dependencies, root.DevDependencies} {
		for k, v := range deps {
			if dep, ok := npmNonRegistryDep(k, v); ok {
				nonRegistry = append(nonRegistry, dep)
				continue
			}
			out[k] = v
		}
	}
	return out, nonRegistry, nil
}

// npmNonRegistryDep classifies a package.json spec with the guard's own npm
// grammar (npmIsSource / npmSourceSpec). file:, link:, workspace: and npm:
// aliases are left as they were: local code, or a registry coordinate under
// another name (plan §3.4: re-key, not "not assessed").
func npmNonRegistryDep(name, spec string) (nonRegistryDep, bool) {
	if !npmIsSource(spec) || risk.ClassifyDepURL(spec) == risk.DepURLOther {
		return nonRegistryDep{}, false
	}
	s := npmSourceSpec(name, spec)
	if s.Origin == "" || strings.HasPrefix(s.Origin, localOriginPrefix) {
		return nonRegistryDep{}, false
	}
	return nonRegistryDep{Name: name, Version: s.Version, Origin: s.Origin}, true
}

// parsePNPMLock and parseYarnLock read pnpm-lock.yaml and yarn.lock (v1 and
// berry) with the server's parsers (core/depparser), split by npmLockSplit.
// They replaced line-scanning parsers that kept one version per name, read
// only the first YAML document of a pnpm 10 lockfile, keyed aliases by the
// alias, and checked git, tarball and workspace packages as their registry
// namesakes. A file that does not parse is an error, counted like any other
// manifest parse failure, not an empty lockfile — returned with whatever
// entries did parse.
func parsePNPMLock(data []byte) ([]lockCoordinate, []nonRegistryDep, error) {
	return parseJSLock(pnpm.Parse, data)
}

func parseYarnLock(data []byte) ([]lockCoordinate, []nonRegistryDep, error) {
	return parseJSLock(yarn.Parse, data)
}

func parseJSLock(parse func(io.Reader) ([]ftypes.Package, error), data []byte) ([]lockCoordinate, []nonRegistryDep, error) {
	if data == nil {
		return nil, nil, nil
	}
	pkgs, err := parse(bytes.NewReader(data))
	reg, nonReg := npmLockSplit(pkgs)
	return reg, nonReg, err
}

// parsePipRequirements parses a requirements.txt file (simple name==version
// lines). A VCS, URL or archive source (`-e git+…`, `pkg @ git+…`, a bare
// `git+…`) is returned in nonRegistry, through the guard's own pip grammar
// (parsePipSpec / pipSourceSpec): it used to vanish, as an option line or a
// line with no "==". A local path is first-party code: no row, like a
// sourceless crate.
func parsePipRequirements(data []byte) (map[string]string, []nonRegistryDep) {
	if data == nil {
		return nil, nil
	}
	out := make(map[string]string)
	var nonRegistry []nonRegistryDep
	source := func(s packageSpec) {
		switch {
		case s.Origin == "" && s.Name != "" && s.Version != "":
			out[strings.ToLower(s.Name)] = s.Version // an archive on PyPI's own hosts
		case s.Origin != "" && !strings.HasPrefix(s.Origin, localOriginPrefix):
			name := s.Name
			if name == "" {
				name = origin.Label(s.Origin) // a nameless source is known by its origin
			}
			nonRegistry = append(nonRegistry, nonRegistryDep{Name: name, Version: s.Version, Origin: s.Origin})
		}
	}
	// Requirements drops option lines, so `-e` sources are read here.
	for _, line := range strings.Split(string(data), "\n") {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "-e") || strings.HasPrefix(t, "--editable") {
			_, flags := splitFlags(strings.Fields(t), pipReqFileFlags)
			for _, f := range flags {
				if (f.name == "-e" || f.name == "--editable") && f.value != "" {
					source(pipSourceSpec(f.value))
				}
			}
		}
	}
	// Requirements joins "\" continuations and drops comments and --hash
	// options (pip-compile --generate-hashes output).
	for _, line := range requirements.Requirements(string(data)) {
		if s := parsePipSpec(line); s.Origin != "" || strings.Contains(line, "://") {
			source(s)
			continue
		}
		line, _, _ = strings.Cut(line, ";") // environment marker
		line = strings.Join(strings.Fields(line), "")
		// Handle name==version, name>=version etc.
		for _, sep := range []string{"==", "~=", ">=", "<="} {
			if idx := strings.Index(line, sep); idx > 0 {
				name := line[:idx]
				if b := strings.IndexByte(name, '['); b >= 0 {
					name = name[:b] // extras
				}
				ver := strings.TrimLeft(line[idx+len(sep):], "=") // "===" arbitrary equality
				// Strip any trailing specifiers (e.g. "1.0.0,<2.0.0").
				if commaIdx := strings.Index(ver, ","); commaIdx > 0 {
					ver = ver[:commaIdx]
				}
				if name != "" && ver != "" {
					out[strings.ToLower(name)] = ver
				}
				break
			}
		}
	}
	return out, nonRegistry
}

// parsePythonLock parses a Pipfile.lock, poetry.lock or uv.lock (file is the
// base name) through core/depparser — the parsers the server lockfile scan
// uses, so the guard, pr-scan and the server read the same packages, sources
// and versions — and splits them by source the way the install guard decides
// a lockfile's sources (pythonSource). Dev packages are included: `poetry
// install` and `pipenv sync --dev` install them. nil data (a file absent at
// the base ref) is no packages.
func parsePythonLock(file string, data []byte) (registry []lockCoordinate, nonRegistry []nonRegistryDep, local []lockCoordinate, err error) {
	if data == nil {
		return nil, nil, nil, nil
	}
	var pkgs []ftypes.Package
	switch file {
	case "Pipfile.lock":
		pkgs, err = pipenv.Parse(bytes.NewReader(stripUTF8BOM(data)))
	case "poetry.lock":
		pkgs, _, err = poetry.NewParser().Parse(context.Background(), bytes.NewReader(data))
	case "uv.lock":
		pkgs, err = uvlock.Parse(bytes.NewReader(data))
	default:
		return nil, nil, nil, fmt.Errorf("not a Python lockfile: %s", file)
	}
	if err != nil {
		return nil, nil, nil, err
	}
	for _, p := range pkgs {
		reg, nr, loc := pythonSource(p.Name, p.Version, p.Origin)
		switch {
		case reg != nil:
			registry = append(registry, *reg)
		case nr != nil:
			nr.Hash = p.Hash
			nonRegistry = append(nonRegistry, *nr)
		case loc != nil:
			local = append(local, *loc)
		}
	}
	return registry, nonRegistry, local, nil
}

// pythonSource is the install guard's rule for one Python lockfile package
// (exactly one result is non-nil):
//
//   - no Origin: PyPI, a registry coordinate.
//   - "file:…": local code (an editable project, a path dependency) —
//     first-party, like a Cargo path crate (packageSpec.Local). Not a
//     vendored wheel or sdist by path (localCode): that is third-party code,
//     not from PyPI.
//   - an index on another host ("registry+<url>", origin.RegistryOther):
//     a registry coordinate when knownRegistry vouches for the host (PyPI
//     under another alias, a registry_mirrors host, the user's own Chainsaw
//     repository); otherwise not assessed, with the registry_mirrors hint.
//     The guard has no registry digest to compare a lockfile hash with; the
//     server decides these by hash.
//   - anything else (git, an archive URL): not from PyPI.
func pythonSource(name, version, src string) (reg *lockCoordinate, nonReg *nonRegistryDep, local *lockCoordinate) {
	c := lockCoordinate{Name: name, Version: version}
	switch {
	case src == "":
		return &c, nil, nil
	case localCode(src):
		return nil, nil, &c
	case origin.Classify("pypi", src) == origin.RegistryOther && knownRegistry("pip", src):
		return &c, nil, nil
	}
	return nil, &nonRegistryDep{Name: name, Version: version, Origin: src}, nil
}

// parsePipRequirementsSources splits a requirements file for pr-scan: the
// registry name->version map (parsePipRequirements, ranges included — a diff
// wants them), and the requirements installed from somewhere else — source
// lines (`name @ git+…`, VCS and archive URLs), and every index requirement
// when the file's primary index (`-i` / `--index-url`) is a host the guard
// does not vouch for (pythonSource). Local paths (`-e ./lib`) get no row, as
// for Cargo path crates.
func parsePipRequirementsSources(data []byte) (registry map[string]string, nonRegistry []nonRegistryDep) {
	if data == nil {
		return nil, nil
	}
	text := string(data)
	// The source rows parsePipRequirements returns are rebuilt below from
	// core/depparser (requirements.Packages), the parser the server uses;
	// its rows are kept only for sources that parser has no name for (a
	// bare `git+https://…` line), so nothing is listed twice.
	registry, lineRows := parsePipRequirements(data)
	idx := requirements.IndexSource(text)
	if _, nr, _ := pythonSource("", "", idx); nr != nil {
		// Every index requirement comes from an index the guard does not
		// vouch for.
		names := make([]string, 0, len(registry))
		for name := range registry {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			nonRegistry = append(nonRegistry, nonRegistryDep{Name: name, Version: registry[name], Origin: idx})
		}
		registry = map[string]string{}
	}
	for _, p := range requirements.Packages(text) {
		name := strings.ToLower(p.Name)
		switch {
		case p.Origin == idx && idx != "":
			// an index requirement, decided above
		case p.Origin == "":
			if _, ok := registry[name]; !ok && p.Version != "" {
				registry[name] = p.Version // `name @ <file on PyPI's host>`
			}
		default:
			if _, nr, _ := pythonSource(name, p.Version, p.Origin); nr != nil {
				nr.Hash = p.Hash
				nonRegistry = append(nonRegistry, *nr)
			}
		}
	}
	seen := map[string]bool{}
	for _, nr := range nonRegistry {
		seen[strings.ToLower(nr.Name)] = true
	}
	for _, nr := range lineRows {
		if !seen[strings.ToLower(nr.Name)] {
			seen[strings.ToLower(nr.Name)] = true
			nonRegistry = append(nonRegistry, nr)
		}
	}
	return registry, nonRegistry
}

// nonRegistryDep is a lockfile package that does NOT come from the
// ecosystem's public registry: a git source, an alternate or private
// registry, a path. Origin is the lockfile's own statement of where it comes
// from (a Cargo `source`, or a Gemfile.lock section and remote), passed
// through origin.Sanitize: a source can carry credentials
// (git+https://user:token@host/...) and Origin is printed and serialised.
//
// Such a package is not its registry namesake. Checking it as one is the
// defect this type exists to prevent: on 2026-10-14 feldera/feldera's 22 git
// crates had been scored as crates.io namesakes on the server (etl@0.1.0 took
// an unrelated crate's verdict). Kept apart from the name->version map the
// registry packages use, so a fork and its namesake never collapse into one
// entry either.
type nonRegistryDep struct {
	Name    string
	Version string
	Origin  string
	Hash    string // the lockfile's content hash, "" when none; see packageSpec.Hash
}

// nonRegistryReason is the one sentence every surface prints for a
// non-registry package. Same wording as the server's lockfile scan
// (internal/scan/lockfile_scan.go). src is printed by originLabel: host
// only for a registry-protocol source.
func nonRegistryReason(ecosystem, src string) string {
	reg := "the public registry"
	switch ecosystem {
	case "cargo":
		reg = "crates.io"
	case "rubygems":
		reg = "rubygems.org"
	case "pip", "pypi":
		reg = "PyPI"
	}
	return "not from " + reg + ": not assessed (" + originLabel(ecosystem, src) + ")"
}

// parseGemfileLock parses Gemfile.lock with the server's parser
// (core/depparser/parser/ruby/bundler: one package per gem and version,
// platform builds folded, every source section classified) and splits the
// result the way the guard and pr-scan consume it:
//
//   - a rubygems.org GEM gem: registry.
//   - a GEM gem from another remote (a mirror, a private gem server, a
//     Bundler 1.x section with several remotes): registry when
//     knownRegistry accepts the remote — the user's declared registry_mirrors
//     or their own Chainsaw repository — otherwise nonRegistry, which the
//     guard reports "not assessed" with the registry_mirrors hint and still
//     runs the known-malicious lookup on.
//   - GIT, PATH ("file:" — local), or any other source section: nonRegistry,
//     never checked as a rubygems.org gem.
//
// A file that does not parse is an error (counted by pr-scan, reported by the
// guard), never an empty lockfile.
func parseGemfileLock(data []byte) (registry map[string]string, nonRegistry []nonRegistryDep, err error) {
	if data == nil {
		return nil, nil, nil
	}
	pkgs, err := bundler.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, nil, err
	}
	registry = make(map[string]string)
	for _, p := range pkgs {
		if p.Origin == "" ||
			(origin.Classify("rubygems", p.Origin) == origin.RegistryOther && knownRegistry("rubygems", p.Origin)) {
			registry[p.Name] = p.Version
			continue
		}
		nonRegistry = append(nonRegistry, nonRegistryDep{Name: p.Name, Version: p.Version, Origin: p.Origin, Hash: p.Hash})
	}
	return registry, nonRegistry, nil
}

// cargoSourceIsCratesIO reports whether a Cargo.lock `source` is crates.io,
// through either its git index or its sparse index.
func cargoSourceIsCratesIO(source string) bool {
	switch strings.TrimSuffix(source, "/") {
	case "registry+https://github.com/rust-lang/crates.io-index", "sparse+https://index.crates.io":
		return true
	}
	return false
}

// parseCargoLock parses Cargo.lock: TOML with repeated [[package]] blocks,
// each carrying `name`, `version` and (for anything not in this workspace)
// `source` lines. Line-based, no TOML dependency.
//
// The `source` decides what a package is:
//   - crates.io (git or sparse index): a registry package, in registry —
//     as coordinates, because one lockfile routinely holds a crate at two
//     versions (syn 1.x and 2.x) and a name->version map keeps only one.
//   - no source: a workspace member or path dependency — first-party code
//     with no registry identity, returned in local. Not a registry package,
//     but deleting a crate's `source` line is a lockfile edit an attacker
//     can make (cargo re-resolves it from crates.io), so the guard still
//     runs the known-malicious lookup on these; see packageSpec.Local.
//   - anything else (git+, another registry+ or sparse+ index): in
//     nonRegistry, never checked as its crates.io namesake.
func parseCargoLock(data []byte) (registry []lockCoordinate, nonRegistry []nonRegistryDep, local []lockCoordinate) {
	if data == nil {
		return nil, nil, nil
	}
	inPkg := false
	name, version, source, checksum := "", "", "", ""
	flush := func() {
		switch {
		case !inPkg || name == "" || version == "":
		case source == "":
			local = append(local, lockCoordinate{Name: name, Version: version})
		case cargoSourceIsCratesIO(source):
			registry = append(registry, lockCoordinate{Name: name, Version: version})
		default:
			nonRegistry = append(nonRegistry, nonRegistryDep{Name: name, Version: version, Origin: origin.Sanitize(source), Hash: origin.JoinHashes("sha256:" + checksum)})
		}
		name, version, source, checksum = "", "", "", ""
	}
	tomlString := func(line, key string) (string, bool) {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, key) {
			return "", false
		}
		rest := strings.TrimSpace(trimmed[len(key):])
		if !strings.HasPrefix(rest, "=") {
			return "", false
		}
		rest = strings.TrimSpace(strings.TrimPrefix(rest, "="))
		return strings.Trim(rest, "\""), true
	}
	for _, line := range strings.Split(string(data), "\n") {
		if trimmed := strings.TrimSpace(line); strings.HasPrefix(trimmed, "[") {
			// Any table header closes the block. Only [[package]] opens
			// one: [metadata] and [[patch.unused]] entries are not
			// installed packages.
			flush()
			inPkg = trimmed == "[[package]]"
			continue
		}
		if v, ok := tomlString(line, "name"); ok {
			name = v
		} else if v, ok := tomlString(line, "version"); ok {
			version = v
		} else if v, ok := tomlString(line, "source"); ok {
			source = v
		} else if v, ok := tomlString(line, "checksum"); ok {
			checksum = v
		}
	}
	flush() // final block
	return registry, nonRegistry, local
}

// parseGoSum returns every module go.sum says was downloaded, with the
// server's parser (core/depparser/parser/golang/sum): one coordinate per
// "<module> <version> h1:" line — a "/go.mod" line is a version read during
// module graph resolution and never built. Coordinates, not a name->version
// map: an older go.sum holds one module at several versions, and the map kept
// whichever came first. Versions keep the guard's existing spelling: the
// leading "v" (as `go get mod@v1.2.3` is typed) and no "+incompatible". A
// file that does not parse is an error, never an empty go.sum.
func parseGoSum(data []byte) ([]lockCoordinate, error) {
	if data == nil {
		return nil, nil
	}
	pkgs, err := gosum.Parse(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	out := make([]lockCoordinate, 0, len(pkgs))
	seen := map[lockCoordinate]bool{}
	for _, p := range pkgs {
		c := lockCoordinate{Name: p.Name, Version: "v" + strings.SplitN(p.Version, "+", 2)[0]}
		if !seen[c] {
			seen[c] = true
			out = append(out, c)
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Signal evaluation
// ---------------------------------------------------------------------------

// evaluatePREntry runs the offline signal engine against a raw manifest entry
// and returns a fully evaluated prScanEntry.  This is intentionally lightweight:
// without a live policy store (a server-side construct) we apply the same
// heuristic signals that `chainsaw scan` uses in offline/quick mode.
//
// Callers can extend this to POST to the server's evaluate endpoint when
// CHAINSAW_SERVER is set — that is a future improvement (TODO: add online
// signal enrichment via /api/v1/intel/evaluate when server configured).
func evaluatePREntry(e rawEntry) prScanEntry {
	out := prScanEntry{
		Ecosystem:       e.Ecosystem,
		Name:            e.Name,
		Version:         e.Version,
		PreviousVersion: e.PreviousVersion,
		Signals:         []prScanSignal{},
		Verdict:         "allow",
	}

	signals := prOfflineSignals(e)

	// A changed source is a warn whichever way it moved: to a fork or a
	// private registry the package is no longer the one reviewed before,
	// and from a private source to the public registry is the
	// dependency-confusion shape. After the not-assessed signal, if any.
	if e.SourceChange != "" {
		signals = append([]prScanSignal{{ID: prScanSourceChangedSignalID, Severity: "warn", Reason: e.SourceChange}}, signals...)
	}

	// A package from outside the public registry is NOT ASSESSED, and the
	// row says so with a warn-level signal, so it can never read as clean.
	// The name-based signals above still run (they only ever add
	// suspicion, so a lockfile entry rewritten to a git source cannot shed
	// them); pr-scan has no lane that could hand it a namesake's clean
	// verdict.
	if e.Origin != "" {
		out.Origin = e.Origin
		signals = append([]prScanSignal{{ID: prScanNotAssessedSignalID, Severity: "warn", Reason: nonRegistryReason(e.Ecosystem, e.Origin)}}, signals...)
	}

	// Policy runs AFTER the offline heuristics, and its output joins the
	// SAME slice. Two consequences, both deliberate:
	//
	//   1. A rule can key on what the heuristics found (see
	//      prScanPolicyInput), because they have already run.
	//   2. `policy:<rule_id>` rows ride the existing signals array, so
	//      the chainsaw.pr-scan/v1 schema, the SARIF writer
	//      (prScanToSARIF builds one rule per signal id and maps
	//      severity "block" → SARIF level "error") and the Action's PR
	//      comment (jq over `.signals | map(.id + ": " + .reason)`) all
	//      carry them with no schema bump and no new rendering code.
	//
	// The append is the tighten-only fold in its final form: the verdict
	// loop below is a max over severities, so a policy signal can only
	// ever raise the verdict, never lower one the heuristics set.
	signals = append(signals, prScanPolicyLane(context.Background(), e, signals)...)
	out.Signals = signals
	out.Verdict = prScanVerdict(signals)
	return out
}

// prScanVerdict is the max over a row's signal severities.
func prScanVerdict(signals []prScanSignal) string {
	verdict := "allow"
	for _, s := range signals {
		if s.Severity == "block" {
			return "block"
		} else if s.Severity == "warn" {
			verdict = "warn"
		}
	}
	return verdict
}

// isWorkflowFile reports whether a changed path is a GitHub Actions workflow
// (.github/workflows/*.yml|yaml) or an action's own metadata (action.yml),
// whose `uses:` refs pull third-party code into CI.
func isWorkflowFile(rel string) bool {
	rel = filepath.ToSlash(rel)
	base := path.Base(rel)
	if base == "action.yml" || base == "action.yaml" {
		return true
	}
	ext := path.Ext(base)
	return (ext == ".yml" || ext == ".yaml") && strings.Contains("/"+rel, "/.github/workflows/")
}

// diffWorkflow returns one row per remote `uses:` ref the PR added or
// changed, scored by the scan-actions scanner (githubactions.Scan) and
// carrying its action.* signal ids. A ref whose owner/name was in base at
// another ref (a SHA pin moved to a tag) is an upgrade. action.malicious
// blocks; every other action signal warns, like pr-scan's own heuristics. An
// unparseable head is an error (counted); an unparseable or absent base
// makes every head ref new.
func diffWorkflow(rel string, baseContent, headContent []byte) (added, upgraded []prScanEntry, err error) {
	headRefs, err := githubactions.ParseWorkflowFile(rel, headContent)
	if err != nil {
		return nil, nil, err
	}
	baseRefs, _ := githubactions.ParseWorkflowFile(rel, baseContent)
	seen, prev := map[string]bool{}, map[string]string{}
	for _, r := range baseRefs {
		seen[strings.TrimSpace(r.Raw)] = true
		if key := strings.ToLower(r.Owner + "/" + r.Name); r.Kind == githubactions.KindRemote && prev[key] == "" {
			prev[key] = r.Version
		}
	}
	var changed []githubactions.ActionRef
	for _, r := range headRefs {
		if raw := strings.TrimSpace(r.Raw); r.Kind == githubactions.KindRemote && !seen[raw] {
			seen[raw] = true
			changed = append(changed, r)
		}
	}
	if len(changed) == 0 {
		return nil, nil, nil
	}
	findings, err := githubactions.Scan(context.Background(), changed, githubactions.ScanDeps{
		// The same wiring as scan-actions (scan_actions.go); both offline.
		Typosquat: githubactions.NewTyposquatAdapter(typosquat.NewGitHubActionsDetector(nil)),
		Malware:   githubactions.NewMalwareAdapter(malware.NewGitHubActionsFeed()),
	})
	if err != nil {
		return nil, nil, err
	}
	signals := map[string][]prScanSignal{}
	for _, f := range findings {
		sev := "warn"
		if f.Signal == githubactions.SignalActionMalicious {
			sev = "block"
		}
		raw := strings.TrimSpace(f.Ref.Raw)
		signals[raw] = append(signals[raw], prScanSignal{ID: f.Signal, Severity: sev, Reason: f.Message})
	}
	for _, r := range changed {
		sigs := signals[strings.TrimSpace(r.Raw)]
		if sigs == nil {
			sigs = []prScanSignal{}
		}
		e := prScanEntry{Ecosystem: "github_actions", Name: r.Owner + "/" + r.Name, Version: r.Version, Signals: sigs, Verdict: prScanVerdict(sigs)}
		if p, ok := prev[strings.ToLower(e.Name)]; ok {
			e.PreviousVersion = &p
			upgraded = append(upgraded, e)
		} else {
			added = append(added, e)
		}
	}
	return added, upgraded, nil
}

// prScanNotAssessedSignalID marks a row for a package from outside the
// public registry (prScanEntry.Origin): not assessed, rather than scored.
const prScanNotAssessedSignalID = "origin.not_assessed"

// prScanSourceChangedSignalID marks a row whose source differs from base
// (rawEntry.SourceChange).
const prScanSourceChangedSignalID = "origin.source_changed"

// prOfflineSignals runs a small set of heuristic supply-chain checks that
// don't require a live server.  Each check returns zero or one signal.
// The set mirrors the conditions that the online policy evaluator can act on
// so human reviewers see the same vocabulary.
func prOfflineSignals(e rawEntry) []prScanSignal {
	var out []prScanSignal

	name := e.Name

	// sc.typosquat_low: check for typo-squatting against well-known packages.
	if sig, ok := checkTyposquat(e.Ecosystem, name); ok {
		out = append(out, sig)
	}

	// sc.scoped_to_unscoped: npm-specific — scoped package moved to unscoped.
	if e.Ecosystem == "npm" && !strings.HasPrefix(name, "@") {
		// Heuristic: if the package name is very short (≤3 chars) it's
		// high-risk for dependency confusion / squatting.
		if len(name) <= 3 {
			out = append(out, prScanSignal{
				ID:       "sc.short_name",
				Severity: "warn",
				Reason:   fmt.Sprintf("package name %q is very short (≤3 chars) — verify intentionality", name),
			})
		}
	}

	// sc.new_package: the package wasn't in the lockfile at base — brand-new
	// dependency introduction.  Surface it as informational for reviewers.
	if e.PreviousVersion == nil {
		out = append(out, prScanSignal{
			ID:       "sc.new_dep",
			Severity: "warn",
			Reason:   fmt.Sprintf("new dependency %s@%s introduced in this PR", name, e.Version),
		})
	}

	return out
}

// ---------------------------------------------------------------------------
// Policy decision point — policy.SurfacePR
// ---------------------------------------------------------------------------
//
// WHY THIS EXISTS. Every signal prOfflineSignals emits is severity
// "warn". The "block" branch in evaluatePREntry was therefore dead code
// and exit 20 was unreachable except via --strict. That is not a
// cosmetic gap: the shipped Guard Action defaults to
// `pr-scan-fail-on: block`, which gates on exit 20 — so an operator who
// set `mode: block` believed they had a merge gate and had a PR
// comment. The documented alternative, "warn", fails essentially every
// PR that adds a dependency, because sc.new_dep fires on every new
// dependency. There was no middle setting.
//
// A Rego rule at SurfacePR is that middle setting: `block if
// input.isSuspectedTyposquat` while sc.new_dep stays a warn. Same rule
// language, same bundle, same CHAINSAW_POLICY_BUNDLE variable as the
// proxy and the guard.
//
// THE BOUNDARY — identical to the guard's (see guard_policy.go).
// Policy TIGHTENS, never loosens. The baseline stays exactly as
// permissive as it was: with no bundle and no built-in rule firing, the
// report is byte-identical and exit 10 behaviour is unchanged, and
// --strict semantics are untouched. An operator who wants to SILENCE
// sc.new_dep is asking policy to LOOSEN, and that is deliberately not
// granted here — the way there is to leave the baseline permissive
// (`pr-scan-fail-on: block`) and raise the specific signals they care
// about to block.
//
// FAIL POSTURE — also identical. A bundle that will not compile, or a
// configured bundle that is not there, falls back to the built-in
// defaults, is COUNTED via GuardPolicyLoadFailureCount, and never
// gates. A broken rule file is one operator's mistake; it must not
// wedge every PR in the org.

var (
	prScanPolicyOnce   sync.Once
	prScanPolicyEngine *policyengine.Engine
)

// prScanPolicySignalPrefix namespaces policy findings inside the
// signals array. "sc." ids are Chainsaw's own heuristics; "policy:" ids
// name a rule the operator (or the built-in bundle) wrote, and the
// suffix is the rule_id verbatim so a reader can grep their bundle for
// it. Kept distinct so neither namespace can ever shadow the other.
const prScanPolicySignalPrefix = "policy:"

// prScanTyposquatSignalID is the id checkTyposquat emits AND the id
// prScanPolicyInput reads to derive input.isSuspectedTyposquat. Sharing
// the constant is what stops a rename in one place from silently
// un-populating the other — the failure mode would be invisible, since
// a rule keyed on isSuspectedTyposquat would simply stop firing.
const prScanTyposquatSignalID = "sc.typosquat_low"

// prScanPolicy compiles the built-in bundle plus any operator bundle,
// once per process, WITHOUT the guard's trust-on-first-use pin. See
// policyBundlePin in guard_policy.go for why an ephemeral CI runner
// must not pin.
func prScanPolicy() *policyengine.Engine {
	prScanPolicyOnce.Do(func() {
		var notice string
		prScanPolicyEngine, notice = loadCLIPolicy(skipBundlePin)
		// DO NOT discard this notice. A merge gate is the surface where a
		// silently-degraded bundle is worst: the operator who set
		// `mode: block` is not watching a terminal, and a typo'd .rego
		// would otherwise produce a permanently green PR check with no
		// signal on any channel — no comment, no stderr, no exit code.
		// The counter this used to lean on (GuardPolicyLoadFailureCount)
		// has no production reader, so "it is counted" was true in code
		// and void in practice.
		//
		// stderr, not the report: the report is a machine-readable
		// artifact whose schema (chainsaw.pr-scan/v1) is consumed by the
		// SARIF writer and the Action's jq, and a bundle-load failure is
		// not a finding about any package. pr-scan already speaks on
		// stderr for read and parse failures.
		if notice != "" {
			fmt.Fprintf(os.Stderr, "pr-scan: %s\n", notice)
		}
	})
	return prScanPolicyEngine
}

// prScanPolicyResetForTest clears the memoized engine so a test can
// exercise a different bundle. Never called in production.
func prScanPolicyResetForTest() {
	prScanPolicyOnce = sync.Once{}
	prScanPolicyEngine = nil
}

// prScanPolicyInput projects what pr-scan knows about a coordinate onto
// the canonical policy.Input. Fields pr-scan cannot observe stay
// zero-valued, which is the documented contract.
//
// ── READ THIS BEFORE "FIXING" IT TO MATCH THE GUARD ──────────────────
//
// guardPolicyInput deliberately OMITS the guard's own Go-lane verdicts
// (isKnownMalicious, isSuspectedTyposquat). That is correct THERE and
// wrong HERE, and the difference is not style — it is which lanes
// return before policy runs.
//
// The guard's malicious/typosquat lanes BLOCK and return. Policy never
// sees those packages, so restating the verdicts could only re-derive a
// decision already made while creating a second place for the two to
// disagree.
//
// pr-scan's lanes never block. checkTyposquat emits a warn and
// evaluation continues to policy every time. So restating the typosquat
// finding is the ONLY way a rule can key on it — omit it and
// `input.isSuspectedTyposquat` is permanently undefined at SurfacePR,
// which silently makes the single most useful PR-time rule a no-op.
//
// Do not "harmonize" this with the guard. The lanes are shaped
// differently and the inputs follow the lanes.
//
// TestPRScanPolicyInput_PopulatedFieldContract pins the exact field set.
func prScanPolicyInput(e rawEntry, signals []prScanSignal) policy.Input {
	in := policy.Input{
		Surface:          policy.SurfacePR,
		RepositoryFormat: strings.ToLower(e.Ecosystem),
		PackageName:      e.Name,
		PackageVersion:   e.Version,
		GitDependency:    gitOrigin(e.Ecosystem, e.Origin),
	}
	setNonRegistryFacts(&in, e.Ecosystem, e.Origin, e.Hash)
	for _, s := range signals {
		if s.ID == prScanTyposquatSignalID {
			in.IsSuspectedTyposquat = true
		}
	}
	return in
}

// prScanPolicyLane runs the policy decision point for one coordinate
// and returns the signals to append. nil when policy had nothing to
// say, which is the common case and the default-off path.
func prScanPolicyLane(ctx context.Context, e rawEntry, signals []prScanSignal) []prScanSignal {
	eng := prScanPolicy()
	if eng == nil {
		return nil
	}
	dec, err := eng.DecideInput(ctx, prScanPolicyInput(e, signals))
	if err != nil {
		// Fail open and COUNT it — see FAIL POSTURE above.
		//
		// Reachability note: policyengine.DecideInput swallows a Rego
		// RUNTIME error internally (it logs and folds an allow) and
		// returns a nil error today, so in practice the counted
		// failures are compile-time and missing-bundle ones raised
		// inside loadCLIPolicy. This branch stays because the facade's
		// signature permits an error and a silent gate failure is the
		// one outcome that must never be possible here.
		guardPolicyLoadFailures.Add(1)
		return nil
	}

	var out []prScanSignal
	for _, v := range dec.Violations {
		sev, ok := prScanPolicySeverity(v.Action)
		if !ok {
			// allow / notify_owner carry no enforcement weight
			// (dsl.strictness ranks them at allow), so there is
			// nothing to report on a merge gate.
			continue
		}
		msg := v.Message
		if msg == "" {
			msg = "refused by policy"
		}
		out = append(out, prScanSignal{
			ID:       prScanPolicySignalID(v.RuleID),
			Severity: sev,
			Reason:   msg,
		})
	}

	// The emitted rows must reach the action the engine folded with
	// dsl.Stricter. Per-violation projection can fall short of it —
	// an action with no violation carrying it, or every violation
	// filtered out — and under-reporting the decision on a merge gate
	// is the failure that matters. Add the decisive row back rather
	// than quietly reporting less than was decided.
	if sev, ok := prScanPolicySeverity(dec.Action); ok && !prScanSignalsReach(out, sev) {
		out = append(out, prScanSignal{
			ID:       prScanPolicySignalID(""),
			Severity: sev,
			Reason:   "refused by policy",
		})
	}
	return out
}

// prScanPolicySignalID renders the signal id for a policy violation.
// A rule that names itself is traceable; an unnamed one still has to be
// visible, so it degrades to the bare prefix rather than vanishing.
func prScanPolicySignalID(ruleID string) string {
	if ruleID == "" {
		return strings.TrimSuffix(prScanPolicySignalPrefix, ":")
	}
	return prScanPolicySignalPrefix + ruleID
}

// prScanPolicySeverity maps a policy action onto pr-scan's two
// severities. ok=false means the action carries no enforcement weight
// and produces no row.
//
// block and quarantine both land on "block": pr-scan has no quarantine
// concept and a merge gate cannot half-refuse a dependency, so the
// stricter reading is the only safe one.
func prScanPolicySeverity(a dsl.Action) (string, bool) {
	switch a {
	case dsl.ActionBlock, dsl.ActionQuarantine:
		return "block", true
	case dsl.ActionMonitor:
		return "warn", true
	default:
		return "", false
	}
}

// prScanSignalsReach reports whether signals already carry at least the
// given severity, using the same block > warn ordering evaluatePREntry
// folds with.
func prScanSignalsReach(signals []prScanSignal, severity string) bool {
	for _, s := range signals {
		if s.Severity == "block" {
			return true
		}
		if s.Severity == severity {
			return true
		}
	}
	return false
}

// wellKnownPackages is a curated set of extremely-targeted packages that are
// commonly typosquatted.  The real typosquat engine lives server-side (see
// internal/typosquat) and pulls a much larger popular-package universe from
// the registries at runtime; this static list is a first-line heuristic for
// offline use during PR scans, where we can't make network calls to fetch
// fresh popularity data.
//
// Sourcing for the npm list (~100 entries):
//   - The 22 entries that pre-date this expansion were hand-picked from
//     long-running typosquat incidents (event-stream, ua-parser-js, etc.).
//   - The added entries cover the npm ecosystem's most-installed packages
//     across the categories typosquat attackers actually target — meta-
//     frameworks, state libs, build tooling, the lodash submodule family,
//     HTTP clients, ORM/database drivers, validation, dates, IDs, auth,
//     logging, GraphQL/data-fetching, templating, and async utilities.
//     Cross-referenced against npmjs.com's "most depended-upon packages"
//     listing and the publicly-tracked top-1000 lists at npmtrends.com.
//
// Sourcing for the pip and rubygems lists (~40 + ~20 entries respectively):
//   - Hand-curated from each registry's public "most-downloaded" rankings
//     (PyPI's top-pypi-packages list and rubygems.org's downloaded-most
//     view). Same category coverage as npm: web frameworks, HTTP clients,
//     ML/scientific stack (pip), data pipelines, dev toolchain, auth.
//   - Pre-checked for distance-1 collisions with the same script-style
//     pass that vetted the npm expansion (see Constraints below). No
//     intra-list collisions remain at the time of expansion.
//
// Constraints when extending:
//   - Avoid 2- or 3-character names (false-positive magnets that already
//     trip sc.short_name) unless the package is exceptionally famous.
//   - Pre-check new entries against the existing list with Damerau-
//     Levenshtein — any pair within distance 1 will false-flag each
//     other for non-seed package names.  (Exact matches against the
//     seed list itself short-circuit to "no signal" via a first-pass
//     check in checkTyposquat, so e.g. "next" stays clean even though
//     "nuxt" is at distance 1.)
//   - The detector strips the "@scope/" prefix before comparison, so adding
//     "@types/X" entries is redundant — store the bare type name instead.
var wellKnownPackages = map[string][]string{
	"npm": {
		// Original seed (pre-expansion).
		"lodash", "react", "express", "axios", "webpack", "babel",
		"typescript", "eslint", "prettier", "moment", "chalk", "commander",
		"dotenv", "jest", "mocha", "underscore", "jquery", "angular",
		"vue", "next", "nuxt", "vite",
		// Frameworks, routing, state.
		"react-dom", "react-native", "react-router", "react-router-dom",
		"redux", "react-redux", "zustand", "svelte", "preact-compat",
		"ember-source",
		// Build tooling, bundlers, CSS pipeline.
		"rollup", "parcel", "esbuild", "tsx", "ts-node",
		"postcss", "tailwindcss", "sass",
		"styled-components", "emotion",
		// Testing.
		"vitest", "cypress", "playwright", "chai", "sinon", "jasmine",
		// Lodash submodule family (most-installed members; "get"/"set" both
		// being present would collide at distance 1, so only "get" is kept).
		"lodash.merge", "lodash.get", "lodash.debounce", "lodash.clonedeep",
		"lodash.template", "lodash.isequal", "lodash.pick", "lodash.throttle",
		"ramda",
		// HTTP clients.
		"node-fetch", "got", "superagent", "undici",
		// Servers and middleware.
		"koa", "fastify", "hapi", "nestjs",
		"body-parser", "cors", "helmet", "multer",
		// Dates.
		"dayjs", "date-fns", "luxon",
		// Validation.
		"zod", "joi", "ajv",
		// IDs.
		"uuid", "nanoid",
		// Filesystem / utility.
		"semver", "glob", "minimatch", "fs-extra", "rimraf",
		// Logging.
		"winston", "pino",
		// CLI argument parsing.
		"yargs", "minimist",
		// Sockets.
		"socket.io", "ws",
		// Auth and crypto.
		"bcrypt", "jsonwebtoken", "passport",
		// Databases / ORMs.
		"mongoose", "sequelize", "prisma", "typeorm", "mysql2", "redis",
		// GraphQL and data fetching.
		"graphql", "apollo-client", "swr", "react-query",
		// Templating / markdown.
		"handlebars", "ejs", "pug", "marked",
		// Dev tooling.
		"nodemon", "cross-env",
		// Async / reactive.
		"async", "rxjs",
	},
	"pip": {
		// Original seed (pre-expansion).
		"requests", "numpy", "pandas", "flask", "django", "sqlalchemy",
		"boto3", "pytest", "setuptools", "pip", "cryptography", "urllib3",
		// Web frameworks + ASGI/WSGI ecosystem.
		"fastapi", "starlette", "uvicorn", "gunicorn", "tornado",
		// Data validation, settings, HTTP clients.
		"pydantic", "httpx", "aiohttp",
		// Imaging + scientific stack — extremely high-traffic typosquat
		// targets per past PyPI incidents (e.g. "pilow", "scilearn").
		"pillow", "matplotlib", "scipy", "scikit-learn",
		// ML / DL frameworks. "tensorflow" and "torch" alone account for
		// multiple historical malicious-package incidents.
		"tensorflow", "torch", "transformers",
		// Async, scheduling, task queues.
		"celery", "redis",
		// Testing + linting + formatting toolchain.
		"black", "ruff", "mypy", "tox",
		// Templating, CLI, env.
		"jinja2", "click", "rich", "typer",
		// Datetime / parsing.
		"python-dateutil", "pytz",
		// Cloud / infra SDKs beyond boto3.
		"google-cloud-storage", "azure-storage-blob", "kubernetes",
		// Config + serialization.
		"pyyaml", "tomli",
	},
	"rubygems": {
		// Original seed (pre-expansion).
		"rails", "rake", "rspec", "bundler", "sinatra", "devise",
		// HTML/XML parsing — long-running typosquat target.
		"nokogiri",
		// Servers, middleware, templating.
		"puma", "rack", "thin",
		// Developer tooling.
		"pry", "rubocop", "byebug",
		// HTTP / networking.
		"faraday", "httparty",
		// Background processing + caching + datastores.
		"sidekiq", "redis", "concurrent-ruby",
		// JSON.
		"oj",
		// Auth + uploads.
		"omniauth", "carrierwave",
	},
	"go": {},
}

// checkTyposquat returns a warn signal when the package name is suspiciously
// close (edit distance 1) to a well-known package in the same ecosystem.
//
// Distance is computed with the shared Damerau-Levenshtein helper from the
// internal/typosquat package — the same engine the proxy detector uses — so
// PR-scan and the proxy stay in agreement. In particular, a single
// transposition (e.g. axios ↔ axois) counts as distance 1, which plain
// Levenshtein would have scored as 2 and missed.
func checkTyposquat(ecosystem, name string) (prScanSignal, bool) {
	// Strip npm scope for comparison.
	compareName := name
	if strings.HasPrefix(name, "@") {
		parts := strings.SplitN(name, "/", 2)
		if len(parts) == 2 {
			compareName = parts[1]
		}
	}
	candidates := wellKnownPackages[ecosystem]
	// Two-pass scan: exact match wins over distance-1.  Without this the
	// loop could return a distance-1 hit on an earlier seed entry before
	// reaching a later exact match (e.g. "next" matching "nuxt" at d=1
	// before reaching the "next" entry itself).  See LOW#2.
	for _, known := range candidates {
		if compareName == known {
			return prScanSignal{}, false // exact match — not a typosquat
		}
	}
	for _, known := range candidates {
		dist := typosquat.DamerauLevenshtein(compareName, known)
		if dist == 1 {
			return prScanSignal{
				ID:       prScanTyposquatSignalID,
				Severity: "warn",
				Reason:   fmt.Sprintf("name distance to %q = 1 (possible typosquat)", known),
			}, true
		}
	}
	return prScanSignal{}, false
}

// ---------------------------------------------------------------------------
// Human-readable output
// ---------------------------------------------------------------------------

func printPRScanReport(cmd *cobra.Command, r prScanReport) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "base: %s\nhead: %s\n\n", r.Base[:minInt(12, len(r.Base))], r.Head[:minInt(12, len(r.Head))])

	total := r.Summary.Added + r.Summary.Upgraded
	if total == 0 {
		fmt.Fprintln(out, "no manifest/lockfile changes detected")
		return
	}

	fmt.Fprintf(out, "added: %d  upgraded: %d  blocking: %d  warnings: %d\n\n",
		r.Summary.Added, r.Summary.Upgraded, r.Summary.Blocking, r.Summary.Warnings)

	fmt.Fprintln(out, "offline heuristics only "+glyphs().dash+" run `chainsaw scan` for full signals")
	fmt.Fprintln(out)

	printEntryGroup(cmd, "Added dependencies", r.Added)
	printEntryGroup(cmd, "Upgraded dependencies", r.Upgraded)
}

// prScanVerdictIcon maps a pr-scan verdict to its row marker.
//
// pr-scan is the one command that speaks EMOJI rather than the CLI's ✓/✗/⚠
// vocabulary, because its primary reader is a GitHub Actions log. Two of the
// three are astral-plane (🚫 U+1F6AB) or carry a VS16 emoji-presentation
// selector (⚠️ = U+26A0 U+FE0F); none is in CP437, and the VS16 pair is the
// worst of the set because a console that cannot encode it may render TWO
// boxes for one marker, shifting the coordinate that follows.
//
// The emoji are preserved verbatim on a capable console — a CI log is exactly
// where they earn their keep, and this change must not alter what the 99% see.
// The fallback drops to the shared ASCII markers rather than inventing a
// fourth alphabet. Within either branch all three markers share a width, so
// the "  %s [eco] name@ver" column never shifts between rows.
func prScanVerdictIcon(g glyphSet, verdict string) string {
	if g == unicodeGlyphs {
		switch verdict {
		case "block":
			return "🚫"
		case "warn":
			return "⚠️"
		default:
			return "✅"
		}
	}
	switch verdict {
	case "block":
		return g.fail
	case "warn":
		return g.warn
	default:
		return g.ok
	}
}

func printEntryGroup(cmd *cobra.Command, title string, entries []prScanEntry) {
	if len(entries) == 0 {
		return
	}
	out := cmd.OutOrStdout()
	g := glyphs()
	fmt.Fprintf(out, "%s (%d)\n", title, len(entries))
	for _, e := range entries {
		icon := prScanVerdictIcon(g, e.Verdict)
		prev := ""
		if e.PreviousVersion != nil {
			prev = fmt.Sprintf(" (was %s)", *e.PreviousVersion)
		}
		fmt.Fprintf(out, "  %s [%s] %s@%s%s\n", icon, e.Ecosystem, e.Name, e.Version, prev)
		for _, s := range e.Signals {
			fmt.Fprintf(out, "       %s: %s\n", s.ID, s.Reason)
		}
	}
	fmt.Fprintln(out)
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
