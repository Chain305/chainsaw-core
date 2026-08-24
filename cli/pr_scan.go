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
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/policy"
	"github.com/chain305/chainsaw-core/policy/dsl"
	"github.com/chain305/chainsaw-core/policyengine"
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
	Ecosystem       string         `json:"ecosystem"`
	Name            string         `json:"name"`
	Version         string         `json:"version"`
	PreviousVersion *string        `json:"previous_version"`
	Signals         []prScanSignal `json:"signals"`
	Verdict         string         `json:"verdict"` // "allow", "warn", or "block"
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
	cmd.Flags().Bool("json", false, "Emit JSON output")
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
		if !ok {
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
	sort.Slice(report.Added, func(i, j int) bool {
		return report.Added[i].Ecosystem+report.Added[i].Name < report.Added[j].Ecosystem+report.Added[j].Name
	})
	sort.Slice(report.Upgraded, func(i, j int) bool {
		return report.Upgraded[i].Ecosystem+report.Upgraded[i].Name < report.Upgraded[j].Ecosystem+report.Upgraded[j].Name
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
}

// diffManifest returns lists of added and upgraded coordinates by comparing
// base and head content. baseContent may be nil (file newly added at head).
func diffManifest(kind manifestKind, relPath string, baseContent, headContent []byte) (added, upgraded []rawEntry, err error) {
	eco := strings.SplitN(string(kind), ":", 2)[0]

	var baseCoords, headCoords map[string]string // name → version
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
	case kindNPMPackageJSON:
		baseCoords, err = parsePackageJSONDeps(baseContent)
		if err != nil {
			return nil, nil, fmt.Errorf("%s base: %w", relPath, err)
		}
		headCoords, err = parsePackageJSONDeps(headContent)
		if err != nil {
			return nil, nil, fmt.Errorf("%s head: %w", relPath, err)
		}
	case kindPNPMLock:
		baseCoords = parsePNPMLock(baseContent)
		headCoords = parsePNPMLock(headContent)
	case kindYarnLock:
		baseCoords = parseYarnLock(baseContent)
		headCoords = parseYarnLock(headContent)
	case kindPipRequirements:
		baseCoords = parsePipRequirements(baseContent)
		headCoords = parsePipRequirements(headContent)
	case kindPipfileLock:
		baseCoords, err = parsePipfileLock(baseContent)
		if err != nil {
			return nil, nil, fmt.Errorf("%s base: %w", relPath, err)
		}
		headCoords, err = parsePipfileLock(headContent)
		if err != nil {
			return nil, nil, fmt.Errorf("%s head: %w", relPath, err)
		}
	case kindPoetryLock:
		baseCoords = parsePoetryLock(baseContent)
		headCoords = parsePoetryLock(headContent)
	case kindUVLock:
		baseCoords = parseUVLock(baseContent)
		headCoords = parseUVLock(headContent)
	case kindGemfileLock:
		baseCoords = parseGemfileLock(baseContent)
		headCoords = parseGemfileLock(headContent)
	case kindGoSum:
		baseCoords = parseGoSum(baseContent)
		headCoords = parseGoSum(headContent)
	case kindCargoLock:
		baseCoords = parseCargoLock(baseContent)
		headCoords = parseCargoLock(headContent)
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
	return added, upgraded, nil
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
			name := pkg.Name
			if name == "" {
				name = lockEntryNameFor(mode, path)
			}
			if name == "" {
				continue
			}
			out[name] = pkg.Version
			record(name, pkg.Version, pkg.Integrity)
		}
	} else {
		for key, dep := range root.Dependencies {
			if dep.Version == "" {
				continue
			}
			name := dep.Name
			if name == "" {
				name = key
			}
			out[name] = dep.Version
			record(name, dep.Version, dep.Integrity)
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

// parsePackageLockCoordinates returns EVERY installed coordinate in a
// package-lock, without collapsing duplicates.
//
// ── WHY THIS EXISTS AND WHY THE MAP FORM CANNOT BE USED HERE ─────────
//
// parsePackageLockIntegrityJSONMode returns map[name]version. A real npm
// tree installs the SAME NAME AT SEVERAL VERSIONS routinely — a measured
// ui_new lockfile carries 40 such names (minimatch at four versions,
// react-is and ansi-styles at three) and a landing lockfile carries 46.
// Collapsing them through a bare-name map does two bad things at once:
// it silently drops ~5% of installed coordinates (924 entries became
// 851), and because Go randomises map iteration, WHICH version survives
// changes between runs of the same binary over the same file. Parsing
// one file 25 times produced minimatch@10.2.5 eleven times and
// minimatch@3.1.5 four times.
//
// For pr-scan's report rows that is survivable: a row is a human-facing
// finding about a name. For the GUARD it is not. The guard turns each
// coordinate into a cache key and analyses the bytes it finds, so a
// collapsed map means the byte scan silently skips real installed
// packages and is not reproducible run to run — a security control whose
// coverage is a coin flip and whose gaps never appear twice in a bug
// report.
//
// The integrity map was already keyed name@version for exactly this
// reason (see the note on record()). The version side was not. This
// returns coordinates so neither side can collapse.
func parsePackageLockCoordinates(data []byte) ([]lockCoordinate, error) {
	if data == nil {
		return nil, nil
	}
	var root struct {
		Packages map[string]struct {
			// An aliased dependency records the REAL package in "name" while
			// the map key holds the alias. Same rule as the map parser: an
			// explicit name always wins over the path.
			Name      string `json:"name"`
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Name      string `json:"name"`
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(stripUTF8BOM(data), &root); err != nil {
		return nil, err
	}

	// Keyed name@version, so the same name at several versions survives as
	// several coordinates. Conflicting SRIs for ONE coordinate collapse to
	// no anchor rather than a coin flip, matching record() in the map
	// parser: a wrong anchor manufactures a digest mismatch on a clean
	// install, which is worse than no anchor at all.
	byCoord := make(map[string]*lockCoordinate)
	add := func(name, version, sri string) {
		if name == "" || version == "" {
			return
		}
		k := lockIntegrityKey(name, version)
		cur, seen := byCoord[k]
		if !seen {
			byCoord[k] = &lockCoordinate{Name: name, Version: version, Integrity: sri}
			return
		}
		if cur.Integrity == "" || sri == "" || cur.Integrity == sri {
			if cur.Integrity == "" {
				cur.Integrity = sri
			}
			return
		}
		cur.Integrity = "" // conflicting anchors for one coordinate
	}

	if len(root.Packages) > 0 {
		for path, pkg := range root.Packages {
			if path == "" {
				continue
			}
			name := pkg.Name
			if name == "" {
				name = lockEntryNameFor(lockNamesInstalled, path)
			}
			add(name, pkg.Version, pkg.Integrity)
		}
	} else {
		for key, dep := range root.Dependencies {
			name := dep.Name
			if name == "" {
				name = key
			}
			add(name, dep.Version, dep.Integrity)
		}
	}

	out := make([]lockCoordinate, 0, len(byCoord))
	for _, c := range byCoord {
		out = append(out, *c)
	}
	// Stable order: map iteration above is randomised by design, and a
	// security control whose coverage order varies per run cannot be
	// diffed between two runs.
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out, nil
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
func parsePackageJSONDeps(data []byte) (map[string]string, error) {
	if data == nil {
		return nil, nil
	}
	var root struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(stripUTF8BOM(data), &root); err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for k, v := range root.Dependencies {
		out[k] = v
	}
	for k, v := range root.DevDependencies {
		out[k] = v
	}
	return out, nil
}

// parsePNPMLock is a best-effort line-oriented parser for pnpm-lock.yaml.
// We avoid a full YAML dependency; the format has stable patterns:
//
//	/package@version:   (leading slash, package name, @ version, colon)
func parsePNPMLock(data []byte) map[string]string {
	if data == nil {
		return nil
	}
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		// pnpm lockfile v6: lines like "  /chalk@5.3.0:"
		// pnpm lockfile v9: lines like "  chalk@5.3.0:" (no leading slash)
		if !strings.HasSuffix(line, ":") {
			continue
		}
		entry := strings.TrimSuffix(line, ":")
		entry = strings.TrimPrefix(entry, "/")
		// Split on last "@" to handle scoped packages like "@scope/pkg@1.0.0".
		idx := strings.LastIndex(entry, "@")
		if idx <= 0 {
			continue
		}
		name := entry[:idx]
		version := entry[idx+1:]
		if name != "" && version != "" && !strings.Contains(version, "(") {
			// Deduplicate: keep first seen (lowest version is typically the
			// resolved one for multiple range entries).
			if _, exists := out[name]; !exists {
				out[name] = version
			}
		}
	}
	return out
}

// parseYarnLock parses yarn.lock (classic v1 format and berry v2/v3).
// Pattern: lines starting with a quoted name+"@" followed eventually by
// a "  version" line.
func parseYarnLock(data []byte) map[string]string {
	if data == nil {
		return nil
	}
	out := make(map[string]string)
	var currentName string
	for _, line := range strings.Split(string(data), "\n") {
		// Entry header: `"pkg@range", "pkg@range2":` or `pkg@range:`
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(strings.TrimSpace(line), ":") {
			header := strings.TrimSuffix(strings.TrimSpace(line), ":")
			// Grab first specifier; extract package name before the "@" range.
			first := strings.SplitN(header, ",", 2)[0]
			first = strings.Trim(first, `"`)
			// Find the last "@" that separates name from range — but for
			// scoped packages "@scope/pkg@range" we want the second "@".
			if strings.HasPrefix(first, "@") {
				rest := first[1:]
				if idx := strings.Index(rest, "@"); idx >= 0 {
					currentName = "@" + rest[:idx]
				} else {
					currentName = ""
				}
			} else {
				if idx := strings.Index(first, "@"); idx >= 0 {
					currentName = first[:idx]
				} else {
					currentName = ""
				}
			}
			continue
		}
		if currentName == "" {
			continue
		}
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "version ") {
			ver := strings.TrimPrefix(trimmed, "version ")
			ver = strings.Trim(ver, `"`)
			if _, exists := out[currentName]; !exists {
				out[currentName] = ver
			}
			currentName = ""
		}
	}
	return out
}

// parsePipRequirements parses a requirements.txt file (simple name==version lines).
func parsePipRequirements(data []byte) map[string]string {
	if data == nil {
		return nil
	}
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Handle name==version, name>=version etc.
		for _, sep := range []string{"==", "~=", ">=", "<="} {
			if idx := strings.Index(line, sep); idx > 0 {
				name := strings.TrimSpace(line[:idx])
				ver := strings.TrimSpace(line[idx+len(sep):])
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
	return out
}

// parsePipfileLock parses Pipfile.lock (JSON with default/develop keys).
func parsePipfileLock(data []byte) (map[string]string, error) {
	if data == nil {
		return nil, nil
	}
	var root map[string]map[string]struct {
		Version string `json:"version"`
	}
	if err := json.Unmarshal(stripUTF8BOM(data), &root); err != nil {
		return nil, err
	}
	out := make(map[string]string)
	for section, pkgs := range root {
		if section == "_meta" {
			continue
		}
		for name, pkg := range pkgs {
			ver := strings.TrimPrefix(pkg.Version, "==")
			if ver != "" {
				out[strings.ToLower(name)] = ver
			}
		}
	}
	return out, nil
}

// parsePoetryLock parses poetry.lock (TOML-ish; we use line scanning since
// we don't want a TOML dependency).  Pattern: [[package]] blocks with
// name = "..." and version = "..." fields.
func parsePoetryLock(data []byte) map[string]string {
	if data == nil {
		return nil
	}
	out := make(map[string]string)
	var currentName string
	inPkg := false
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "[[package]]" {
			inPkg = true
			currentName = ""
			continue
		}
		if !inPkg {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			inPkg = false
			currentName = ""
			continue
		}
		if strings.HasPrefix(trimmed, "name = ") {
			currentName = strings.Trim(strings.TrimPrefix(trimmed, "name = "), `"`)
		} else if strings.HasPrefix(trimmed, "version = ") && currentName != "" {
			ver := strings.Trim(strings.TrimPrefix(trimmed, "version = "), `"`)
			if ver != "" {
				out[currentName] = ver
			}
		}
	}
	return out
}

// parseUVLock parses uv.lock (TOML-ish, similar structure to poetry.lock).
// Pattern: [[package]] blocks with name = "..." and version = "...".
func parseUVLock(data []byte) map[string]string {
	// uv.lock uses the same [[package]] / name / version layout as poetry.lock.
	return parsePoetryLock(data)
}

// parseGemfileLock parses Gemfile.lock.  The GEM section lists "    gem (version)"
// lines under "  specs:".
func parseGemfileLock(data []byte) map[string]string {
	if data == nil {
		return nil
	}
	out := make(map[string]string)
	inSpecs := false
	for _, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "specs:" {
			inSpecs = true
			continue
		}
		if inSpecs {
			// Blank line or section header resets.
			if strings.TrimSpace(line) == "" || (len(line) > 0 && line[0] != ' ') {
				inSpecs = false
				continue
			}
			// 4-space-indented lines are "    name (version)" or "      dep".
			if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     ") {
				entry := strings.TrimSpace(line)
				if idx := strings.Index(entry, " ("); idx > 0 {
					name := entry[:idx]
					ver := strings.TrimSuffix(entry[idx+2:], ")")
					// Strip platform suffix "1.0.0-x86_64-linux".
					if dashIdx := strings.Index(ver, "-"); dashIdx > 0 {
						candidate := ver[:dashIdx]
						// Only strip if it looks like a platform suffix (has letters).
						if strings.ContainsAny(ver[dashIdx:], "abcdefghijklmnopqrstuvwxyz") {
							ver = candidate
						}
					}
					if name != "" && ver != "" {
						out[name] = ver
					}
				}
			}
		}
	}
	return out
}

// parseCargoLock parses Cargo.lock.  It is TOML with repeated [[package]]
// blocks, each carrying `name = "x"` and `version = "y"` lines.  We pair the
// name and version within each block (line-based, no TOML dependency).
func parseCargoLock(data []byte) map[string]string {
	if data == nil {
		return nil
	}
	out := make(map[string]string)
	name, version := "", ""
	flush := func() {
		if name != "" && version != "" {
			out[name] = version
		}
		name, version = "", ""
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
		if strings.TrimSpace(line) == "[[package]]" {
			flush() // close out any prior block
			continue
		}
		if v, ok := tomlString(line, "name"); ok {
			name = v
			continue
		}
		if v, ok := tomlString(line, "version"); ok {
			version = v
		}
	}
	flush() // final block
	return out
}

// parseGoSum parses go.sum.  Each line is: "module version hash".
// We collect the module@version pairs (ignoring /go.mod lines since those
// are just the go.mod of each module and don't represent an additional download).
func parseGoSum(data []byte) map[string]string {
	if data == nil {
		return nil
	}
	out := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// fields[0] = module path, fields[1] = version/go.mod
		modPath := fields[0]
		verField := fields[1]
		// Skip the /go.mod variant — only count the module itself.
		if strings.HasSuffix(verField, "/go.mod") {
			continue
		}
		// Strip build-metadata suffix (e.g. "+incompatible").
		ver := strings.SplitN(verField, "+", 2)[0]
		// go.sum versions start with "v"; keep as-is for fidelity.
		if _, exists := out[modPath]; !exists {
			out[modPath] = ver
		}
	}
	return out
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

	for _, s := range signals {
		if s.Severity == "block" {
			out.Verdict = "block"
			break
		} else if s.Severity == "warn" && out.Verdict == "allow" {
			out.Verdict = "warn"
		}
	}

	return out
}

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
	}
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
