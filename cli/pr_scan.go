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
//
// With --strict, warn-level findings are treated as blocking (exit 20).
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
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/typosquat"
)

// pr-scan exit codes — distinct from the doctor matrix so a CI step that
// combines both gets a predictable non-zero without ambiguity.
const (
	prScanExitOK       = 0
	prScanExitWarning  = 10
	prScanExitBlocking = 20
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
	Added    int `json:"added"`
	Upgraded int `json:"upgraded"`
	Blocking int `json:"blocking"`
	Warnings int `json:"warnings"`
}

// prScanReport is the top-level JSON output document.
type prScanReport struct {
	Schema   string        `json:"schema"`
	Base     string        `json:"base"`
	Head     string        `json:"head"`
	Added    []prScanEntry `json:"added"`
	Upgraded []prScanEntry `json:"upgraded"`
	Summary  prScanSummary `json:"summary"`
}

func init() {
	cmd := &cobra.Command{
		Use:   "pr-scan",
		Short: "Diff manifest/lockfile changes and flag added or upgraded dependencies",
		Long: `Compares manifest and lockfile files between two git refs and reports every
newly added or upgraded dependency coordinate (name@version). For each
coordinate the offline signal engine emits supply-chain signals; the final
verdict is "allow", "warn", or "block".

Intended as a required-status-check companion to chainsaw scan-repo: scan-repo
catches committed bypass config; pr-scan catches newly introduced packages.

Exit codes:
  0   clean — no warn or block findings
  10  one or more warning-level findings
  20  one or more blocking findings (also exit 20 with --strict + any warning)`,
		RunE: runPRScan,
	}
	cmd.Flags().String("base", "", "Base git ref or SHA to diff from (required)")
	cmd.Flags().String("head", "HEAD", "Head git ref or SHA to diff to (default: HEAD)")
	cmd.Flags().String("repo-path", ".", "Path to the git repository")
	cmd.Flags().Bool("json", false, "Emit JSON output")
	cmd.Flags().String("output-file", "", "Write the JSON report to this path (implies --json)")
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

	// Write output.
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

	// Apply --strict escalation.
	if strict && exitCode == prScanExitWarning {
		exitCode = prScanExitBlocking
	}

	if exitCode != prScanExitOK {
		os.Exit(exitCode)
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
		Base:     baseSHA,
		Head:     headSHA,
		Added:    []prScanEntry{},
		Upgraded: []prScanEntry{},
	}

	// Find changed manifest/lockfile paths.
	changedFiles, err := gitDiffFiles(absRepo, baseSHA, headSHA)
	if err != nil {
		return report, prScanExitOK, fmt.Errorf("git diff: %w", err)
	}

	for _, rel := range changedFiles {
		eco, ok := classifyManifest(rel)
		if !ok {
			continue
		}

		baseContent, _ := gitFileAtRef(absRepo, baseSHA, rel)
		// baseContent may be nil — file newly created at head.

		headContent, err := gitFileAtRef(absRepo, headSHA, rel)
		if err != nil || headContent == nil {
			// File removed or unreadable — skip (removals are risk-reduction).
			continue
		}

		added, upgraded, parseErr := diffManifest(eco, rel, baseContent, headContent)
		if parseErr != nil {
			// Best-effort: log and continue.
			fmt.Fprintf(os.Stderr, "pr-scan: parse %s: %v\n", rel, parseErr)
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

	return report, exitCode, nil
}

// resolveRef converts any git ref (branch name, tag, HEAD~N, full SHA, etc.)
// to a canonical full-length SHA by running `git rev-parse`.
func resolveRef(repoPath, ref string) (string, error) {
	out, err := runGit(repoPath, "rev-parse", ref)
	if err != nil {
		return "", err
	}
	sha := strings.TrimSpace(out)
	if sha == "" {
		return "", fmt.Errorf("empty output from git rev-parse %s", ref)
	}
	return sha, nil
}

// gitDiffFiles returns the list of files that differ between base and head
// (using `git diff --name-only`). Both args must be resolved SHAs or valid refs.
func gitDiffFiles(repoPath, base, head string) ([]string, error) {
	out, err := runGit(repoPath, "diff", "--name-only", base, head)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			files = append(files, line)
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
		baseCoords = parsePackageJSONDeps(baseContent)
		headCoords = parsePackageJSONDeps(headContent)
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

// parsePackageLockJSON extracts the flat packages map from package-lock.json v2/v3.
// Falls back to a best-effort v1 parse (dependencies key).
func parsePackageLockJSON(data []byte) (map[string]string, error) {
	if data == nil {
		return nil, nil
	}
	var root struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Version  string `json:"version"`
			Resolved string `json:"resolved"`
		} `json:"packages"`
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	out := make(map[string]string)
	if len(root.Packages) > 0 {
		for path, pkg := range root.Packages {
			if pkg.Version == "" || path == "" {
				continue
			}
			// Strip "node_modules/" prefix to get the package name.
			name := strings.TrimPrefix(path, "node_modules/")
			if name == "" {
				continue
			}
			out[name] = pkg.Version
		}
	} else {
		for name, dep := range root.Dependencies {
			if dep.Version != "" {
				out[name] = dep.Version
			}
		}
	}
	return out, nil
}

// parsePackageJSONDeps extracts declared dependencies from package.json
// (dependencies + devDependencies). Versions may be semver ranges here, not
// resolved; useful for detecting new entries.
func parsePackageJSONDeps(data []byte) map[string]string {
	if data == nil {
		return nil
	}
	var root struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}
	out := make(map[string]string)
	for k, v := range root.Dependencies {
		out[k] = v
	}
	for k, v := range root.DevDependencies {
		out[k] = v
	}
	return out
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
	if err := json.Unmarshal(data, &root); err != nil {
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
				ID:       "sc.typosquat_low",
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

	printEntryGroup(cmd, "Added dependencies", r.Added)
	printEntryGroup(cmd, "Upgraded dependencies", r.Upgraded)
}

func printEntryGroup(cmd *cobra.Command, title string, entries []prScanEntry) {
	if len(entries) == 0 {
		return
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "%s (%d)\n", title, len(entries))
	for _, e := range entries {
		icon := "✅"
		if e.Verdict == "block" {
			icon = "🚫"
		} else if e.Verdict == "warn" {
			icon = "⚠️"
		}
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
