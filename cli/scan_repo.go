package cli

// `chainsaw scan-repo` walks a repo tree and flags files that bypass
// Chainsaw: committed `.npmrc` registries, `--index-url` lines in
// requirements.txt, Maven `<repository>` blocks in pom.xml, NuGet
// sources in nuget.config, Docker images without the Chainsaw host
// prefix, etc. Intended to run in CI as a required status check so
// bypasses are caught at PR time rather than after the fact.
//
// Exit codes: 0 clean, 10 bypass files found, 2 the scan could not be
// completed (the path does not exist, or a candidate file could not be
// inspected). 10 shares the `doctor --strict` matrix so a single CI step
// combining both gets a predictable non-zero on either signal; 2 is
// deliberately NOT 10, because "the tool was prevented from looking" must not
// be reported as "a bypass was found".
//
// P8-27 — the verdict is produced by emitAndGateInto, so the gate is the last
// statement on every non-error path and no rendering choice can reach a
// `return` ahead of it. That is the structural form of the fix scan-remote's
// S1 applied after `--json` had silently disarmed its gate on every
// invocation. Two explicit knobs sit on the gate: --exit-zero (report without
// gating) and --fail-on-unscanned (default ON here — see runScanRepo).
//
// This is a pragmatic grep — a full Gradle / Maven AST parser is out
// of scope. False positives are surfaced as suggestions ("committed
// .npmrc — ensure registry is Chainsaw-pointed") rather than hard
// fails when the file looks benign.

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

type scanFinding struct {
	File     string `json:"file"`
	Category string `json:"category"`
	Rule     string `json:"rule"`
	Detail   string `json:"detail"`
}

type scanReport struct {
	Root string `json:"root"`
	// Findings must be non-nil whenever this struct is marshalled: `findings`
	// is an ARRAY in every case, including the clean one. See runScanRepo's
	// initialiser. No `omitempty` — the key is part of the contract.
	Findings []scanFinding `json:"findings"`
	// Unreadable lists candidate files the walk could not read (permissions,
	// a broken symlink, an IO error). X2: these used to be swallowed by a bare
	// `return nil`, so a file the rules WOULD have flagged reported as clean.
	// `omitempty` keeps a clean repo's JSON byte-identical to the pre-fix
	// shape, and the slice is sorted alongside Findings so `scan-repo --json`
	// stays deterministic across runs.
	Unreadable []string `json:"unreadable,omitempty"`
}

// scanRepoMaxFileBytes caps how much of a single file scan-repo will read.
//
// S7: the walk had no filter and no cap — every regular file in the tree was
// read fully into memory and then copied again by `string(data)`. Measured:
// 665 MB RSS on a 300 MB blob, 1,715,273,728 bytes on an 800 MB one, for files
// no rule can ever match. 4 MiB is far above any real .npmrc / pom.xml /
// Dockerfile while keeping a pathological fixture from OOM-ing the CI step.
const scanRepoMaxFileBytes = 4 << 20

// scanRepoCandidateBasenames is the set of exact basenames inspectFile's switch
// can match. isScanRepoCandidate gates the (expensive) file read on it.
//
// INVARIANT: this must stay in sync with inspectFile's `case` arms. The prefix/
// suffix arms (requirements*.txt, Dockerfile.*) are handled separately below.
// TestScanRepoCandidatePredicate_CoversEveryInspectFileArm pins every arm.
var scanRepoCandidateBasenames = map[string]bool{
	".npmrc":              true,
	".yarnrc":             true,
	".yarnrc.yml":         true,
	"bunfig.toml":         true,
	".bunfig.toml":        true,
	"pip.conf":            true,
	"pip.ini":             true,
	"pyproject.toml":      true,
	"pom.xml":             true,
	"build.gradle":        true,
	"build.gradle.kts":    true,
	"settings.gradle":     true,
	"settings.gradle.kts": true,
	"nuget.config":        true,
	"NuGet.Config":        true,
	"config.toml":         true, // inspectFile additionally requires a .cargo/ path
	"Gemfile":             true,
	"Podfile":             true,
	"Package.swift":       true,
	"Dockerfile":          true,
}

// isScanRepoCandidate reports whether a basename can possibly match a rule in
// inspectFile. Anything else is skipped WITHOUT being read.
func isScanRepoCandidate(base string) bool {
	if scanRepoCandidateBasenames[base] {
		return true
	}
	if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
		return true
	}
	if strings.HasPrefix(base, "Dockerfile.") {
		return true
	}
	return false
}

func init() {
	cmd := &cobra.Command{
		Use:     "scan-repo [path]",
		GroupID: GrpScan,
		Short:   "Scan a repo tree for Chainsaw-bypass config files",
		Long: `Walks the given directory (default: current) and flags files that can
route package traffic around Chainsaw: committed .npmrc / .yarnrc.yml /
.bunfig.toml registries, pip/poetry index-url, Maven <repository>, NuGet
packageSources, Cargo [source.*] replace-with entries, GOPROXY overrides,
Dockerfile images without the Chainsaw prefix, CocoaPods non-Chainsaw
sources, SPM .package(url:) direct dependencies.

Exit codes:
  0  the tree is clean
  10 at least one bypass file was found
  2  the scan could not be completed — the path does not exist, or a file a
     rule applies to could not be read (a tree that was not fully inspected
     is not reported as clean)

The exit gate applies to EVERY output format. Choosing --json (or a repo-wide
--format json) is a rendering decision and never weakens the verdict.

Gate control:
  --exit-zero              report findings but always exit 0 (monitor mode)
  --fail-on-unscanned      exit 2 when a candidate file could not be inspected.
                           ON by default; pass --fail-on-unscanned=false to
                           downgrade that case to a warning on stderr.

Files larger than 4 MiB are not inspected and are reported as skipped.

Intended for CI preflight ("required status check").`,
		RunE: runScanRepo,
	}
	// P8-27 — no local --json here. The root persistent --json (root.go) is
	// documented as sugar for --format=json and useJSON/resolveFormat read it;
	// a local shadow made the two flags two different variables and is the
	// mechanism behind scan-remote's S1 gate-disarm. `policy gate` had the
	// same shadow removed for the same reason.
	//
	// --fail-on-unscanned DEFAULTS ON here, which is the one place this
	// command's semantics deviate from `chainsaw scan`'s. It is not a
	// difference of posture but of history: scan-repo has ALWAYS exited 2 on
	// an uninspectable candidate (X2), unconditionally and with no way to opt
	// out. Registering the flag default-off would silently disarm a shipped
	// fail-closed gate — a security regression dressed as a consistency fix.
	// So the default preserves today's behaviour exactly and the flag adds
	// only the escape hatch that did not exist. `scan`'s default stays OFF
	// because its gate has never been armed and flipping it would break
	// existing CI on upgrade (scan.go's L-05).
	addScanGateFlags(cmd, scanGateFlags{
		FailOnUnscanned:        true,
		FailOnUnscannedDefault: true,
		FailOnUnscannedUsage:   "Exit 2 when a candidate file could not be inspected (default: on; pass =false to warn only)",
		ExitZero:               true,
		ExitZeroUsage:          "Always exit 0, even when bypass files are found (report-only mode)",
	})
	rootCmd.AddCommand(cmd)
}

func runScanRepo(cmd *cobra.Command, args []string) error {
	root := "."
	if len(args) > 0 {
		root = args[0]
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}
	// X1 — a nonexistent root used to report "no bypass files found" and exit 0
	// on a command whose own help calls it a required CI status check: a typo
	// in the path silently disarmed the gate. Stat before walking.
	//
	// ExitOpError(2), NOT doctorExitDrift(10): 10 means "a bypass WAS found",
	// so returning it here would report a mistyped path as a security finding.
	if _, statErr := os.Stat(abs); statErr != nil {
		return &ExitCodeError{Code: ExitOpError, Err: fmt.Errorf("scan-repo path %q: %w", root, statErr)}
	}
	// Findings starts as an EMPTY slice, not nil. A clean tree is the common
	// case for a command built to gate CI, and a nil slice marshals as
	// `"findings": null` — `report.findings.map(...)` throws TypeError and
	// `jq '.findings[]'` errors with "Cannot iterate over null", so the JSON
	// broke on exactly the automated path scan-repo exists for. `omitempty` is
	// deliberately NOT the fix: dropping the key breaks the same consumers a
	// different way. The non-empty shape is untouched — append to an empty
	// slice produces the identical array.
	report := scanReport{Root: abs, Findings: []scanFinding{}}
	errOut := cmd.ErrOrStderr()

	err = filepath.WalkDir(abs, func(path string, d fs.DirEntry, werr error) error {
		if werr != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "node_modules" || name == "vendor" ||
				name == ".gradle" || name == "target" || name == "build" ||
				name == "dist" || name == ".venv" || name == "venv" {
				return filepath.SkipDir
			}
			return nil
		}
		base := filepath.Base(path)
		rel, _ := filepath.Rel(abs, path)

		// S7 — decide from the BASENAME whether any rule could match before
		// spending a read (and a second full copy via string(data)) on the
		// file. Everything below this line runs on candidates only.
		if !isScanRepoCandidate(base) {
			return nil
		}

		if info, ierr := d.Info(); ierr == nil && info.Size() > scanRepoMaxFileBytes {
			// Loud, because this is coverage loss on a file we WOULD have
			// inspected — not the silent skip the size cap replaces.
			fmt.Fprintf(errOut, "warning: %s is %d bytes (> %d cap) — not inspected\n",
				rel, info.Size(), scanRepoMaxFileBytes)
			report.Unreadable = append(report.Unreadable, rel)
			return nil
		}

		data, rerr := os.ReadFile(path)
		if rerr != nil {
			// X2 — escalate only for CANDIDATE files. Escalating on every
			// unreadable file in the tree would fail CI on ordinary permission
			// noise (sockets, root-owned caches, broken symlinks); a candidate
			// we cannot read is a rule we cannot evaluate, which must not read
			// as "clean".
			fmt.Fprintf(errOut, "warning: cannot read %s: %v — not inspected\n", rel, rerr)
			report.Unreadable = append(report.Unreadable, rel)
			return nil
		}
		text := string(data)

		// Skip files that contain the chainsaw sentinel — those are
		// managed by install-hook and are expected to have the keys
		// we'd otherwise flag.
		if strings.Contains(text, "chainsaw-managed") {
			return nil
		}

		findings := inspectFile(rel, base, text)
		report.Findings = append(report.Findings, findings...)
		return nil
	})
	if err != nil {
		return err
	}

	sort.SliceStable(report.Findings, func(i, j int) bool {
		if report.Findings[i].File != report.Findings[j].File {
			return report.Findings[i].File < report.Findings[j].File
		}
		return report.Findings[i].Rule < report.Findings[j].Rule
	})
	// Sorted for the same reason Findings is: `scan-repo --json` must be
	// byte-identical across runs (WalkDir's order is lexical per directory but
	// the caller should not have to rely on that).
	sort.Strings(report.Unreadable)

	// P8-27 — render, THEN gate, on every format. The two branches below used
	// to be followed by three bare `return`s; nothing structural stopped a
	// future format branch from returning early and taking the verdict with
	// it, which is exactly how scan-remote's --json disarmed its own gate.
	// emitAndGateInto makes the ordering an invariant of the helper instead of
	// a property of this function's statement order.
	//
	// S9 — the JSON sink still honors --output, with cmd.OutOrStdout() as the
	// fallback so tests that capture via cmd.SetOut keep working.
	//
	// Y3/Y4 — the codes are RETURNED, not os.Exit'd. A bare exit skipped
	// Execute()'s telemetry flush entirely, so a drift-detecting scan-repo
	// (the outcome CI cares about) emitted zero cli.session.completed events.
	// doctorExitDrift (10) is unchanged — ExitCodeError carries arbitrary
	// codes — and Err stays nil on the findings path so renderError adds
	// nothing to the report already printed.
	return emitAndGateInto(cmd, cmd.OutOrStdout(), report,
		func() error { printScanReport(cmd, report); return nil },
		func() error {
			// Monitor mode. Deliberately does NOT cover the nonexistent-path
			// exit above: --exit-zero suppresses a VERDICT, never a failure to
			// run at all.
			if scanExitZero(cmd) {
				return nil
			}
			if len(report.Findings) > 0 {
				return &ExitCodeError{Code: doctorExitDrift}
			}
			// X2 — a tree with no findings but with candidate files we could
			// not read is NOT provably clean, so it must not exit 0.
			// ExitOpError(2) rather than doctorExitDrift(10): nothing was
			// found, the tool was prevented from looking. Findings win when
			// both are present (10 is the stronger signal and the one CI keys
			// on). Armed by default — see the flag registration above.
			if len(report.Unreadable) > 0 && resolveFailOnUnscanned(cmd, true) {
				return &ExitCodeError{
					Code: ExitOpError,
					Err:  fmt.Errorf("%d candidate file(s) could not be inspected; the tree is not provably clean", len(report.Unreadable)),
				}
			}
			return nil
		})
}

// inspectFile runs the full rule set over one file's contents and
// returns any findings. Returns nil when the file is benign.
func inspectFile(rel, base, text string) []scanFinding {
	var out []scanFinding
	add := func(category, rule, detail string) {
		out = append(out, scanFinding{File: rel, Category: category, Rule: rule, Detail: detail})
	}

	switch {
	case base == ".npmrc":
		if containsPrefixLine(text, "registry=") && !strings.Contains(text, "chainsaw") {
			add("npm", "project-npmrc-registry", "project .npmrc sets registry= — likely overrides system/user config")
		}
		if strings.Contains(text, ":_authToken=") && !strings.Contains(text, "CHAINSAW_TOKEN") {
			add("npm", "project-npmrc-authToken", "hardcoded :_authToken in project .npmrc — migrate to CHAINSAW_TOKEN env var")
		}
	case base == ".yarnrc" || base == ".yarnrc.yml":
		if strings.Contains(text, "npmRegistryServer") && !strings.Contains(text, "chainsaw") {
			add("yarn", "project-yarnrc-registry", "project yarnrc sets npmRegistryServer — overrides user config")
		}
	case base == "bunfig.toml" || base == ".bunfig.toml":
		if strings.Contains(text, "registry") && !strings.Contains(text, "chainsaw") {
			add("bun", "project-bunfig-registry", "project bunfig.toml configures registry — overrides user config")
		}
	case base == "pip.conf" || base == "pip.ini":
		if strings.Contains(text, "index-url") && !strings.Contains(text, "chainsaw") {
			add("pip", "project-pip-index-url", "project pip.conf sets index-url — overrides user config")
		}
	case strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
		for _, ln := range strings.Split(text, "\n") {
			t := strings.TrimSpace(ln)
			if strings.HasPrefix(t, "--index-url") || strings.HasPrefix(t, "--extra-index-url") {
				if !strings.Contains(t, "chainsaw") {
					add("pip", "requirements-index-url", "requirements.txt pins a non-Chainsaw index URL")
				}
			}
		}
	case base == "pyproject.toml":
		if strings.Contains(text, "[[tool.poetry.source]]") || strings.Contains(text, "[[tool.uv.index]]") {
			if !strings.Contains(text, "chainsaw") {
				add("pip", "pyproject-source-override", "pyproject.toml declares a non-Chainsaw package source")
			}
		}
	case base == "pom.xml":
		if strings.Contains(text, "<repository>") || strings.Contains(text, "<pluginRepository>") {
			add("maven", "pom-repositories", "pom.xml declares <repository> or <pluginRepository> — depends on mirrorOf=* being set on every workstation")
		}
	case base == "build.gradle" || base == "build.gradle.kts" ||
		base == "settings.gradle" || base == "settings.gradle.kts":
		low := strings.ToLower(text)
		if strings.Contains(low, "mavencentral()") || strings.Contains(low, "jcenter()") ||
			strings.Contains(low, "google()") || strings.Contains(low, "gradlepluginportal()") {
			add("gradle", "gradle-public-repo", "build/settings gradle file declares a public repository helper")
		}
	case base == "nuget.config" || base == "NuGet.Config":
		if strings.Contains(text, "api.nuget.org") || strings.Contains(text, "nuget.org/v3") {
			add("nuget", "nuget-public-source", "nuget.config pins a public nuget.org source")
		}
	case base == "config.toml" && strings.Contains(rel, ".cargo/"):
		if strings.Contains(text, "[source.") && !strings.Contains(text, "chainsaw") {
			add("cargo", "cargo-source-override", "cargo config declares a non-Chainsaw source")
		}
	case base == "Gemfile":
		if strings.Contains(text, "source \"https://rubygems.org") {
			add("rubygems", "gemfile-rubygems-source", "Gemfile uses public rubygems.org source without a Bundler mirror — works locally, breaks on fresh CI")
		}
	case base == "Podfile":
		if strings.Contains(text, "source 'https://cdn.cocoapods.org") {
			add("cocoapods", "podfile-public-source", "Podfile uses public CocoaPods CDN source")
		}
	case base == "Package.swift":
		if strings.Contains(text, ".package(url:") {
			add("swift", "package-swift-scm", "Package.swift has git-URL dependencies — run swift package --replace-scm-with-registry")
		}
	case base == "Dockerfile" || strings.HasPrefix(base, "Dockerfile."):
		for _, ln := range strings.Split(text, "\n") {
			t := strings.TrimSpace(ln)
			if strings.HasPrefix(strings.ToUpper(t), "FROM ") {
				// S5 — detection was case-insensitive but extraction was not:
				// two literal TrimPrefix calls only stripped "FROM " and
				// "from ", so `From ghcr.io/o/r:1` (valid Dockerfile syntax —
				// instructions are case-insensitive) left image == "From",
				// which classifies as a bare Docker Hub name and was waved
				// through. Verified: FROM→10, from→10, From→0.
				//
				// Splitting on fields makes panic-freedom STRUCTURAL rather
				// than an argument about the prefix guaranteeing a token: the
				// len check is the only thing indexing depends on.
				fields := strings.Fields(t)
				if len(fields) < 2 {
					continue
				}
				image := fields[1]
				if !dockerImageRoutesThroughChainsaw(image) {
					add("docker", "dockerfile-unprefixed-from", "FROM "+image+" — no Chainsaw host prefix, relies on daemon mirror")
				}
			}
		}
	}

	return out
}

// dockerImageRoutesThroughChainsaw recognises image refs that either
// (a) explicitly prefix the Chainsaw host, or (b) use Docker Hub
// (default) where the daemon `registry-mirrors` list could route the
// pull. Non-Hub public registries (quay.io, gcr.io, ghcr.io, etc.) are
// NOT covered by registry-mirrors and are always flagged.
func dockerImageRoutesThroughChainsaw(image string) bool {
	if strings.Contains(image, "chainsaw") {
		return true
	}
	// Non-Hub registries are identified by a dot or colon in the first
	// path segment. Those bypass mirrors.
	parts := strings.SplitN(image, "/", 2)
	if len(parts) > 1 {
		first := parts[0]
		if strings.ContainsAny(first, ".:") {
			return false
		}
	}
	// Bare `alpine`, `library/nginx`, etc. — Docker Hub, covered by
	// registry-mirrors if configured. Flag only if we can't tell whether
	// mirrors are configured; that's doctor's job, not scan-repo's.
	return true
}

func printScanReport(cmd *cobra.Command, r scanReport) {
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "scanned: %s\n", r.Root)
	if len(r.Findings) == 0 {
		// X2 — never say "no bypass files found" without qualifying it when
		// candidate files went uninspected.
		if len(r.Unreadable) > 0 {
			fmt.Fprintf(out, "no bypass files found in the files that could be inspected (%d skipped)\n", len(r.Unreadable))
			for _, f := range r.Unreadable {
				fmt.Fprintf(out, "  not inspected: %s\n", f)
			}
			return
		}
		fmt.Fprintln(out, "no bypass files found")
		return
	}
	fmt.Fprintf(out, "findings: %d\n\n", len(r.Findings))
	for _, f := range r.Findings {
		fmt.Fprintf(out, "%s [%s:%s]\n  %s\n", f.File, f.Category, f.Rule, f.Detail)
	}
	if len(r.Unreadable) > 0 {
		fmt.Fprintf(out, "\n%d candidate file(s) could not be inspected:\n", len(r.Unreadable))
		for _, f := range r.Unreadable {
			fmt.Fprintf(out, "  %s\n", f)
		}
	}
}
