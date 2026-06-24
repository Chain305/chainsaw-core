package cli

// `chainsaw scan-repo` walks a repo tree and flags files that bypass
// Chainsaw: committed `.npmrc` registries, `--index-url` lines in
// requirements.txt, Maven `<repository>` blocks in pom.xml, NuGet
// sources in nuget.config, Docker images without the Chainsaw host
// prefix, etc. Intended to run in CI as a required status check so
// bypasses are caught at PR time rather than after the fact.
//
// Exit code: 0 clean, 10 bypass files found. Same matrix as
// `doctor --strict` so a single CI step that combines both gets a
// predictable non-zero on either signal.
//
// This is a pragmatic grep — a full Gradle / Maven AST parser is out
// of scope. False positives are surfaced as suggestions ("committed
// .npmrc — ensure registry is Chainsaw-pointed") rather than hard
// fails when the file looks benign.

import (
	"encoding/json"
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
	Root     string        `json:"root"`
	Findings []scanFinding `json:"findings"`
}

func init() {
	cmd := &cobra.Command{
		Use:   "scan-repo [path]",
		Short: "Scan a repo tree for Chainsaw-bypass config files",
		Long: `Walks the given directory (default: current) and flags files that can
route package traffic around Chainsaw: committed .npmrc / .yarnrc.yml /
.bunfig.toml registries, pip/poetry index-url, Maven <repository>, NuGet
packageSources, Cargo [source.*] replace-with entries, GOPROXY overrides,
Dockerfile images without the Chainsaw prefix, CocoaPods non-Chainsaw
sources, SPM .package(url:) direct dependencies.

Exits 10 if any bypass is found; 0 when the tree is clean. Intended for
CI preflight ("required status check").`,
		RunE: runScanRepo,
	}
	cmd.Flags().Bool("json", false, "emit JSON output")
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
	report := scanReport{Root: abs}

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

		data, rerr := os.ReadFile(path)
		if rerr != nil {
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

	if useJSON(cmd) {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		_ = enc.Encode(report)
	} else {
		printScanReport(cmd, report)
	}

	if len(report.Findings) > 0 {
		os.Exit(doctorExitDrift)
	}
	return nil
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
				image := strings.TrimPrefix(t, "FROM ")
				image = strings.TrimPrefix(image, "from ")
				image = strings.Fields(image)[0]
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
		fmt.Fprintln(out, "no bypass files found")
		return
	}
	fmt.Fprintf(out, "findings: %d\n\n", len(r.Findings))
	for _, f := range r.Findings {
		fmt.Fprintf(out, "%s [%s:%s]\n  %s\n", f.File, f.Category, f.Rule, f.Detail)
	}
}
