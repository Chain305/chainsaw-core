package cli

// `chainsaw npm <args>` / `chainsaw go <args>` — the local-first install-path
// wrapper (T1). Run your package manager through Chainsaw and malicious /
// typosquatted packages are refused BEFORE they enter the build. Everything is
// evaluated locally (see guard_eval.go); nothing leaves the box on the default
// path.
//
//   $ chainsaw npm install lodahs        # blocked: typosquat of "lodash"
//   $ chainsaw npm install lodash        # clean: delegates to real `npm install lodash`
//   $ chainsaw go get github.com/x/y@v1  # evaluated, then real `go get`
//
// Flags are passed through untouched (DisableFlagParsing). Non-install
// subcommands (`npm run`, `go build`) just delegate.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/spf13/cobra"
)

var npmInstallActions = map[string]bool{"install": true, "i": true, "add": true, "ci": true}

var npmGuardCmd = &cobra.Command{
	Use:                "npm [args...]",
	Short:              "Run npm through Chainsaw — refuse malicious/typosquatted packages at install time",
	DisableFlagParsing: true,
	SilenceUsage:       true,
	SilenceErrors:      true,
	Args:               cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGuardedPassthrough("npm", args, parseNpmInstall)
	},
}

var goGuardCmd = &cobra.Command{
	Use:                "go [args...]",
	Short:              "Run go through Chainsaw — refuse malicious/typosquatted modules at `go get`",
	DisableFlagParsing: true,
	SilenceUsage:       true,
	SilenceErrors:      true,
	Args:               cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGuardedPassthrough("go", args, parseGoGet)
	},
}

var pipGuardCmd = &cobra.Command{
	Use:                "pip [args...]",
	Short:              "Run pip through Chainsaw — refuse malicious/typosquatted packages at install time",
	DisableFlagParsing: true,
	SilenceUsage:       true,
	SilenceErrors:      true,
	Args:               cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGuardedPassthrough("pip", args, parsePipInstall)
	},
}

var cargoGuardCmd = &cobra.Command{
	Use:                "cargo [args...]",
	Short:              "Run cargo through Chainsaw — refuse malicious/typosquatted crates at install time",
	DisableFlagParsing: true,
	SilenceUsage:       true,
	SilenceErrors:      true,
	Args:               cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGuardedPassthrough("cargo", args, parseCargoInstall)
	},
}

var gemGuardCmd = &cobra.Command{
	Use:                "gem [args...]",
	Short:              "Run gem through Chainsaw — refuse malicious/typosquatted gems at install time",
	DisableFlagParsing: true,
	SilenceUsage:       true,
	SilenceErrors:      true,
	Args:               cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGuardedPassthrough("gem", args, parseGemInstall)
	},
}

func init() {
	rootCmd.AddCommand(npmGuardCmd, goGuardCmd, pipGuardCmd, cargoGuardCmd, gemGuardCmd)
}

// pipValueFlags are pip flags that consume the following argument (so we don't
// mistake a requirements file or path for a package name).
var pipValueFlags = map[string]bool{
	"-r": true, "--requirement": true,
	"-c": true, "--constraint": true,
	"-e": true, "--editable": true,
}

// parsePipInstall recognizes `pip install [flags] <pkg>...` and returns the named
// package specs. Skips flags and their values (e.g. `-r requirements.txt`).
func parsePipInstall(args []string) ([]packageSpec, bool) {
	if len(args) == 0 || args[0] != "install" {
		return nil, false
	}
	var specs []packageSpec
	skipNext := false
	for _, a := range args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(a, "-") {
			if pipValueFlags[a] {
				skipNext = true
			}
			continue
		}
		specs = append(specs, parsePipSpec(a))
	}
	return specs, true
}

// parsePipSpec turns "requests", "requests==2.31.0", "requests>=2.0", or
// "requests[security]==2.31.0" into a spec. Version is captured only when pinned
// with "=="; looser specifiers leave it empty (name-based signals still fire).
func parsePipSpec(arg string) packageSpec {
	name, version := arg, ""
	if i := strings.IndexAny(name, "<>=!~"); i >= 0 {
		if rest := name[i:]; strings.HasPrefix(rest, "==") {
			version = strings.TrimLeft(rest, "=")
		}
		name = name[:i]
	}
	if b := strings.Index(name, "["); b >= 0 {
		name = name[:b] // drop extras: requests[security] -> requests
	}
	return packageSpec{Ecosystem: "pip", Name: strings.TrimSpace(name), Version: version}
}

// specParser extracts the packages a given invocation is asking to install.
// Returns (specs, recognized): recognized=false means this isn't an install
// command, so we delegate without evaluation.
type specParser func(args []string) (specs []packageSpec, recognized bool)

// runGuardedPassthrough is the wrapper core: parse → evaluate locally → block or
// delegate to the real binary.
func runGuardedPassthrough(bin string, args []string, parse specParser) error {
	specs, recognized := parse(args)
	if recognized && len(specs) == 0 {
		// No named packages (e.g. `npm install`/`npm ci` from a lockfile, or
		// `pip install -r requirements.txt`) — scan the resolved tree.
		if expanded := expandLockfile(bin, args); len(expanded) > 0 {
			specs = expanded
			fmt.Fprintf(os.Stderr, "chainsaw: scanning %d packages from lockfile\n", len(specs))
		}
	}
	if !recognized || len(specs) == 0 {
		return execPassthrough(bin, args)
	}

	guard := newLocalGuard()
	for _, n := range guard.notices {
		fmt.Fprintf(os.Stderr, "chainsaw: %s\n", n)
	}

	verdicts, blocked := guard.evaluateAll(context.Background(), specs)
	for _, v := range verdicts {
		switch {
		case v.Block:
			fmt.Fprintf(os.Stderr, "chainsaw: BLOCKED %s — %s\n", v.Spec, v.Reason)
		case v.Severity == "typosquat-medium":
			fmt.Fprintf(os.Stderr, "chainsaw: warning %s — %s (allowed; medium confidence)\n", v.Spec, v.Reason)
		}
	}

	if blocked {
		fmt.Fprintln(os.Stderr, "chainsaw: refused at install path. Nothing was installed.")
	}

	// D-NUDGE: disclosure + counters + telemetry (emitted AND flushed here,
	// before the os.Exit / passthrough branches that skip Execute()'s deferred
	// flush) + the chosen conversion nudge.
	processGuardOutcome(bin, verdicts, blocked)

	if blocked {
		os.Exit(1)
	}

	return execPassthrough(bin, args)
}

// parseNpmInstall recognizes `npm install|i|add [flags] <pkg>...` and returns the
// named package specs. Flags (anything starting with "-") are skipped.
func parseNpmInstall(args []string) ([]packageSpec, bool) {
	if len(args) == 0 || !npmInstallActions[args[0]] {
		return nil, false
	}
	var specs []packageSpec
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		specs = append(specs, parseNpmSpec(a))
	}
	return specs, true
}

// parseNpmSpec turns "lodash", "lodash@4.17.21", or "@babel/core@7.24.0" into a
// spec. The version is whatever follows the last "@" that isn't the leading
// scope marker.
func parseNpmSpec(arg string) packageSpec {
	name, version := arg, ""
	if at := strings.LastIndex(arg, "@"); at > 0 {
		name, version = arg[:at], arg[at+1:]
	}
	return packageSpec{Ecosystem: "npm", Name: name, Version: version}
}

// parseGoGet recognizes `go get [flags] <module>...` (named modules) and
// `go mod download` (no named modules → triggers go.sum lockfile scan).
func parseGoGet(args []string) ([]packageSpec, bool) {
	// `go mod download` — recognized with no specs so expandLockfile scans go.sum.
	if len(args) >= 2 && args[0] == "mod" && args[1] == "download" {
		return nil, true
	}
	if len(args) == 0 || args[0] != "get" {
		return nil, false
	}
	var specs []packageSpec
	for _, a := range args[1:] {
		if strings.HasPrefix(a, "-") {
			continue
		}
		name, version := a, ""
		if at := strings.LastIndex(a, "@"); at > 0 {
			name, version = a[:at], a[at+1:]
		}
		specs = append(specs, packageSpec{Ecosystem: "go", Name: name, Version: version})
	}
	return specs, true
}

// cargoInstallActions are the cargo subcommands that fetch named crates.
var cargoInstallActions = map[string]bool{"add": true, "install": true}

// parseCargoInstall recognizes `cargo add <crate>...` and `cargo install <crate>...`
// and returns the named crate specs. Flags are skipped; `--version X` consumes its
// value so it isn't treated as a crate name. Bare `cargo build`/`cargo add` (no
// crates) is recognized with no specs so expandLockfile scans Cargo.lock.
func parseCargoInstall(args []string) ([]packageSpec, bool) {
	if len(args) == 0 || !cargoInstallActions[args[0]] {
		return nil, false
	}
	var specs []packageSpec
	pendingVersion := "" // crate awaiting a `--version X` value
	skipNext := false
	for _, a := range args[1:] {
		if skipNext {
			skipNext = false
			// A `--version X` value applies to the most recent crate.
			if pendingVersion != "" {
				for i := range specs {
					if specs[i].Name == pendingVersion {
						specs[i].Version = a
					}
				}
				pendingVersion = ""
			}
			continue
		}
		if strings.HasPrefix(a, "-") {
			if a == "--version" || a == "--vers" {
				skipNext = true
				if len(specs) > 0 {
					pendingVersion = specs[len(specs)-1].Name
				}
			}
			continue
		}
		specs = append(specs, parseCargoSpec(a))
	}
	return specs, true
}

// parseCargoSpec turns "serde" or "serde@1.0.0" into a spec.
func parseCargoSpec(arg string) packageSpec {
	name, version := arg, ""
	if at := strings.LastIndex(arg, "@"); at > 0 {
		name, version = arg[:at], arg[at+1:]
	}
	return packageSpec{Ecosystem: "cargo", Name: strings.TrimSpace(name), Version: version}
}

// gemValueFlags are `gem install` flags that consume the following argument.
var gemValueFlags = map[string]bool{"-v": true, "--version": true}

// parseGemInstall recognizes `gem install <gem>...` and returns the named gem
// specs. A `-v X` / `--version X` flag pins the version of the gems named on the
// same line; a `name:version` form is also honored.
func parseGemInstall(args []string) ([]packageSpec, bool) {
	if len(args) == 0 || (args[0] != "install" && args[0] != "i") {
		return nil, false
	}
	var specs []packageSpec
	version := ""
	skipNext := false
	for _, a := range args[1:] {
		if skipNext {
			skipNext = false
			version = a
			continue
		}
		if strings.HasPrefix(a, "-") {
			if gemValueFlags[a] {
				skipNext = true
			}
			continue
		}
		specs = append(specs, parseGemSpec(a))
	}
	// Apply a trailing `-v X` to specs that didn't carry their own version.
	if version != "" {
		for i := range specs {
			if specs[i].Version == "" {
				specs[i].Version = version
			}
		}
	}
	return specs, true
}

// parseGemSpec turns "rails" or "rails:7.1.0" into a spec.
func parseGemSpec(arg string) packageSpec {
	name, version := arg, ""
	if c := strings.LastIndex(arg, ":"); c > 0 {
		name, version = arg[:c], arg[c+1:]
	}
	return packageSpec{Ecosystem: "rubygems", Name: strings.TrimSpace(name), Version: version}
}

// expandLockfile resolves a no-named-package install into the full set of
// pinned dependencies, reusing the pr-scan lockfile parsers. Offline (reads
// files in the cwd / the requirements path).
//   - npm install | npm ci  → package-lock.json / npm-shrinkwrap.json / pnpm-lock.yaml / yarn.lock
//   - pip install -r FILE    → the requirements file(s)
//   - go get | go mod download → go.sum
func expandLockfile(bin string, args []string) []packageSpec {
	switch bin {
	case "npm":
		if len(args) == 0 || !npmInstallActions[args[0]] {
			return nil
		}
		// package-lock.json / npm-shrinkwrap.json (v2/v3, error-returning parser).
		for _, f := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
			if data, err := os.ReadFile(f); err == nil {
				if deps, perr := parsePackageLockJSON(data); perr == nil && len(deps) > 0 {
					return depsToSpecs("npm", deps)
				}
			}
		}
		// pnpm / yarn (single-return parsers).
		if data, err := os.ReadFile("pnpm-lock.yaml"); err == nil {
			if deps := parsePNPMLock(data); len(deps) > 0 {
				return depsToSpecs("npm", deps)
			}
		}
		if data, err := os.ReadFile("yarn.lock"); err == nil {
			if deps := parseYarnLock(data); len(deps) > 0 {
				return depsToSpecs("npm", deps)
			}
		}
	case "go":
		// `go get` (no module) / `go mod download` → scan the resolved go.sum.
		if data, err := os.ReadFile("go.sum"); err == nil {
			if deps := parseGoSum(data); len(deps) > 0 {
				return depsToSpecs("go", deps)
			}
		}
	case "cargo":
		// `cargo add`/`cargo install`/`cargo build` (no named crate) → scan Cargo.lock.
		if data, err := os.ReadFile("Cargo.lock"); err == nil {
			if deps := parseCargoLock(data); len(deps) > 0 {
				return depsToSpecs("cargo", deps)
			}
		}
	case "gem":
		// `gem install` from a Gemfile.lock (bundler-resolved tree).
		if data, err := os.ReadFile("Gemfile.lock"); err == nil {
			if deps := parseGemfileLock(data); len(deps) > 0 {
				return depsToSpecs("rubygems", deps)
			}
		}
	case "pip":
		if len(args) == 0 || args[0] != "install" {
			return nil
		}
		var specs []packageSpec
		for i := 0; i < len(args); i++ {
			if args[i] != "-r" && args[i] != "--requirement" {
				continue
			}
			if i+1 >= len(args) {
				break
			}
			if data, err := os.ReadFile(args[i+1]); err == nil {
				specs = append(specs, parseRequirementsLines(data)...)
			}
			i++
		}
		return specs
	}
	return nil
}

// parseRequirementsLines parses a requirements.txt into specs, capturing BOTH
// pinned and UNPINNED packages (the shared pr-scan parser drops unpinned ones, but
// an unpinned malicious name must still be caught). Reuses parsePipSpec for the
// name/version/extras handling; skips blanks, comments, and option lines (-r, -e).
func parseRequirementsLines(data []byte) []packageSpec {
	var specs []packageSpec
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}
		// Drop inline comments and environment markers ("pkg ; python_version<'3'").
		if i := strings.IndexAny(line, " \t;#"); i > 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			specs = append(specs, parsePipSpec(line))
		}
	}
	return specs
}

// depsToSpecs converts a name→version map (from a lockfile parser) into specs.
func depsToSpecs(ecosystem string, deps map[string]string) []packageSpec {
	specs := make([]packageSpec, 0, len(deps))
	for name, version := range deps {
		specs = append(specs, packageSpec{Ecosystem: ecosystem, Name: name, Version: version})
	}
	return specs
}

// execPassthrough runs the real package manager with the original args, wiring
// through stdio and propagating its exit code.
func execPassthrough(bin string, args []string) error {
	path, err := exec.LookPath(bin)
	if err != nil {
		return fmt.Errorf("%s not found on PATH: %w", bin, err)
	}
	c := exec.Command(path, args...)
	c.Stdin, c.Stdout, c.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		return err
	}
	return nil
}
