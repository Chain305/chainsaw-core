// Analyzer shims — one struct per registered ecosystem. Each implements
// the Analyzer interface (Type / Required / Parse) as a thin adapter
// between chainsaw's filesystem walk and the per-parser package under
// internal/depparser/parser/**.
//
// The shape is identical for every shim: open the file, call the parser,
// convert ftypes.Package → analyzer.Package, filter dev deps. Kept in
// one file so adding a new ecosystem is a 3-line change (import, struct,
// init() line) rather than a new file.
//
// Each shim's Required() mirrors Trivy's detection rule for that format
// (exact match, suffix, or PEP-751-style regex).

package analyzer

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	ftypes "github.com/chain305/chainsaw-core/fanal"

	bun "github.com/chain305/chainsaw-core/depparser/parser/nodejs/bun"
	npm "github.com/chain305/chainsaw-core/depparser/parser/nodejs/npm"
	pnpm "github.com/chain305/chainsaw-core/depparser/parser/nodejs/pnpm"
	yarn "github.com/chain305/chainsaw-core/depparser/parser/nodejs/yarn"

	pipenv "github.com/chain305/chainsaw-core/depparser/parser/python/pipenv"
	pylock "github.com/chain305/chainsaw-core/depparser/parser/python/pylock"
	uvpkg "github.com/chain305/chainsaw-core/depparser/parser/python/uv"

	gosum "github.com/chain305/chainsaw-core/depparser/parser/golang/sum"
	composer "github.com/chain305/chainsaw-core/depparser/parser/php/composer"
	bundler "github.com/chain305/chainsaw-core/depparser/parser/ruby/bundler"
	cargo "github.com/chain305/chainsaw-core/depparser/parser/rust/cargo"

	gradlelock "github.com/chain305/chainsaw-core/depparser/parser/gradle/lockfile"
	sbtlock "github.com/chain305/chainsaw-core/depparser/parser/sbt/lockfile"

	nugetconfig "github.com/chain305/chainsaw-core/depparser/parser/nuget/config"
	nugetlock "github.com/chain305/chainsaw-core/depparser/parser/nuget/lock"

	conanpkg "github.com/chain305/chainsaw-core/depparser/parser/c/conan"
	condapkg "github.com/chain305/chainsaw-core/depparser/parser/conda/env"
	pubpkg "github.com/chain305/chainsaw-core/depparser/parser/dart/pub"
	mixpkg "github.com/chain305/chainsaw-core/depparser/parser/hex/mix"
	juliapkg "github.com/chain305/chainsaw-core/depparser/parser/julia/manifest"
	cocoapodspkg "github.com/chain305/chainsaw-core/depparser/parser/swift/cocoapods"
	resolvedpkg "github.com/chain305/chainsaw-core/depparser/parser/swift/resolved"

	// Manifest parsers — ported out of internal/cli/scan.go's former
	// hardcoded switch when the registry took ownership of discovery.
	// Kept alongside their lockfile peers so a walk of a monorepo picks
	// up manifest (direct deps) + lockfile (transitives) in one pass.
	gomod "github.com/chain305/chainsaw-core/depparser/parser/golang/mod"
	pompkg "github.com/chain305/chainsaw-core/depparser/parser/java/pom"
	packagejson "github.com/chain305/chainsaw-core/depparser/parser/nodejs/packagejson"
	requirements "github.com/chain305/chainsaw-core/depparser/parser/python/requirements"
	cargomanifest "github.com/chain305/chainsaw-core/depparser/parser/rust/cargomanifest"
)

// parseFn is the uniform signature every parser exposes.
type parseFn = func(io.Reader) ([]ftypes.Package, error)

// shim wraps a (LangType, matcher, parser) triple into an Analyzer.
type shim struct {
	langType ftypes.LangType
	match    func(path string) bool
	parser   parseFn
}

func (s shim) Type() ftypes.LangType     { return s.langType }
func (s shim) Required(path string) bool { return s.match(path) }
func (s shim) Parse(_ context.Context, path string) ([]Package, error) {
	f, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	defer f.Close()
	fpkgs, err := s.parser(f)
	if err != nil {
		return nil, err
	}
	out := make([]Package, 0, len(fpkgs))
	for _, fp := range fpkgs {
		if fp.Dev || fp.Name == "" || fp.Version == "" {
			continue
		}
		out = append(out, Package{
			Name:    fp.Name,
			Version: fp.Version,
			Lang:    s.langType,
			Source:  path,
		})
	}
	return out, nil
}

// exact returns a Required-matcher for an exact basename match.
func exact(basename string) func(string) bool {
	return func(path string) bool { return filepath.Base(path) == basename }
}

// suffix returns a matcher for any path ending in the given suffix.
func suffix(s string) func(string) bool {
	return func(path string) bool { return strings.HasSuffix(path, s) }
}

// pylockRe is the PEP 751 filename pattern: pylock.toml or
// pylock.{identifier}.toml where identifier has no dots.
var pylockRe = regexp.MustCompile(`^pylock(?:\.[A-Za-z0-9_-]+)?\.toml$`)

func pylockMatch(path string) bool {
	return pylockRe.MatchString(filepath.Base(path))
}

// init registers every shim. Order does not matter — WalkDir dispatches
// each file to every analyzer whose Required() matches.
func init() {
	// Python
	Register(shim{ftypes.Pipenv, exact("Pipfile.lock"), pipenv.Parse})
	Register(shim{ftypes.Uv, exact("uv.lock"), uvpkg.Parse})
	Register(shim{ftypes.PyLock, pylockMatch, pylock.Parse})

	// Node
	Register(shim{ftypes.Npm, exact("package-lock.json"), npm.Parse})
	Register(shim{ftypes.Yarn, exact("yarn.lock"), yarn.Parse})
	Register(shim{ftypes.Pnpm, exact("pnpm-lock.yaml"), pnpm.Parse})
	Register(shim{ftypes.Bun, exact("bun.lock"), bun.Parse})

	// Ruby / PHP / Rust / Go
	Register(shim{ftypes.Bundler, exact("Gemfile.lock"), bundler.Parse})
	Register(shim{ftypes.Composer, exact("composer.lock"), composer.Parse})
	Register(shim{ftypes.Cargo, exact("Cargo.lock"), cargo.Parse})
	Register(shim{ftypes.GoModule, exact("go.sum"), gosum.Parse})

	// JVM
	Register(shim{ftypes.Gradle, suffix("gradle.lockfile"), gradlelock.Parse})
	Register(shim{ftypes.Sbt, exact("build.sbt.lock"), sbtlock.Parse})

	// .NET
	Register(shim{ftypes.NuGet, exact("packages.lock.json"), nugetlock.Parse})
	Register(shim{ftypes.NuGet, exact("packages.config"), nugetconfig.Parse})

	// Misc
	Register(shim{ftypes.Conan, exact("conan.lock"), conanpkg.Parse})
	Register(shim{ftypes.Hex, exact("mix.lock"), mixpkg.Parse})
	Register(shim{ftypes.Pub, exact("pubspec.lock"), pubpkg.Parse})
	Register(shim{ftypes.Swift, exact("Package.resolved"), resolvedpkg.Parse})
	Register(shim{ftypes.Cocoapods, exact("Podfile.lock"), cocoapodspkg.Parse})
	Register(shim{ftypes.Julia, exact("Manifest.toml"), juliapkg.Parse})
	Register(shim{ftypes.CondaEnv, condaEnvMatch, condapkg.Parse})

	// Manifest parsers — direct-dep sources, no transitive graph.
	// Registered under the same LangType as their lockfile siblings so
	// downstream detector drivers don't need to distinguish them.
	Register(shim{ftypes.Npm, exact("package.json"), packagejson.Parse})
	Register(shim{ftypes.Pip, exact("requirements.txt"), requirements.Parse})
	Register(shim{ftypes.GoModule, exact("go.mod"), gomod.Parse})
	Register(shim{ftypes.Pom, exact("pom.xml"), pompkg.Parse})
	Register(shim{ftypes.Cargo, exact("Cargo.toml"), cargomanifest.Parse})
}

// condaEnvMatch: Conda environment files are conventionally
// `environment.yml` or `environment.yaml`, sometimes with a prefix
// (e.g. `environment-dev.yml`). Match either extension with an optional
// suffix after "environment".
func condaEnvMatch(path string) bool {
	base := filepath.Base(path)
	if !strings.HasPrefix(base, "environment") {
		return false
	}
	return strings.HasSuffix(base, ".yml") || strings.HasSuffix(base, ".yaml")
}
