// Package analyzer is chainsaw's (non-vendored) plug point for dependency
// parsers. It mirrors the shape of Trivy's analyzer registry — each
// ecosystem registers an Analyzer via init(), and a recursive WalkDir
// dispatches each file to every Analyzer whose Required() matches.
//
// This is the ONE package in internal/depparser/ that is *not* vendored
// from Trivy. It adapts Trivy's per-parser package into chainsaw's
// collectFromManifests contract (returning []scanPkg-style name/version
// tuples, which the caller then hands to the vuln scanner).
//
// Design constraints:
//
//   - Analyzers are registered at init() time. No plugin discovery, no
//     dynamic loading — a new language is added by dropping a file in this
//     package and calling Register() in init().
//
//   - Required(path) is the ONLY language-detection hook. It sees the full
//     path so it can match exact names (poetry.lock), suffixes
//     (.gradle.lockfile), or regex patterns (pylock.{id}.toml).
//
//   - Parse() takes an xio.ReadSeekerAt — matching Trivy's parser signature
//     so vendored parsers plug in without an adapter layer.
//
//   - WalkDir skips the usual heavy directories (vendor, node_modules,
//     .venv, etc.) to keep a monorepo scan fast. The skip set mirrors
//     Trivy's "excludedDirs" in pkg/fanal/walker.
package analyzer

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

// Package is the minimal name+version tuple surfaced to the scan command.
// Chainsaw's scan.go uses a local scanPkg type with the same shape; we
// intentionally keep this symbol distinct so the depparser tree can be
// imported without circular deps.
type Package struct {
	Name    string
	Version string
	Lang    ftypes.LangType
	Source  string // file path the package was parsed from (for diagnostics)
}

// Analyzer is the interface every language parser satisfies. Kept small
// on purpose — Trivy's richer analyzer.Analyzer interface adds options
// for layer/image/FS context which chainsaw's filesystem-only scan does
// not need at this stage.
type Analyzer interface {
	// Type returns the ecosystem LangType this analyzer emits. Used only
	// for diagnostics and for Package.Lang; does not affect dispatch.
	Type() ftypes.LangType

	// Required returns true if a file at path should be parsed by this
	// analyzer. Called once per file during WalkDir. Must be cheap.
	Required(path string) bool

	// Parse opens and parses one file. The caller (WalkDir) provides the
	// absolute path so Parse can os.Open it; taking a path (rather than
	// an already-open file) lets each analyzer choose whether it needs
	// a full io.ReadSeekerAt or just a streaming io.Reader.
	Parse(ctx context.Context, path string) ([]Package, error)
}

var (
	mu         sync.RWMutex
	registered []Analyzer
)

// Register adds an analyzer to the global registry. Called from init()
// in each analyzer file. Duplicate LangTypes are allowed — one ecosystem
// can have multiple lockfile formats (e.g. NuGet's packages.lock.json +
// packages.config, npm's package-lock.json + shrinkwrap). Uniqueness is
// enforced per-(LangType, Required-pattern) at dispatch time by the
// caller, not here.
func Register(a Analyzer) {
	mu.Lock()
	defer mu.Unlock()
	registered = append(registered, a)
}

// All returns a snapshot of the registered analyzers. Callers may range
// over the result freely; the slice is not shared with the registry.
func All() []Analyzer {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]Analyzer, len(registered))
	copy(out, registered)
	return out
}

// skipDirs is the fixed list of directory names WalkDir will not descend
// into. Matches Trivy's pkg/fanal/walker excluded set plus common
// monorepo build-output dirs. Callers that want a different set can
// bypass WalkDir and drive dispatch themselves.
var skipDirs = map[string]struct{}{
	".git":          {},
	".hg":           {},
	".svn":          {},
	"node_modules":  {},
	"vendor":        {},
	".venv":         {},
	"venv":          {},
	"__pycache__":   {},
	".mypy_cache":   {},
	".pytest_cache": {},
	".tox":          {},
	"target":        {}, // rust/java build output
	"build":         {},
	"dist":          {},
	".gradle":       {},
	".idea":         {},
	".vscode":       {},
}

// WalkDir traverses root depth-first, calling every registered analyzer's
// Required() for each regular file. When an analyzer matches, its Parse()
// is invoked and the returned packages are appended to the aggregate
// result. Parse errors for a single file are returned joined — one bad
// lockfile does not abort the walk.
func WalkDir(ctx context.Context, root string) ([]Package, error) {
	analyzers := All()
	if len(analyzers) == 0 {
		return nil, nil
	}

	var (
		all      []Package
		walkErrs []error
	)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			// Unreadable dir — record and continue.
			walkErrs = append(walkErrs, fmt.Errorf("%s: %w", path, walkErr))
			if d != nil && d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if _, skip := skipDirs[d.Name()]; skip && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		// Only regular files dispatch to analyzers. Symlinks, sockets,
		// devices etc. are skipped.
		if !d.Type().IsRegular() {
			return nil
		}
		for _, a := range analyzers {
			if !a.Required(path) {
				continue
			}
			pkgs, perr := a.Parse(ctx, path)
			if perr != nil {
				walkErrs = append(walkErrs, fmt.Errorf("%s: parse: %w", path, perr))
				continue
			}
			all = append(all, pkgs...)
		}
		return nil
	})
	if err != nil {
		walkErrs = append(walkErrs, err)
	}

	// Stable output ordering (walk order is OS-dependent).
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Name != all[j].Name {
			return all[i].Name < all[j].Name
		}
		return all[i].Version < all[j].Version
	})

	if len(walkErrs) > 0 {
		return all, errorJoin(walkErrs)
	}
	return all, nil
}

// errorJoin builds a single error that lists all child errors. Kept local
// to avoid depending on Go 1.20's errors.Join in case downstream tooling
// hasn't upgraded; go.mod declares go 1.25.4 so this could be replaced
// with errors.Join, but the explicit string keeps diagnostic output tidy.
func errorJoin(errs []error) error {
	if len(errs) == 1 {
		return errs[0]
	}
	msg := fmt.Sprintf("%d errors during depparser walk:\n", len(errs))
	for _, e := range errs {
		msg += "  - " + e.Error() + "\n"
	}
	return fmt.Errorf("%s", msg)
}

// readFile is a small helper for analyzers that want an *os.File typed
// as xio.ReadSeekerAt without reimplementing the open-and-close dance.
// Defined here rather than in xio/ so the xio package stays a pure
// interface declaration (matching Trivy's layout).
func readFile(path string) (*os.File, error) { return os.Open(path) }
