// Package mod parses go.mod.
//
// Manifest, but Go's go.mod already carries fully-resolved module
// versions (no ranges), so treating it as a lock file is accurate. The
// companion go.sum (see ../sum) adds transitives + build-time deps
// pulled in by test-only packages; go.mod itself only names direct
// requires.
//
// `replace` directives decide what a require actually builds
// (docs/PLANS_INTELLIGENCE.md#plan-non-registry-sources §3.4):
//
//   - `replace a [vA] => b vB`: the build uses module b at vB, so the
//     package is b@vB. Go has no registry: a module path that names a VCS
//     host directly (github.com/cockroachdb/gogoproto) is as public as any
//     other, served by proxy.golang.org, so a re-keyed module carries no
//     Origin.
//   - `replace a [vA] => ../dir`: the build uses a local directory, so the
//     package keeps a's path and required version and carries the directory
//     as Origin ("file:../dir"). It used to be scored as the module a@vA —
//     usually the never-published v0.0.0 (kubernetes' 32 staging modules).
//
// A version-specific replace wins over a wildcard one for the same module,
// as in the go command.
package mod

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/chain305/chainsaw-core/depparser/origin"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

func Parse(r io.Reader) ([]ftypes.Package, error) {
	data, err := io.ReadAll(io.LimitReader(r, 16<<20))
	if err != nil {
		return nil, err
	}
	// Parse, not ParseLax: ParseLax drops replace directives (it is for
	// dependencies' go.mod files, where the go command ignores them).
	f, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		// A directive newer than golang.org/x/mod fails the strict parse.
		// ParseLax reads the rest but DROPS every replace, which would score
		// each fork and local directory as the upstream module; so the
		// replace lines are re-parsed strictly on their own, and a file
		// whose replaces do not parse is refused rather than read without
		// them. Bump x/mod when Go adds a directive.
		lax, lerr := modfile.ParseLax("go.mod", data, nil)
		if lerr != nil {
			return nil, lerr
		}
		reps, rerr := replaces(lax)
		if rerr != nil {
			return nil, fmt.Errorf("%w (replace directives unreadable: %v)", err, rerr)
		}
		f, lax.Replace = lax, reps
	}
	type key struct{ path, version string }
	repl := map[key]modfile.Replace{}
	for _, rp := range f.Replace {
		repl[key{rp.Old.Path, rp.Old.Version}] = *rp
	}
	var out []ftypes.Package
	for _, req := range f.Require {
		pkg := ftypes.Package{Name: req.Mod.Path, Version: normaliseVersion(req.Mod.Version)}
		rp, ok := repl[key{req.Mod.Path, req.Mod.Version}]
		if !ok {
			rp, ok = repl[key{req.Mod.Path, ""}]
		}
		switch {
		case !ok:
		case rp.New.Version == "":
			// A replacement without a version is a filesystem path (the go
			// command accepts nothing else there).
			pkg.Origin = origin.Sanitize("file:" + rp.New.Path)
		default:
			pkg.Name, pkg.Version = rp.New.Path, normaliseVersion(rp.New.Version)
		}
		out = append(out, pkg)
	}
	return out, nil
}

// replaces parses the replace directives of a file read with ParseLax,
// which keeps them in the syntax tree but not in File.Replace: each is
// written back out as a replace line of a minimal go.mod and parsed strictly.
func replaces(f *modfile.File) ([]*modfile.Replace, error) {
	var b strings.Builder
	b.WriteString("module m\n")
	for _, st := range f.Syntax.Stmt {
		switch x := st.(type) {
		case *modfile.Line:
			if len(x.Token) > 0 && x.Token[0] == "replace" {
				b.WriteString(strings.Join(x.Token, " ") + "\n")
			}
		case *modfile.LineBlock:
			if len(x.Token) == 1 && x.Token[0] == "replace" {
				for _, l := range x.Line {
					b.WriteString("replace " + strings.Join(l.Token, " ") + "\n")
				}
			}
		}
	}
	rf, err := modfile.Parse("go.mod", []byte(b.String()), nil)
	if err != nil {
		return nil, err
	}
	return rf.Replace, nil
}

// normaliseVersion strips the leading "v" from a Go module version so this
// parser agrees byte-for-byte with its go.sum sibling (../sum, which has
// always stripped it) and with Trivy.
//
// Why this matters: a directory holding BOTH go.mod and go.sum used to emit
// every module twice — once "1.6.0" from go.sum, once "v1.6.0" from go.mod —
// and the scan dedup key compares raw version strings, so the pair never
// collapsed (650 rows for 419 distinct coordinates on this repo's own files).
//
// The stripped spelling is NOT resolvable against the Go module proxy, whose
// protocol requires the "v". Consumers that build proxy URLs re-add it — see
// core/intelligence/provider_registrymetadata.go (goProxyVersion) and
// core/depparser/dependency/id.go (ID).
func normaliseVersion(v string) string {
	return strings.TrimPrefix(v, "v")
}
