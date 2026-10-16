package cli

import (
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/chain305/chainsaw-core/depparser/origin"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

// npmLockSplit splits a JavaScript lockfile's packages, as the server's
// parsers read them (core/depparser: npm, yarn, pnpm, bun), into registry
// coordinates and packages from outside the public registry — the same rule
// the install guard applies to a registry given on the command line
// (docs/PLANS_INTELLIGENCE.md#plan-non-registry-sources):
//
//   - no Origin: the public registry.
//   - a registry-shaped URL on another host (origin.RegistryOther) that
//     knownRegistry vouches for — a registry_mirrors host or the user's own
//     Chainsaw repository: the registry. The CLI holds no registry digests,
//     so it cannot make the server's content-hash decision; it takes the
//     user's declaration instead.
//   - any other RegistryOther: Origin "registry+<url>", so the guard says
//     "not assessed" with the registry_mirrors hint and prints the host only
//     (a private registry may carry a token in the path).
//   - git, a URL tarball, local code ("file:<path>"): Origin as recorded.
//
// Registry coordinates carry the lockfile's hash back as an SRI string, the
// guard's byte anchor (packageSpec.Integrity). Order is kept and nothing is
// deduplicated: callers collapse duplicates by their own rules.
func npmLockSplit(pkgs []ftypes.Package) (registry []lockCoordinate, nonRegistry []nonRegistryDep) {
	for _, p := range pkgs {
		if p.Name == "" {
			continue
		}
		switch o := p.Origin; {
		case npmOriginIsRegistry(o):
			if p.Version != "" {
				registry = append(registry, lockCoordinate{Name: p.Name, Version: p.Version, Integrity: hashToSRI(p.Hash)})
			}
		case origin.Classify("npm", o) == origin.RegistryOther:
			nonRegistry = append(nonRegistry, nonRegistryDep{Name: p.Name, Version: p.Version, Origin: "registry+" + o})
		default:
			nonRegistry = append(nonRegistry, nonRegistryDep{Name: p.Name, Version: p.Version, Origin: o})
		}
	}
	return registry, nonRegistry
}

// npmOriginIsRegistry is npmLockSplit's per-package rule: a recorded npm
// source the CLI treats as the registry — none, a public alias, or a
// registry-shaped URL on a host knownRegistry vouches for.
func npmOriginIsRegistry(o string) bool {
	if o == "" {
		return true
	}
	c := origin.Classify("npm", o)
	return c == origin.Public || (c == origin.RegistryOther && knownRegistry("npm", o))
}

// npmLockSpecs turns npmLockSplit's output into guard specs. Local code
// ("file:<path>": a workspace member, a link, a file: dependency) becomes a
// Local spec — the known-malicious lookup only, silent otherwise, like a
// sourceless Cargo crate — so `npm ci` in a monorepo does not print a "not
// assessed" line per workspace package.
func npmLockSpecs(registry []lockCoordinate, nonRegistry []nonRegistryDep) []packageSpec {
	specs := coordsToSpecs("npm", registry)
	for _, d := range nonRegistry {
		if localCode(d.Origin) {
			if d.Version != "" {
				specs = append(specs, packageSpec{Ecosystem: "npm", Name: d.Name, Version: d.Version, Local: true})
			}
			continue
		}
		specs = append(specs, packageSpec{Ecosystem: "npm", Name: d.Name, Version: d.Version, Origin: d.Origin})
	}
	return specs
}

// npmNonLocal drops local code ("file:<path>") from npmLockSplit's
// non-registry list, for pr-scan: a workspace package is first-party, no
// row, as a sourceless Cargo crate is none.
func npmNonLocal(deps []nonRegistryDep) []nonRegistryDep {
	out := deps[:0:0]
	for _, d := range deps {
		if !localCode(d.Origin) {
			out = append(out, d)
		}
	}
	return out
}

// hashToSRI turns a lockfile Hash — one canonical hash ("sha512:<hex>") or
// several (origin.JoinHashes) — back into an SRI string, one
// "<algo>-<base64>" token per hash, space-separated: the guard verifies it
// as npm's ssri does (any token of the strongest algorithm). "" if no token
// converts, and "" — no anchor — when any token is unreadable
// (origin.UnreadableHash: sha224, md5…): npm verifies the strongest
// algorithm, which may be exactly that one, so an anchor built from the
// rest would vouch for bytes npm never checked.
func hashToSRI(h string) string {
	var toks []string
	for _, t := range origin.SplitHashes(h) {
		if origin.IsUnreadableHash(t) {
			return ""
		}
		algo, hx, _ := strings.Cut(t, ":")
		if raw, err := hex.DecodeString(hx); err == nil && len(raw) > 0 {
			toks = append(toks, algo+"-"+base64.StdEncoding.EncodeToString(raw))
		}
	}
	return strings.Join(toks, " ")
}
