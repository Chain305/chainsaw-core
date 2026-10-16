package pnpm

import (
	"strings"
	"testing"
)

// Red-team round 2.

// TestPublicTarballSwap: a registry tarball in resolution.tarball names the
// package fetched (re-keyed: the evil swap is evil@1.0.0); with a `path` it
// is a monorepo tarball, and a public URL that is not a tarball path, both
// "url+<url>" (non-registry). Break it like this: set Origin with
// nodesource.Origin (Classify alone).
func TestPublicTarballSwap(t *testing.T) {
	src := `lockfileVersion: '9.0'
packages:
  lodash@4.17.21:
    resolution: {integrity: ` + sriA + `, tarball: https://registry.npmjs.org/evil/-/evil-1.0.0.tgz}
  chalk@4.1.2:
    resolution: {integrity: ` + sriA + `, tarball: https://registry.npmjs.org/chalk/-/chalk-4.1.2.tgz}
  '@babel/core@7.22.0':
    resolution: {tarball: 'https://registry.npmjs.org/@babel/core/-/core-7.22.0.tgz'}
  debug@4.3.4:
    resolution: {tarball: https://registry.npmjs.org/debug/-/debug-4.3.4.tgz, path: sub}
  bare@1.0.0:
    resolution: {integrity: ` + sriA + `, tarball: https://registry.npmjs.org/bare}
`
	check(t, got(t, src), []string{
		"evil@1.0.0 origin= hash=" + hashA,
		"bare@1.0.0 origin=url+https://registry.npmjs.org/bare hash=",
		"chalk@4.1.2 origin= hash=" + hashA,
		"@babel/core@7.22.0 origin= hash=",
		"debug@4.3.4 origin=url+https://registry.npmjs.org/debug/-/debug-4.3.4.tgz#path:sub hash=",
	})
}

// TestPartialDecode (finding E): scalars of any type decode as strings, and
// an entry that does not decode is an error returned with every other
// entry. Break it like this: return nil on a decode error.
func TestPartialDecode(t *testing.T) {
	src := `lockfileVersion: '9.0'
packages:
  a@1.0.0:
    resolution: {integrity: ` + sriA + `}
    dev: 1
  b@2.0.0:
    version: 2.0
    resolution: {integrity: ` + sriA + `}
  c@3.0.0:
    resolution: [1, 2]
`
	pkgs, err := Parse(strings.NewReader(src))
	if err == nil || len(pkgs) != 2 {
		t.Fatalf("pkgs=%+v err=%v, want a and b plus an error", pkgs, err)
	}
}
