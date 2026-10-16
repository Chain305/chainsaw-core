package pnpm

import (
	"sort"
	"strings"
	"testing"
)

const (
	sriA  = "sha512-H0D8ktokFpR1CXnubPWC8tXX0o4YM13gWrxU0FYOD1MChgxlK/CNVgJSql50IQVG82n7u86MEs/HlXsmUv6adQ=="
	hashA = "sha512:1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f369fbbbce8c12cfc7957b2652fe9a75"
)

func got(t *testing.T, src string) []string {
	t.Helper()
	pkgs, err := Parse(strings.NewReader(src))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range pkgs {
		out = append(out, p.Name+"@"+p.Version+" origin="+p.Origin+" hash="+p.Hash)
	}
	sort.Strings(out)
	return out
}

func check(t *testing.T, got, want []string) {
	t.Helper()
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// Shaped like pnpm 10's two-document lockfile (vitejs/vite, vuejs/core): the
// package manager's own lock, then the project's. Reading only the first
// document lost every project package.
const twoDocs = `---
lockfileVersion: '9.0'

importers:

  .:
    configDependencies: {}
    packageManagerDependencies:
      pnpm:
        specifier: 10.18.0
        version: 10.18.0

packages:

  pnpm@10.18.0:
    resolution: {integrity: ` + sriA + `}
    hasBin: true

snapshots:

  pnpm@10.18.0: {}

---
lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      lodash:
        specifier: ^4.17.21
        version: 4.17.21
      local-pkg:
        specifier: file:packages/local-pkg
        version: file:packages/local-pkg

packages:

  lodash@4.17.21:
    resolution: {integrity: ` + sriA + `}

  '@scope/pkg@1.0.0':
    resolution: {integrity: sha1-hvfkN/qlp/zhXR3cuerq6jd2Z7g= ` + sriA + `}

  local-pkg@file:packages/local-pkg:
    resolution: {directory: packages/local-pkg, type: directory}

  global-mercator@https://codeload.github.com/decision-labs/global-mercator/tar.gz/905ce5c6f8dd66d180abcbb62594f6094cac7878:
    resolution: {tarball: https://codeload.github.com/decision-labs/global-mercator/tar.gz/905ce5c6f8dd66d180abcbb62594f6094cac7878}
    version: 3.1.0

  '@datasworn/core@https://codeload.github.com/tbsvttr/datasworn/tar.gz/79bc272#path:pkg/nodejs/@datasworn/core':
    resolution: {path: pkg/nodejs/@datasworn/core, tarball: https://codeload.github.com/tbsvttr/datasworn/tar.gz/79bc272}
    version: 0.1.0

  solady@git+https://git@github.com:Vectorized/solady.git#eb227ea1c5eaa56296e7dd713eb165d5d75891dd:
    resolution: {commit: eb227ea1c5eaa56296e7dd713eb165d5d75891dd, repo: git@github.com:Vectorized/solady.git, type: git}
    version: 0.0.237

  mirrored@1.0.0:
    resolution: {integrity: ` + sriA + `, tarball: https://artifactory.example.com/api/npm/npm-remote/mirrored/-/mirrored-1.0.0.tgz}

  registry-looking@1.0.0:
    resolution: {directory: packages/registry-looking, type: directory}

  sneaky@1.0.0:
    resolution: {tarball: https://codeload.github.com/evil/sneaky/tar.gz/0123456}

  vendored@file:vendor/vendored-2.0.0.tgz:
    resolution: {integrity: ` + sriA + `, tarball: file:vendor/vendored-2.0.0.tgz}
    version: 2.0.0

snapshots:

  lodash@4.17.21: {}
`

func TestParseEveryDocumentAndOrigins(t *testing.T) {
	check(t, got(t, twoDocs), []string{
		// First document: pnpm itself, downloaded from the registry.
		"pnpm@10.18.0 origin= hash=" + hashA,
		// Second document: the project.
		"lodash@4.17.21 origin= hash=" + hashA,
		"@scope/pkg@1.0.0 origin= hash=sha1:86f7e437faa5a7fce15d1ddcb9eaeaea377667b8 " + hashA, // every SRI token
		"local-pkg@ origin=file:packages/local-pkg hash=",
		// URL references: the body's version, never the URL; Origin set.
		"global-mercator@3.1.0 origin=https://codeload.github.com/decision-labs/global-mercator/tar.gz/905ce5c6f8dd66d180abcbb62594f6094cac7878 hash=",
		"@datasworn/core@0.1.0 origin=https://codeload.github.com/tbsvttr/datasworn/tar.gz/79bc272#path:pkg/nodejs/@datasworn/core hash=",
		// git: name split at the FIRST "@" (the URL has its own), commit kept
		// in the Origin, never a Hash.
		"solady@0.0.237 origin=git+git@github.com:Vectorized/solady.git#eb227ea1c5eaa56296e7dd713eb165d5d75891dd hash=",
		// A registry-shaped tarball on another host: Origin and the hash.
		"mirrored@1.0.0 origin=https://artifactory.example.com/api/npm/npm-remote/mirrored/-/mirrored-1.0.0.tgz hash=" + hashA,
		"vendored@2.0.0 origin=file:vendor/vendored-2.0.0.tgz hash=",
		// The resolution decides, not the key: pnpm installs what the
		// resolution names, whatever the key looks like.
		"registry-looking@1.0.0 origin=file:packages/registry-looking hash=",
		"sneaky@1.0.0 origin=https://codeload.github.com/evil/sneaky/tar.gz/0123456 hash=",
	})
}

// Shaped like a pnpm 8 (lockfile v6) file: leading-slash keys, peer
// suffixes, and a git dependency keyed by its host path with name/version
// in the body.
const v6 = `lockfileVersion: '6.0'

dependencies:
  react-dom:
    specifier: ^18.2.0
    version: 18.2.0(react@18.2.0)

packages:

  /react-dom@18.2.0(react@18.2.0):
    resolution: {integrity: ` + sriA + `}
    dev: false

  /@babel/core@7.22.0:
    resolution: {integrity: ` + sriA + `}
    dev: true

  github.com/acme/fork/0123456789abcdef0123456789abcdef01234567:
    resolution: {tarball: https://codeload.github.com/acme/fork/tar.gz/0123456789abcdef0123456789abcdef01234567}
    name: fork
    version: 2.0.0
    dev: false
`

func TestParseV6(t *testing.T) {
	check(t, got(t, v6), []string{
		"react-dom@18.2.0 origin= hash=" + hashA,
		"@babel/core@7.22.0 origin= hash=" + hashA,
		"fork@2.0.0 origin=https://codeload.github.com/acme/fork/tar.gz/0123456789abcdef0123456789abcdef01234567 hash=",
	})
}

func TestParseKey(t *testing.T) {
	for k, want := range map[string]string{
		"/foo/1.0.0":                        "foo 1.0.0",
		"/@scope/foo/1.0.0":                 "@scope/foo 1.0.0",
		"/foo/1.0.0_react@17.0.2":           "foo 1.0.0",
		"/foo@1.0.0(peer@2.0.0)":            "foo 1.0.0",
		"/@scope/foo@1.0.0(@x/y@2.0.0)":     "@scope/foo 1.0.0",
		"foo@1.0.0":                         "foo 1.0.0",
		"@scope/foo@1.0.0":                  "@scope/foo 1.0.0",
		"x@git+https://git@h.com:a/b.git#c": "x git+https://git@h.com:a/b.git#c",
	} {
		n, r := parseKey(k)
		if n+" "+r != want {
			t.Errorf("parseKey(%q) = %q %q, want %q", k, n, r, want)
		}
	}
}

// TestParseResolutionTypeDecides: pnpm's fetcher is chosen by
// resolution.type, so a `directory` field beside a tarball, or a file:/link:
// key over a tarball resolution, does not make the fetched tarball local.
// Red-team PoC: {directory: x, tarball: <evil>, integrity} read as file:x.
func TestParseResolutionTypeDecides(t *testing.T) {
	const lock = `lockfileVersion: '9.0'

packages:

  lodash@4.17.21:
    resolution: {directory: x, tarball: https://evil.example/lodash/-/lodash-4.17.21.tgz, integrity: ` + sriA + `}

  plain@1.0.0:
    resolution: {directory: x, integrity: ` + sriA + `}

  keyed@file:./x:
    resolution: {integrity: ` + sriA + `, tarball: https://evil.example/files/keyed-1.0.0.tgz}
    version: 1.0.0

  linked@link:../linked: {}
`
	check(t, got(t, lock), []string{
		"lodash@4.17.21 origin=https://evil.example/lodash/-/lodash-4.17.21.tgz hash=" + hashA,
		// no type, no tarball: the registry, scored as itself.
		"plain@1.0.0 origin= hash=" + hashA,
		"keyed@1.0.0 origin=https://evil.example/files/keyed-1.0.0.tgz hash=",
		"linked@ origin=file:../linked hash=",
	})
}
