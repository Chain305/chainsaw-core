package yarn

import (
	"strings"
	"testing"
)

// Red-team round 2.

// TestV1PublicSwap: a v1 `resolved` registry tarball names the package yarn
// fetches, whatever the descriptors say — re-keyed to it (the evil swap
// becomes evil@1.0.0; elastic/kibana's "@emotion/sheet@^1.4.0",
// "@emotion/sheet@npm:@elastic/emotion-sheet@1.4.1" block is
// @elastic/emotion-sheet). A public URL that is not a tarball path is
// "url+<url>". Break it like this: set Origin with nodesource.Origin
// (Classify alone), or keep the first descriptor's name.
func TestV1PublicSwap(t *testing.T) {
	src := `# yarn lockfile v1

lodash@^4.17.21:
  version "4.17.21"
  resolved "https://registry.yarnpkg.com/evil/-/evil-1.0.0.tgz#` + sha1A + `"
  integrity ` + sriA + `

"@babel/core@^7.22.0":
  version "7.22.0"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.22.0.tgz#` + sha1A + `"

"@babel/parser@^7.22.0":
  version "7.22.0"
  resolved "https://registry.npmjs.org/@babel%2fparser/-/parser-7.22.0.tgz"

"string-width-cjs@npm:string-width@^4.2.0":
  version "4.2.3"
  resolved "https://registry.yarnpkg.com/string-width/-/string-width-4.2.3.tgz"

"@emotion/sheet@^1.4.0", "@emotion/sheet@npm:@elastic/emotion-sheet@1.4.1":
  version "1.4.1"
  resolved "https://registry.yarnpkg.com/@elastic/emotion-sheet/-/emotion-sheet-1.4.1.tgz#ec86896018f34d04c6dff61347e267738d3265c3"

bare@^1:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/bare"
`
	check(t, got(t, src), []string{
		"evil@1.0.0 origin= hash=" + hashA,
		"@babel/core@7.22.0 origin= hash=sha1:" + sha1A,
		"@babel/parser@7.22.0 origin= hash=",
		"string-width@4.2.3 origin= hash=",
		"@elastic/emotion-sheet@1.4.1 origin= hash=sha1:ec86896018f34d04c6dff61347e267738d3265c3",
		"bare@1.0.0 origin=url+https://registry.yarnpkg.com/bare hash=",
	})
}

// TestBerryResolutionVersionWins (TestRT2BerryVersionLie): yarn fetches the
// `resolution` locator, so its npm: version keys the package, not the
// `version` field. A descriptor fallback (no resolution) keeps `version`.
// An __archiveUrl locator parameter is the tarball yarn fetches and decides
// the coordinate. Break it like this: prefer e.Version again, or ignore the
// "::" parameters.
func TestBerryResolutionVersionWins(t *testing.T) {
	src := `__metadata:
  version: 8

"event-stream@npm:^3.3.4":
  version: 3.3.5
  resolution: "event-stream@npm:3.3.6"

"ms@npm:^2":
  version: 2.1.3

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21::__archiveUrl=https%3A%2F%2Fregistry.npmjs.org%2Fevil%2F-%2Fevil-1.0.0.tgz"

"chalk@npm:4.1.2":
  version: 4.1.2
  resolution: "chalk@npm:4.1.2::__archiveUrl=https%3A%2F%2Fregistry.npmjs.org%2Fchalk%2F-%2Fchalk-4.1.2.tgz"

"debug@npm:4.3.4":
  version: 4.3.4
  resolution: "debug@npm:4.3.4::__archiveUrl=https%3A%2F%2Fnpm.example.com%2Fdebug%2F-%2Fdebug-4.3.4.tgz"
`
	check(t, got(t, src), []string{
		"event-stream@3.3.6 origin= hash=",
		"ms@2.1.3 origin= hash=",
		"evil@1.0.0 origin= hash=",
		"chalk@4.1.2 origin= hash=",
		"debug@4.3.4 origin=https://npm.example.com/debug/-/debug-4.3.4.tgz hash=",
	})
}

// TestBerryPartialDecode (finding E): an entry that does not decode is an
// error returned with every entry that did; a scalar of another type reads
// as a string. Break it like this: decode the whole map at once again.
func TestBerryPartialDecode(t *testing.T) {
	src := "__metadata:\n  version: 8\n\n\"a@npm:1.0.0\":\n  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n\n" +
		"\"b@npm:2\":\n  version: 2\n  resolution: \"b@npm:2\"\n\n\"0bad@npm:1\":\n  version: [1]\n  resolution: {x: 1}\n"
	pkgs, err := Parse(strings.NewReader(src))
	if err == nil || len(pkgs) != 2 {
		t.Fatalf("pkgs=%+v err=%v, want a and b plus an error", pkgs, err)
	}
}

// TestBerryArchiveURLWithMalformedParams (red-team round 3): locator params
// Go's url.ParseQuery rejects ("…&a=;", "…&a=%zz") are read by Node's
// querystring, so yarn fetches __archiveUrl anyway — it must still decide
// the coordinate; an __archiveUrl that cannot be read at all is never the
// public package. Break it like this: require err == nil from ParseQuery.
func TestBerryArchiveURLWithMalformedParams(t *testing.T) {
	src := `__metadata:
  version: 8

"lodash@npm:4.17.21":
  version: 4.17.21
  resolution: "lodash@npm:4.17.21::__archiveUrl=https%3A%2F%2Fevil.example%2Fx%2Fevil-1.0.0.tgz&a=;"

"chalk@npm:4.1.2":
  version: 4.1.2
  resolution: "chalk@npm:4.1.2::__archiveUrl=https%3A%2F%2Fevil.example%2Fx%2Fevil-1.0.0.tgz&a=%zz"

"debug@npm:4.3.4":
  version: 4.3.4
  resolution: "debug@npm:4.3.4::__archiveUrl=%zz"
`
	for _, l := range got(t, src) {
		if strings.Contains(l, "origin= ") {
			t.Errorf("scored as the public package: %s", l)
		}
	}
}
