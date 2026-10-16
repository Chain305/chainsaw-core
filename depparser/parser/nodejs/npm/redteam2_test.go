package npm

import (
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/depparser/origin"
)

// Red-team round 2 (TestRT2NpmPublicSwap and friends).

func parseString(t *testing.T, s string) map[string]string {
	t.Helper()
	pkgs, err := Parse(strings.NewReader(s))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	out := map[string]string{}
	for _, p := range pkgs {
		out[p.Name+"@"+p.Version] = p.Origin
	}
	return out
}

// TestTarballURLDecidesTheCoordinate (TestRT2NpmPublicSwap): `resolved` is
// what npm fetches. A registry tarball path names the package — re-keyed to
// it, like an alias, so node_modules/lodash resolved to evil-1.0.0.tgz is
// evil@1.0.0 (hash and malware lane on evil), never lodash. A public-registry
// URL that is not a tarball path (no "/-/", a basename that is not the
// package's, an escape) is "url+<url>": non-registry, never the namesake.
// Break it like this: set Origin from origin.Classify alone (the old pkg()),
// or ignore the URL's name/version.
func TestTarballURLDecidesTheCoordinate(t *testing.T) {
	evil := "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz"
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"app"},
"node_modules/lodash":{"version":"4.17.21","resolved":"` + evil + `"},
"node_modules/old":{"version":"1.0.0","resolved":"https://registry.npmjs.org/old/-/old-1.0.1.tgz"},
"node_modules/bare":{"version":"1.0.0","resolved":"https://registry.npmjs.org/bare"},
"node_modules/deep":{"version":"1.0.0","resolved":"https://registry.npmjs.org/x/deep/-/deep-1.0.0.tgz"},
"node_modules/esc":{"version":"1.0.0","resolved":"https://registry.npmjs.org/esc/-/esc-1.0.0%2etgz"},
"node_modules/@babel/core":{"version":"7.22.0","resolved":"https://registry.npmjs.org/@babel/core/-/core-7.22.0.tgz"},
"node_modules/@babel/parser":{"version":"7.22.0","resolved":"https://registry.npmjs.org/@babel%2fparser/-/parser-7.22.0.tgz"},
"node_modules/@babel/types":{"version":"7.22.0","resolved":"https://registry.npmjs.org/@babel/types/-/core-7.22.0.tgz"},
"node_modules/string-width-cjs":{"name":"string-width","version":"4.2.3","resolved":"https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz"},
"node_modules/jsonstream":{"version":"1.3.5","resolved":"https://registry.yarnpkg.com/JSONStream/-/JSONStream-1.3.5.tgz"},
"node_modules/mirrored":{"version":"1.0.0","resolved":"https://artifactory.example.com/api/npm/npm-remote/@acme/real/-/real-2.0.0.tgz"}}}`
	got := parseString(t, lock)
	want := map[string]string{
		"evil@1.0.0":           "",
		"old@1.0.1":            "",
		"bare@1.0.0":           "url+https://registry.npmjs.org/bare",
		"deep@1.0.0":           "url+https://registry.npmjs.org/x/deep/-/deep-1.0.0.tgz",
		"esc@1.0.0":            "url+https://registry.npmjs.org/esc/-/esc-1.0.0%2etgz",
		"@babel/core@7.22.0":   "",
		"@babel/parser@7.22.0": "",
		"@babel/types@7.22.0":  "url+https://registry.npmjs.org/@babel/types/-/core-7.22.0.tgz",
		"string-width@4.2.3":   "",
		"JSONStream@1.3.5":     "",
		"@acme/real@2.0.0":     "https://artifactory.example.com/api/npm/npm-remote/@acme/real/-/real-2.0.0.tgz",
	}
	if len(got) != len(want) {
		t.Errorf("got %v", got)
	}
	for coord, w := range want {
		if o, ok := got[coord]; !ok || o != w {
			t.Errorf("%s: origin %q (present=%v), want %q", coord, o, ok, w)
		}
		if strings.HasPrefix(w, "url+") && origin.Classify("npm", w) != origin.NonRegistry {
			t.Errorf("%s: %q does not classify non-registry", coord, w)
		}
	}

	// v1: the same rule on `resolved`, and on a URL recorded as the spec.
	v1 := `{"lockfileVersion":1,"dependencies":{
"lodash":{"version":"4.17.21","resolved":"` + evil + `"},
"chalk":{"version":"4.1.2","resolved":"https://registry.npmjs.org/chalk/-/chalk-4.1.2.tgz"},
"spec":{"version":"https://registry.npmjs.org/spec/-/spec-2.0.0.tgz"},
"bare":{"version":"1.0.0","resolved":"https://registry.npmjs.org/bare"}}}`
	got = parseString(t, v1)
	if len(got) != 4 || got["evil@1.0.0"] != "" || got["chalk@4.1.2"] != "" || got["spec@2.0.0"] != "" ||
		got["bare@1.0.0"] != "url+https://registry.npmjs.org/bare" {
		t.Errorf("v1: %v", got)
	}
}

// TestKeyOutsideNodeModulesWithRemoteResolved (finding F): an entry whose key
// is not under node_modules/ was local code ("file:<key>") whatever its
// `resolved`; one npm fetches from a URL or git is from there. Break it like
// this: drop the IsRemote check.
func TestKeyOutsideNodeModulesWithRemoteResolved(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"app"},
"packages/a":{"name":"a","version":"1.0.0"},
"vendor/x":{"name":"x","version":"1.0.0","resolved":"https://evil.example/x-1.0.0.tgz"},
"vendor/y":{"name":"y","version":"2.0.0","resolved":"git+ssh://git@github.com/e/y.git#0123456"},
"vendor/z":{"name":"z","version":"3.0.0","resolved":"https://registry.npmjs.org/z"}}}`
	got := parseString(t, lock)
	if got["a@1.0.0"] != "file:packages/a" {
		t.Errorf("workspace member: %q", got["a@1.0.0"])
	}
	for coord, want := range map[string]string{
		"x@1.0.0": "https://evil.example/x-1.0.0.tgz",
		"y@2.0.0": "git+ssh://github.com/e/y.git#0123456", // userinfo sanitized
		"z@3.0.0": "url+https://registry.npmjs.org/z",
	} {
		if got[coord] != want {
			t.Errorf("%s: origin %q, want %q", coord, got[coord], want)
		}
	}
}

// TestTolerantFieldTypes (finding E): `"dev": 1` and `"link": 0` are a
// lockfile npm installs; they parse with JavaScript truthiness. A string
// field holding a non-string (round 3: `"resolved": ["https://evil/…"]`,
// which npm coerces to that URL, or `"version": 1`) is NOT tolerated as "":
// that entry is an error, returned WITH every other entry. One entry that is
// not an object likewise. Break it like this: make Dev a bool, read a
// non-string string field as "", or return nil on an entry error.
func TestTolerantFieldTypes(t *testing.T) {
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"app"},
"node_modules/a":{"version":"1.0.0","dev":1},
"node_modules/b":{"version":"1.0.0","dev":0,"link":""},
"node_modules/c":{"version":"1.0.0","dev":"yes"},
"node_modules/lodash":{"version":"4.17.21","resolved":["https://evil.example/x/evil-1.0.0.tgz"]},
"node_modules/evil":{"version":1}}}`
	pkgs, err := Parse(strings.NewReader(lock))
	if err == nil || len(pkgs) != 3 {
		t.Fatalf("pkgs=%+v err=%v, want a, b, c and an error", pkgs, err)
	}
	dev := map[string]bool{}
	for _, p := range pkgs {
		dev[p.Name] = p.Dev
		if p.Name == "lodash" || p.Name == "evil" {
			t.Errorf("%s parsed from a non-string field", p.Name)
		}
	}
	if !dev["a"] || dev["b"] || !dev["c"] {
		t.Errorf("dev = %v", dev)
	}

	pkgs, err = Parse(strings.NewReader(`{"lockfileVersion":3,"packages":{"node_modules/a":{"version":"1.0.0"},"node_modules/x":7}}`))
	if err == nil || len(pkgs) != 1 || pkgs[0].Name != "a" {
		t.Fatalf("partial: pkgs=%+v err=%v, want a plus an error", pkgs, err)
	}
}

// TestIsArchiveIsOriginIsArchive (finding G): the npm parser, bun and the
// guard decide "vendored archive, not local code" by one list. Break it like
// this: give npm.IsArchive its own suffix list again.
func TestIsArchiveIsOriginIsArchive(t *testing.T) {
	for _, p := range []string{"vendor/x-1.0.0.tar", "x.tgz", "x.tar.gz", "x.TGZ", "x.zip", "x.tgz?y=1", "./dir", "x.tar.bz2", "pkg"} {
		if IsArchive(p) != origin.IsArchive(p) {
			t.Errorf("%s: npm.IsArchive=%v origin.IsArchive=%v", p, IsArchive(p), origin.IsArchive(p))
		}
	}
	if !IsArchive("file:vendor/evilpkg-1.0.0.tar") {
		t.Error(".tar is not an archive")
	}
}
