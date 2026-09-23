package intelligence

// Go module artifacts were never fetched, so every artifact-reading provider
// skipped every Go coordinate.
//
// Measured in production 2026-09-22: `artifactScan.performed` is true on
// **4 of 6,139** Go reports. `artifactURLFor` knew npm/yarn/bun, cargo and
// rubygems; `go` and `gomod` fell through to the empty return, the scanner
// then saw req.Artifact == nil, and every NeedsArtifact provider emitted
// WarnNeedsArtifact instead of running. Go is the single largest ecosystem in
// the corpus, so this was the biggest coverage hole in the product.
//
// The module proxy makes this deterministic — there is no registry lookup to
// cache first, which is why PyPI is still skipped and Go did not have to be.
//
// VERIFIED AGAINST THE REAL PROXY 2026-09-22, because a wrong escape is a
// silent 404 rather than an error, and a unit test asserting a string I made
// up would have proved nothing:
//
//	github.com/gorilla/mux@v1.8.1            -> 200, 60,113 B
//	github.com/!masterminds/semver/v3@v3.2.1 -> 200, 33,424 B
//	github.com/Masterminds/semver/v3@v3.2.1  -> 404   (unescaped control)
//	github.com/!burnt!sushi/toml@v1.3.2      -> 200, 303,020 B
//
// The unescaped control is the one that matters: it proves the escaping is
// load-bearing and not decoration. It also cost one wrong fixture to learn
// that `semver` v3 lives at `.../semver/v3`, since a major version >= 2 is
// part of the module path — the URL builder was right, my coordinate was not.

import "testing"

func TestArtifactURLFor_GoModule(t *testing.T) {
	for _, tc := range []struct {
		name, eco, mod, ver, want string
	}{
		{
			name: "lowercase module path passes through",
			eco:  "go", mod: "github.com/gorilla/mux", ver: "v1.8.1",
			want: "https://proxy.golang.org/github.com/gorilla/mux/@v/v1.8.1.zip",
		},
		{
			// The proxy's case-encoding: an uppercase letter becomes
			// "!" + its lowercase form, because module paths are
			// case-sensitive but many filesystems are not. Getting this
			// wrong is a 404 on every module with a capitalised author,
			// which is a large share of real Go dependencies.
			name: "uppercase is !-escaped, not lowercased",
			eco:  "go", mod: "github.com/Masterminds/semver/v3", ver: "v3.2.1",
			want: "https://proxy.golang.org/github.com/!masterminds/semver/v3/@v/v3.2.1.zip",
		},
		{
			name: "gomod alias resolves the same way",
			eco:  "gomod", mod: "golang.org/x/text", ver: "v0.14.0",
			want: "https://proxy.golang.org/golang.org/x/text/@v/v0.14.0.zip",
		},
		{
			name: "several capitals each escape",
			eco:  "go", mod: "github.com/BurntSushi/toml", ver: "v1.3.2",
			want: "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.3.2.zip",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, media := artifactURLFor(tc.eco, tc.mod, tc.ver)
			if got != tc.want {
				t.Errorf("url = %q\nwant %q", got, tc.want)
			}
			if media == "" {
				t.Error("empty media type; the fetcher passes it as Content-Type")
			}
		})
	}
}

// A BARE version is the normal stored spelling, not an error.
//
// This used to assert that "1.8.1" produced no URL, on the reasoning that a
// version without the leading "v" is not a module version and building a URL
// from it burns an upstream fetch on a guaranteed 404. The reasoning was
// sound and the conclusion was backwards: both Go lockfile parsers STRIP the
// "v" so their coordinates dedup and match how vulnerability databases index
// semver, which means bare is what **6,093 of the 6,139** stored Go
// coordinates look like. Refusing them did avoid 404s — by declining to scan
// 99.2% of the Go corpus.
//
// The prefix is restored now (intelligence.GoModuleZipPath), so a bare version
// resolves. What must still be refused is a string that is not a version at
// all, where there is nothing to restore.
func TestArtifactURLFor_GoRestoresBareVersions(t *testing.T) {
	got, _ := artifactURLFor("go", "github.com/gorilla/mux", "1.8.1")
	const want = "https://proxy.golang.org/github.com/gorilla/mux/@v/v1.8.1.zip"
	if got != want {
		t.Errorf("bare version produced %q, want %q — this is the spelling 6,093 of "+
			"6,139 stored Go coordinates use", got, want)
	}
}

func TestArtifactURLFor_GoRejectsNonVersions(t *testing.T) {
	for _, ver := range []string{"", "latest", "not-a-version", "main"} {
		if got, _ := artifactURLFor("go", "github.com/gorilla/mux", ver); got != "" {
			t.Errorf("version %q produced url %q, want empty — there is no prefix to "+
				"restore on a string that is not semver, so this is a guaranteed 404", ver, got)
		}
	}
}

// Control: the ecosystems that deliberately have no URL must keep having none.
// PyPI needs a registry lookup first (documented at the call site) and
// huggingface artifacts are model weights fetched on a different path.
func TestArtifactURLFor_StillEmptyWhereItShouldBe(t *testing.T) {
	for _, eco := range []string{"pypi", "pip", "huggingface", "maven"} {
		if got, _ := artifactURLFor(eco, "x", "1.0.0"); got != "" {
			t.Errorf("%s returned %q, want empty", eco, got)
		}
	}
}
