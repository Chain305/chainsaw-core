package nodesource

import (
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/depparser/origin"
)

const (
	pub  = "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
	evil = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
	ev2  = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

// TestIntegrityKeepsEveryToken: ssri accepts bytes matching ANY token of the
// strongest algorithm, so "sha512-<public> sha512-<evil>" installs either
// and the Hash must carry both (the server then needs every token to be a
// registry digest). An uppercase-algorithm token, which ssri ignores, is
// dropped, so "SHA512-<public> sha256-<evil>" is the evil sha256 alone —
// never the public sha512. Break it like this: keep only the first
// strongest token, or accept an uppercase SRI algorithm in NormalizeHash.
func TestIntegrityKeepsEveryToken(t *testing.T) {
	got := Integrity(pub + " " + evil)
	if toks := origin.SplitHashes(got); len(toks) != 2 {
		t.Fatalf("Integrity(pub evil) = %q, want both sha512 tokens", got)
	}
	if got := Integrity("SHA512-" + pub[len("sha512-"):] + " " + ev2); got != origin.NormalizeHash(ev2) {
		t.Fatalf("Integrity(SHA512-pub sha256-evil) = %q, want only %q", got, origin.NormalizeHash(ev2))
	}
	if got := Integrity(pub); got != origin.NormalizeHash(pub) || strings.Contains(got, " ") {
		t.Fatalf("single token = %q", got)
	}
	if Integrity("") != "" || Integrity("sha512") != "" || Integrity("Sha224-abc") != "" {
		t.Fatal("no token ssri reads must be \"\"")
	}
}

// TestIntegrityKeepsUnreadable (red-team round 2, TestRT2Sha224Dropped): a
// token ssri reads but NormalizeHash cannot — sha224, which ssri ranks above
// sha1, md5, a malformed digest — is kept as origin.UnreadableHash, so
// "sha1-<public> sha224-<evil>" is never the public sha1 alone. Break it
// like this: drop tokens NormalizeHash rejects (the old behaviour).
func TestIntegrityKeepsUnreadable(t *testing.T) {
	const sha1Pub = "sha1-VgiurfwAvmwpAd9fmGF4jeDVl8g="
	const evil224 = "sha224-d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3"
	got := Integrity(sha1Pub + " " + evil224)
	want := origin.JoinHashes(origin.NormalizeHash(sha1Pub), origin.UnreadableHash("sha224"))
	if got != want {
		t.Fatalf("Integrity(sha1 sha224) = %q, want %q", got, want)
	}
	for in, want := range map[string]string{
		"md5-abc":          origin.UnreadableHash("md5"),
		"sha512-notbase64": origin.UnreadableHash("sha512"),
		"sha3-abc?opt":     origin.UnreadableHash("sha3"),
		"SHA224-abc":       "", // ssri ignores a non-lowercase algorithm
		"sha-224-abc":      origin.UnreadableHash("sha"),
	} {
		if got := Integrity(in); got != want {
			t.Errorf("Integrity(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestTarball: a registry tarball path names the package fetched; anything
// else on the public registry is "url+"; off it, the coordinate is kept
// unless the path is a tarball path. Break it like this: drop the rooted
// check (a public path with segments in front would re-key), or accept a
// basename that is not the package's.
func TestTarball(t *testing.T) {
	const reg = "https://registry.npmjs.org"
	for _, c := range []struct{ src, n, v, o string }{
		{"", "k", "1", ""},
		{reg + "/lodash/-/lodash-4.17.21.tgz", "lodash", "4.17.21", ""},
		{reg + "/lodash/-/lodash-4.17.21.tgz?x=1#abc", "lodash", "4.17.21", ""},
		{reg + "/@s/x/-/x-1.0.0-beta.1.tgz", "@s/x", "1.0.0-beta.1", ""},
		{reg + "/@s%2Fx/-/x-1.0.0.tgz", "@s/x", "1.0.0", ""},
		{reg + "/a/b/-/b-1.0.0.tgz", "k", "1", "url+" + reg + "/a/b/-/b-1.0.0.tgz"},
		{reg + "/@/x/-/x-1.0.0.tgz", "k", "1", "url+" + reg + "/@/x/-/x-1.0.0.tgz"},
		{reg + "/x/-/x-1.0.0/y.tgz", "k", "1", "url+" + reg + "/x/-/x-1.0.0/y.tgz"},
		{reg + "/x/-/x-.tgz", "k", "1", "url+" + reg + "/x/-/x-.tgz"},
		{reg + "/x/-/y-1.0.0.tgz", "k", "1", "url+" + reg + "/x/-/y-1.0.0.tgz"},
		{reg + "/x/-/x-1.0.0.tar.gz", "k", "1", "url+" + reg + "/x/-/x-1.0.0.tar.gz"},
		{"https://m.example/npm/@s/x/-/x-2.0.0.tgz", "@s/x", "2.0.0", "https://m.example/npm/@s/x/-/x-2.0.0.tgz"},
		{"https://m.example/npm/x", "k", "1", "https://m.example/npm/x"},
		{"git+https://github.com/a/b.git#0123456", "k", "1", "git+https://github.com/a/b.git#0123456"},
	} {
		n, v, o := Tarball("k", "1", c.src)
		if n != c.n || v != c.v || o != c.o {
			t.Errorf("Tarball(%q) = %q %q %q, want %q %q %q", c.src, n, v, o, c.n, c.v, c.o)
		}
	}
}

// TestMirrorPathNormalisationIsNotTheLockfileName (red-team round 3): a
// mirror URL the client normalises to another package's tarball (dot
// segments, %2e, other escapes) must not fall back to the lockfile's
// coordinate; an honest Artifactory scoped path still does. Break it like
// this: drop the plainMirrorPath check.
func TestMirrorPathNormalisationIsNotTheLockfileName(t *testing.T) {
	for _, u := range []string{
		"https://mirror.corp/npm/evil/-/./evil-1.0.0.tgz",
		"https://mirror.corp/npm/evil/-/x/../evil-1.0.0.tgz",
		"https://mirror.corp/npm/evil/-/%2e/evil-1.0.0.tgz",
		"https://mirror.corp/npm/%65vil/-/evil-1.0.0.tgz",
	} {
		n, v, o := Tarball("lodash", "4.17.21", u)
		if n == "lodash" && !strings.HasPrefix(o, "url+") {
			t.Errorf("%s: (%s, %s, %q) — scored under the lockfile name", u, n, v, o)
		}
	}
	n, v, o := Tarball("@babel/core", "7.0.0", "https://artifactory.corp/api/npm/npm/@babel/core/-/@babel/core-7.0.0.tgz")
	if n != "@babel/core" || v != "7.0.0" || strings.HasPrefix(o, "url+") {
		t.Errorf("honest scoped Artifactory path: (%s, %s, %q)", n, v, o)
	}
}
