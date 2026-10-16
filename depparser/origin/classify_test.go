package origin

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	for _, c := range []struct {
		eco, src string
		want     Class
	}{
		{"cargo", "", Public},
		// Every public alias, per ecosystem.
		{"cargo", "registry+https://github.com/rust-lang/crates.io-index", Public},
		{"cargo", "registry+https://github.com/rust-lang/crates.io-index.git", Public},
		{"cargo", "sparse+https://index.crates.io/", Public},
		{"cargo", "sparse+https://index.crates.io", Public},
		{"cargo", "https://static.crates.io/crates/serde/serde-1.0.0.crate", Public},
		{"cargo", "https://crates.io/api/v1/crates/serde/1.0.0/download", Public},
		{"npm", "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz", Public},
		{"npm", "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz", Public},
		{"yarn", "https://registry.yarnpkg.com/lodash/-/lodash-4.17.21.tgz", Public},
		{"pypi", "https://pypi.org/simple", Public},
		{"pip", "https://files.pythonhosted.org/packages/ab/cd/requests-2.31.0-py3-none-any.whl", Public},
		{"pypi", "https://pypi.python.org/simple/", Public},
		{"rubygems", "https://rubygems.org/", Public},
		{"rubygems", "https://index.rubygems.org/", Public},
		{"pub", "https://pub.dev", Public},
		{"pub", "https://pub.dartlang.org", Public},
		{"cocoapods", "https://cdn.cocoapods.org/", Public},
		{"cocoapods", "https://trunk.cocoapods.org/", Public},
		{"cocoapods", "https://github.com/CocoaPods/Specs.git", Public},
		{"cocoapods", "https://github.com/cocoapods/specs", Public},
		{"nuget", "https://api.nuget.org/v3/index.json", Public},
		{"nuget", "https://www.nuget.org/api/v2/", Public},
		{"composer", "https://repo.packagist.org", Public},
		{"composer", "https://packagist.org", Public},
		{"maven", "https://repo1.maven.org/maven2/", Public},
		{"maven", "https://repo.maven.apache.org/maven2", Public},
		{"conda", "https://conda.anaconda.org/conda-forge/linux-64/x-1.0.conda", Public},
		{"conda", "https://repo.anaconda.com/pkgs/main/linux-64/x-1.0.tar.bz2", Public},
		{"conda", "conda-forge", Public},
		// Dot segments, escapes and backslashes in a path alias resolve
		// elsewhere under WHATWG parsing (cargo, conda): never Public.
		{"cargo", "registry+https://github.com/rust-lang/crates.io-index/../../attacker/index", RegistryOther},
		{"cargo", "registry+https://github.com/rust-lang/crates.io-index/%2e%2e/%2e%2e/attacker/index", RegistryOther},
		{"cargo", `registry+https://github.com/rust-lang/crates.io-index/..\..\attacker/index`, RegistryOther},
		{"cargo", "registry+https://github.com/rust-lang/crates.io-index/sub", RegistryOther},
		{"cargo", "registry+https://github.com/rust-lang//crates.io-index", RegistryOther},
		{"conda", "https://conda.anaconda.org/conda-forge/../attacker/linux-64/x-1.0-0.conda", NonRegistry},
		{"conda", "https://conda.anaconda.org/conda-forge/%2e%2e/attacker/x-1.0-0.conda", NonRegistry},
		{"conda", "defaults", Public},

		// Exact host, default port, no suffix tricks.
		{"npm", "https://registry.npmjs.org.evil.example/lodash/-/lodash-4.17.21.tgz", RegistryOther},
		{"npm", "https://evilregistry.npmjs.org/lodash/-/lodash-4.17.21.tgz", RegistryOther},
		{"npm", "https://registry.npmjs.org:8443/lodash/-/lodash-4.17.21.tgz", RegistryOther},
		{"cargo", "registry+https://github.com/rust-lang/crates.io-index-evil", RegistryOther},
		{"cargo", "registry+https://github.com/attacker/crates.io-index", RegistryOther},
		{"cocoapods", "https://github.com/attacker/Specs.git", RegistryOther},
		{"conda", "https://conda.anaconda.org/attacker/linux-64/x-1.0.conda", NonRegistry},
		// A public host only counts for its own ecosystem.
		{"npm", "https://pypi.org/simple", NonRegistry},

		// Registry protocol elsewhere: a mirror or a private registry.
		{"cargo", "registry+https://my-registry.example/index", RegistryOther},
		{"cargo", "sparse+https://artifactory.example/api/cargo/crates/index/", RegistryOther},
		{"cargo", "sparse+https://chain305.com/chainproxy/repository/@acme/crates/", RegistryOther},
		{"npm", "https://artifactory.example/api/npm/npm-remote/lodash/-/lodash-4.17.21.tgz", RegistryOther},
		{"npm", "https://chain305.com/chainproxy/repository/@acme/npmjs/lodash/-/lodash-4.17.21.tgz", RegistryOther},
		{"pypi", "https://artifactory.example/api/pypi/pypi-remote/simple", RegistryOther},
		{"pypi", "https://devpi.example/root/pypi/+simple/", NonRegistry}, // devpi's +simple: P1b
		{"pypi", "https://chain305.com/chainproxy/repository/@acme/pypi/packages/r-1.0.whl", RegistryOther},
		{"rubygems", "https://gems.example/", RegistryOther},
		{"nuget", "https://pkgs.dev.azure.com/acme/_packaging/feed/nuget/v3/index.json", RegistryOther},

		// Non-registry: git, path, tarball, workspace, link.
		{"cargo", "git+https://github.com/feldera/etl?rev=cdfb3c7#cdfb3c7", NonRegistry},
		{"cargo", "path+file:///home/x/crate", NonRegistry},
		{"npm", "git+ssh://git@github.com/x/y.git#abc", NonRegistry},
		{"npm", "github:x/y", NonRegistry},
		{"npm", "git@github.com:x/y.git", NonRegistry},
		{"npm", "file:../local", NonRegistry},
		{"npm", "link:../local", NonRegistry},
		{"npm", "workspace:*", NonRegistry},
		{"npm", "https://codeload.github.com/x/y/tar.gz/abc", NonRegistry},
		{"npm", "https://evil.example/x.tgz", NonRegistry},
		{"pypi", "https://evil.example/requests-2.31.0-py3-none-any.whl", NonRegistry},
		{"pypi", "../local", NonRegistry},
		{"rubygems", "https://evil.example/x-1.0.gem", NonRegistry},
		{"cargo", "ssh://git@github.com/x/y", NonRegistry},
		{"cargo", "git://github.com/x/y", NonRegistry},
	} {
		if got := Classify(c.eco, c.src); got != c.want {
			t.Errorf("Classify(%q, %q) = %v, want %v", c.eco, c.src, got, c.want)
		}
	}
}

func TestNormalizeMirrorHost(t *testing.T) {
	for in, want := range map[string]string{
		"artifactory.example.com":      "artifactory.example.com",
		" Nexus.Corp ":                 "nexus.corp",
		"artifactory.example.com:8443": "artifactory.example.com:8443",
		"10.0.0.5":                     "10.0.0.5",
	} {
		if got, err := NormalizeMirrorHost(in); err != nil || got != want {
			t.Errorf("NormalizeMirrorHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "https://artifactory.example.com", "artifactory.example.com/api", "*.corp", "user@host", "host:0", "host:99999", "host:08", "-bad.example", "a..b", "host name", ".corp"} {
		if got, err := NormalizeMirrorHost(bad); err == nil {
			t.Errorf("NormalizeMirrorHost(%q) = %q, want an error", bad, got)
		}
	}
	// A pasted URL's credential must not reach the error (stderr, CI logs,
	// the PATCH 400 body).
	if _, err := NormalizeMirrorHost("https://user:s3cretTOKEN@artifactory.example.com"); err == nil || strings.Contains(err.Error(), "s3cretTOKEN") {
		t.Errorf("error leaks the credential: %v", err)
	}
}

func TestMirrorHost(t *testing.T) {
	mirrors := []string{"artifactory.example.com", "nexus.corp:8081"}
	for src, want := range map[string]string{
		"registry+https://artifactory.example.com/api/cargo/index":         "artifactory.example.com",
		"https://ARTIFACTORY.example.com/api/npm/x/-/x-1.0.0.tgz":          "artifactory.example.com",
		"https://artifactory.example.com:443/x":                            "artifactory.example.com",
		"https://nexus.corp:8081/repository/pypi/simple":                   "nexus.corp:8081",
		"https://artifactory.example.com:8443/x":                           "", // bare host = default port only
		"https://nexus.corp/x":                                             "", // port given = that port only
		"https://artifactory.example.com.evil.example/x":                   "", // never a suffix
		"https://evil-artifactory.example.com/x":                           "",
		"git+https://artifactory.example.com/x.git":                        "artifactory.example.com", // class decides git; host matching is separate
		"https://artifactory.example.com/chainproxy/repository/@other/npm": "",                        // a Chainsaw repository: hash only
		"ssh://artifactory.example.com/x":                                  "",
		"https://artifactory.example.com/x/repository/./@other/npm":        "", // path tricks still a Chainsaw repository
		"https://artifactory.example.com/x/repository//@other/npm":         "",
		"https://artifactory.example.com/x/Repository/%40other/npm":        "",
		"": "",
	} {
		if got := MirrorHost(src, mirrors); got != want {
			t.Errorf("MirrorHost(%q) = %q, want %q", src, got, want)
		}
	}
}

func TestNormalizeHash(t *testing.T) {
	const crate = "beb81ca59b1a7bc7a92b7ac7c4c13a9f78a4d3d7e5d06d2ff27a2a37fd5c0b9e"
	for in, want := range map[string]string{
		"sha256:" + crate:            "sha256:" + crate,
		"SHA256:" + crate:            "sha256:" + crate,
		"sha256=" + crate:            "sha256:" + crate,
		"sha256:" + crate[:63]:       "",
		"sha256:" + crate[:63] + "z": "",
		// npm integrity for lodash 4.17.21.
		"sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==":     "sha512:bf690311ee7b95e713ba568322e3533f2dd1cb880b189e99d4edef13592b81764daec43e2c54c61d5c558dc5cfb35ecb85b65519e74026ff17675b6f8f916f4a",
		"sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg==?foo": "sha512:bf690311ee7b95e713ba568322e3533f2dd1cb880b189e99d4edef13592b81764daec43e2c54c61d5c558dc5cfb35ecb85b65519e74026ff17675b6f8f916f4a",
		"sha512-notbase64!": "",
		"md5:abc":           "",
		crate:               "",
		"":                  "",
	} {
		if got := NormalizeHash(in); got != want {
			t.Errorf("NormalizeHash(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestJoinSplitHashes: several candidate files of one release become one
// deterministic Hash (canonical, deduplicated, sorted); unusable tokens are
// dropped; a single hash round-trips unchanged.
func TestJoinSplitHashes(t *testing.T) {
	a, b := "sha256:"+strings.Repeat("b", 64), "sha256:"+strings.Repeat("a", 64)
	got := JoinHashes(a, "SHA256="+strings.Repeat("A", 64), "md5:00", "", b)
	if want := b + " " + a; got != want {
		t.Fatalf("JoinHashes = %q, want %q", got, want)
	}
	if s := SplitHashes(got + " junk"); len(s) != 2 || s[0] != b || s[1] != a {
		t.Fatalf("SplitHashes = %q", s)
	}
	if got := JoinHashes(a); got != a || NormalizeHash(got) != a {
		t.Fatalf("single hash = %q", got)
	}
	if JoinHashes() != "" || len(SplitHashes("")) != 0 {
		t.Fatal("empty")
	}
}

// TestJoinHashesBoundedAndNonMutating: past MaxJoinedHashes distinct tokens
// the Hash is "" (a crafted lockfile cannot make every entry carry an
// unbounded string); duplicates do not count toward the cap; the caller's
// slice is never reordered. Break it like this: drop the cap, or sort the
// argument slice in place.
func TestJoinHashesBoundedAndNonMutating(t *testing.T) {
	tok := func(i int) string { return fmt.Sprintf("sha256:%064x", i) }
	var hs []string
	for i := MaxJoinedHashes; i > 0; i-- {
		hs = append(hs, tok(i), tok(i)) // duplicates
	}
	orig := append([]string(nil), hs...)
	if got := len(SplitHashes(JoinHashes(hs...))); got != MaxJoinedHashes {
		t.Fatalf("%d distinct tokens: joined %d, want all", MaxJoinedHashes, got)
	}
	if !reflect.DeepEqual(hs, orig) {
		t.Fatal("JoinHashes reordered the caller's slice")
	}
	if got := JoinHashes(append(hs, tok(0))...); got != "" {
		t.Fatalf("%d distinct tokens: Hash = %d bytes, want \"\"", MaxJoinedHashes+1, len(got))
	}
}

// TestNormalizeHashUppercaseSRI: npm's ssri reads only a lowercase SRI
// algorithm and skips "SHA512-…", so such a token must not be one we
// compare: "SHA512-<public> sha256-<evil>" would otherwise vouch for bytes
// npm never checks against it. "<algo>:<hex>" stays case-insensitive.
// Break it like this: lowercase the SRI algorithm before checking it.
func TestNormalizeHashUppercaseSRI(t *testing.T) {
	const lodash = "v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="
	for _, in := range []string{"SHA512-" + lodash, "Sha512-" + lodash} {
		if got := NormalizeHash(in); got != "" {
			t.Errorf("NormalizeHash(%q) = %q, want \"\"", in, got)
		}
	}
	if NormalizeHash("sha512-"+lodash) == "" || NormalizeHash("SHA256:"+strings.Repeat("A", 64)) == "" {
		t.Fatal("lowercase SRI / uppercase <algo>:<hex> must still parse")
	}
}

func TestIsArchive(t *testing.T) {
	for in, want := range map[string]bool{
		"file:vendor/x-1.0.0.tgz":        true,
		"file:vend/X-1.0.0.TAR.GZ":       true,
		"file:dist/pkg-1.0-py3-none.whl": true,
		"file:x.zip#sha1=abc":            true,
		"https://h.example/a.gem?t=1":    true,
		"./vendor/evilpkg-1.0.tar":       true,
		"file:v/x-1.0.TBZ":               true,
		"file:v/x-1.0.txz":               true,
		"file:v/x-1.0.tlz":               true,
		"file:v/x-1.0.tar.lz":            true,
		"file:v/x-1.0.tar.lzma":          true,
		"file:packages/tar":              false,
		"file:packages/ws":               false,
		"file:./tgz":                     false,
		"":                               false,
	} {
		if got := IsArchive(in); got != want {
			t.Errorf("IsArchive(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestUnreadableHashKept: a placeholder for a hash we cannot read survives
// JoinHashes/SplitHashes (dropping it let "sha1-<public> sha224-<other>"
// match on the sha1 alone), is canonical and bounded, and dedupes.
func TestUnreadableHashKept(t *testing.T) {
	sha1 := "sha1:" + strings.Repeat("a", 40)
	j := JoinHashes(sha1, UnreadableHash("SHA224"), UnreadableHash("sha224"), "garbage")
	if j != sha1+" unknown:sha224" {
		t.Fatalf("JoinHashes = %q", j)
	}
	if got := SplitHashes(j); len(got) != 2 || !IsUnreadableHash(got[1]) {
		t.Fatalf("SplitHashes = %q", got)
	}
	if got := UnreadableHash(""); got != "unknown:none" {
		t.Fatalf("UnreadableHash(\"\") = %q", got)
	}
	if got := UnreadableHash("a/b c" + strings.Repeat("x", 40)); len(got) > len("unknown:")+16 || strings.ContainsAny(got[8:], "/ ") {
		t.Fatalf("UnreadableHash not bounded/sanitised: %q", got)
	}
}
