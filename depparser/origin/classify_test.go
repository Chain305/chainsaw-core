package origin

import (
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
