package bun

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/depparser/origin"
	ftypes "github.com/chain305/chainsaw-core/fanal"
)

// Entries copied from SeismicSystems/seismic-starter's bun.lock (corpus),
// plus the corpus gate's mirror rewrites of a registry entry (the registry
// slot set to a Chainsaw proxy or Artifactory registry root), a registry
// tarball URL as Bun records one for a non-default registry, an alias, a git
// URL carrying a credential, and a vendored tarball.
const lockOrigins = `{
  "lockfileVersion": 1,
  "workspaces": {
    "": { "name": "seismic-starter" },
    "packages/cli": { "name": "walnut-cli" },
    "packages/web": { "name": "seismic-starter-web", "version": "0.0.0" },
  },
  "packages": {
    "@babel/helper-string-parser": ["@babel/helper-string-parser@7.27.1", "", {}, "sha512-qMlSxKbpRlAridDExk92nSobyDdpPijUq2DW6oDnUqd0iOGxmQjyqhMIihI9+zv4LPyZdRje2cavWPbCbWm3eA=="],
    "seismic-client": ["seismic-client@github:SeismicSystems/seismic-client#47f16b8", { "dependencies": { "caniuse-lite": "^1.0.30001751" } }, "SeismicSystems-seismic-client-47f16b8", "sha512-RMrfZQ4MVkbTws8GVLNfh/WJ+dCZJsPg+la+sBKEpjpKMCGgkXId8CtnvmX/2O/nnXg9hbYPtAwr1NprpMxnEQ=="],
    "seismic-starter-web": ["seismic-starter-web@workspace:packages/web"],
    "walnut-cli": ["walnut-cli@workspace:packages/cli"],
    "via-proxy": ["via-proxy@1.0.0", "https://chain305.com/chainproxy/repository/@acme/npmjs/", {}, "sha512-qMlSxKbpRlAridDExk92nSobyDdpPijUq2DW6oDnUqd0iOGxmQjyqhMIihI9+zv4LPyZdRje2cavWPbCbWm3eA=="],
    "@s/via-artifactory": ["@s/via-artifactory@2.0.0", "https://artifactory.example.com/artifactory/api/npm/npm-remote/", {}, "sha1-VgiurfwAvmwpAd9fmGF4jeDVl8g= sha512-qMlSxKbpRlAridDExk92nSobyDdpPijUq2DW6oDnUqd0iOGxmQjyqhMIihI9+zv4LPyZdRje2cavWPbCbWm3eA=="],
    "@acme/private": ["@acme/private@3.0.0", "https://npm.pkg.github.com/download/@acme/private/3.0.0/0123abcd", {}, "sha512-qMlSxKbpRlAridDExk92nSobyDdpPijUq2DW6oDnUqd0iOGxmQjyqhMIihI9+zv4LPyZdRje2cavWPbCbWm3eA=="],
    "aliased": ["real-pkg@4.0.0", "", {},"sha512-qMlSxKbpRlAridDExk92nSobyDdpPijUq2DW6oDnUqd0iOGxmQjyqhMIihI9+zv4LPyZdRje2cavWPbCbWm3eA=="],
    "secret": ["secret@git+https://ci:tok@github.com/acme/secret.git#abc1234", {}, "acme-secret-abc1234"],
    "vendored": ["vendored@file:vend/vendored-0.1.0.tgz", {}],
  },
}`

func TestParseOrigins(t *testing.T) {
	h := origin.NormalizeHash("sha512-qMlSxKbpRlAridDExk92nSobyDdpPijUq2DW6oDnUqd0iOGxmQjyqhMIihI9+zv4LPyZdRje2cavWPbCbWm3eA==")
	want := render([]ftypes.Package{
		{Name: "@babel/helper-string-parser", Version: "7.27.1", Hash: h},
		// git: no version recorded; the git tarball integrity is not a
		// registry artifact hash and is not kept.
		{Name: "seismic-client", Origin: "github:SeismicSystems/seismic-client#47f16b8"},
		// workspace member with a version: local Origin; walnut-cli has none.
		{Name: "seismic-starter-web", Version: "0.0.0", Origin: "file:packages/web"},
		{Name: "via-proxy", Version: "1.0.0", Hash: h,
			Origin: "https://chain305.com/chainproxy/repository/@acme/npmjs/via-proxy/-/via-proxy-1.0.0.tgz"},
		{Name: "@s/via-artifactory", Version: "2.0.0", Hash: "sha1:5608aeadfc00be6c2901df5f9861788de0d597c8 " + h, // every SRI token
			Origin: "https://artifactory.example.com/artifactory/api/npm/npm-remote/@s/via-artifactory/-/via-artifactory-2.0.0.tgz"},
		{Name: "@acme/private", Version: "3.0.0", Hash: h,
			Origin: "https://npm.pkg.github.com/download/@acme/private/3.0.0/0123abcd"},
		{Name: "real-pkg", Version: "4.0.0", Hash: h},
		{Name: "secret", Origin: "git+https://github.com/acme/secret.git#abc1234"},
		{Name: "vendored", Origin: "file:vend/vendored-0.1.0.tgz"},
	})
	pkgs, err := Parse(strings.NewReader(lockOrigins))
	if err != nil {
		t.Fatal(err)
	}
	if got := render(pkgs); !reflect.DeepEqual(got, want) {
		t.Fatalf("got:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	for _, p := range pkgs {
		want := origin.NonRegistry
		switch p.Name {
		case "via-proxy", "@s/via-artifactory":
			want = origin.RegistryOther
		case "@babel/helper-string-parser", "real-pkg":
			want = origin.Public
		}
		if c := origin.Classify("npm", p.Origin); c != want {
			t.Errorf("%s: Classify(%q) = %v, want %v", p.Name, p.Origin, c, want)
		}
	}
}

func render(pkgs []ftypes.Package) []string {
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		out = append(out, fmt.Sprintf("%s@%s origin=%q hash=%q", p.Name, p.Version, p.Origin, p.Hash))
	}
	sort.Strings(out)
	return out
}
