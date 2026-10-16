package bun

import (
	"strings"
	"testing"
)

// Red-team round 2.

const (
	pub512  = "sha512-qMlSxKbpRlAridDExk92nSobyDdpPijUq2DW6oDnUqd0iOGxmQjyqhMIihI9+zv4LPyZdRje2cavWPbCbWm3eA=="
	evil512 = "sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="
)

func coords(t *testing.T, lock string) []string {
	t.Helper()
	pkgs, err := Parse(strings.NewReader(lock))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, p := range pkgs {
		out = append(out, p.Name+"@"+p.Version+" "+p.Origin+" "+p.Hash)
	}
	return out
}

// TestDedupeKeepsHash (TestRT2BunDedupeDropsEvil): two copies of one
// name@version from one source with different integrity are two artifacts.
// Break it like this: drop Hash from the dedupe key.
func TestDedupeKeepsHash(t *testing.T) {
	got := coords(t, `{"lockfileVersion":1,"packages":{
"a/debug":["debug@4.3.4","",{},"`+pub512+`"],
"debug":["debug@4.3.4","",{},"`+evil512+`"],
"b/debug":["debug@4.3.4","",{},"`+pub512+`"]}}`)
	if len(got) != 2 {
		t.Fatalf("got %q, want the two distinct hashes", got)
	}
}

// TestPublicSwap: a full registry tarball URL — as the entry's source or in
// the registry slot — names the package fetched (re-keyed); a public URL
// that is not a tarball path is "url+<url>". Break it like this: Classify
// the URL alone.
func TestPublicSwap(t *testing.T) {
	got := coords(t, `{"lockfileVersion":1,"packages":{
"lodash":["lodash@https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",{"version":"4.17.21"}],
"chalk":["chalk@4.1.2","https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",{},"`+pub512+`"],
"ms":["ms@2.1.3","https://registry.npmjs.org/ms/-/ms-2.1.3.tgz",{},"`+pub512+`"],
"ok":["ok@https://registry.npmjs.org/ok/-/ok-1.0.0.tgz",{"version":"1.0.0"}],
"bare":["bare@https://registry.npmjs.org/bare",{"version":"1.0.0"}]}}`)
	want := map[string]string{
		"evil@1.0.0": "", // lodash and chalk both fetch evil-1.0.0.tgz
		"ms@2.1.3":   "",
		"ok@1.0.0":   "",
		"bare@1.0.0": "url+https://registry.npmjs.org/bare",
	}
	seen := map[string]bool{}
	for _, g := range got {
		f := strings.SplitN(g, " ", 3)
		if w, ok := want[f[0]]; !ok || w != f[1] {
			t.Errorf("%s: origin %q, want %q", f[0], f[1], w)
		}
		seen[f[0]] = true
	}
	if len(seen) != len(want) {
		t.Errorf("got %q, want %v", got, want)
	}
}
