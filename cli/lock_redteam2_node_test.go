package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

// Red-team round 2, JavaScript lockfiles, CLI side.

// TestGuardPartialLockfileStillChecked (TestRT2GuardUnparsedTypeMismatch):
// `"dev": 1` is a lockfile npm installs (arborist tests truthiness); the
// strict decode failed the whole file and the guard replaced the tree with
// one non-blocking "not assessed" spec, so event-stream@3.3.6 was never
// looked up. It now parses, and a file that genuinely fails in one entry
// keeps every entry that parsed beside the unparsed marker. Break it like
// this: make lockPackage.Dev a bool again, or return only the marker on a
// parse error in expandLockfile.
func TestGuardPartialLockfileStillChecked(t *testing.T) {
	idx := malware.NewIndex(nil)
	idx.Load([]*malware.OSVEntry{{ID: "MAL-TEST-event-stream", Affected: []malware.OSVAffected{{
		Package: malware.OSVPackage{Ecosystem: "npm", Name: "event-stream"}, Versions: []string{"3.3.6"}}}}})
	for _, tc := range []struct {
		name, lock string
		marker     bool
	}{
		{"dev-is-a-number", `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"},
"node_modules/event-stream":{"version":"3.3.6","resolved":"https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz"},
"node_modules/x":{"version":"1.0.0","dev":1,"link":0}}}`, false},
		{"one-entry-unreadable", `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"},
"node_modules/event-stream":{"version":"3.3.6","resolved":"https://registry.npmjs.org/event-stream/-/event-stream-3.3.6.tgz"},
"node_modules/x":7}}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := guardOriginChdir(t)
			if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(tc.lock), 0o644); err != nil {
				t.Fatal(err)
			}
			specs := expandLockfile("npm", []string{"ci"})
			var found, marker bool
			for _, s := range specs {
				found = found || (s.Name == "event-stream" && s.Version == "3.3.6" && s.Origin == "")
				marker = marker || s.Origin == unparsedLockPrefix+"package-lock.json"
			}
			if !found || marker != tc.marker {
				t.Fatalf("specs = %+v: want event-stream@3.3.6 as a registry spec, unparsed marker=%v", specs, tc.marker)
			}
			g := &localGuard{detectors: map[string]*typosquat.Detector{}, malware: idx}
			if _, blocked := g.evaluateAll(context.Background(), specs); !blocked {
				t.Fatal("known-malicious event-stream@3.3.6 was not blocked")
			}
		})
	}
}

// TestNpmTarballURLDecidesTheCoordinate: `resolved` is what npm fetches. A
// registry tarball path names the package, so pr-scan's name->version map,
// its depparser rows and the guard (same parser) all key node_modules/lodash
// resolved to evil-1.0.0.tgz as evil@1.0.0, never lodash; a public URL that
// is not a tarball path is a url+ non-registry row, never the namesake.
// Break it like this: check npmOriginIsRegistry(pkg.Resolved) again, or
// drop the re-key in parsePackageLockIntegrityJSONMode.
func TestNpmTarballURLDecidesTheCoordinate(t *testing.T) {
	lock := `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"},
"node_modules/lodash":{"version":"4.17.21","resolved":"https://registry.npmjs.org/evil/-/evil-1.0.0.tgz","integrity":"sha512-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="},
"node_modules/bare":{"version":"1.0.0","resolved":"https://registry.npmjs.org/bare"},
"node_modules/@babel/core":{"version":"7.22.0","resolved":"https://registry.npmjs.org/@babel/core/-/core-7.22.0.tgz"},
"node_modules/al":{"name":"chalk","version":"4.1.2","resolved":"https://registry.yarnpkg.com/chalk/-/chalk-4.1.2.tgz"}}}`
	versions, err := parsePackageLockJSON([]byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"evil": "1.0.0", "@babel/core": "7.22.0", "chalk": "4.1.2"}
	if len(versions) != len(want) {
		t.Errorf("pr-scan map = %v, want %v", versions, want)
	}
	for n, v := range want {
		if versions[n] != v {
			t.Errorf("pr-scan map = %v, want %v", versions, want)
		}
	}
	reg, nonReg, err := parsePackageLockCoordinates([]byte(lock))
	if err != nil || len(nonReg) != 1 || nonReg[0].Name != "bare" || nonReg[0].Origin != "url+https://registry.npmjs.org/bare" {
		t.Fatalf("nonReg = %+v err=%v, want bare with a url+ Origin", nonReg, err)
	}
	var keys []string
	for _, c := range reg {
		keys = append(keys, c.Name+"@"+c.Version)
	}
	if strings.Join(keys, " ") != "@babel/core@7.22.0 chalk@4.1.2 evil@1.0.0" {
		t.Errorf("guard registry coordinates = %v, want the same set as pr-scan", keys)
	}
}

// TestHashToSRIUnreadableIsNoAnchor: "sha1-<public> sha224-<evil>" must not
// become a sha1 anchor; npm verifies sha224. Break it like this: skip
// unreadable tokens instead of returning "".
func TestHashToSRIUnreadableIsNoAnchor(t *testing.T) {
	if got := hashToSRI("sha1:5608aeadfc00be6c2901df5f9861788de0d597c8 unknown:sha224"); got != "" {
		t.Fatalf("hashToSRI = %q, want no anchor", got)
	}
	if got := hashToSRI("sha1:5608aeadfc00be6c2901df5f9861788de0d597c8"); got != "sha1-VgiurfwAvmwpAd9fmGF4jeDVl8g=" {
		t.Fatalf("hashToSRI(sha1) = %q", got)
	}
}
