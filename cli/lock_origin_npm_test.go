package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

// P1b npm (docs/PLANS_INTELLIGENCE.md#plan-non-registry-sources): the guard
// and pr-scan read package-lock.json / npm-shrinkwrap.json through
// core/depparser, so a git, tarball or undeclared-registry package is never
// checked as its npm namesake, a workspace member is first-party, and an
// alias is its real package. Entries are real-format (npm 10 v3).
const guardOriginPackageLock = `{
  "name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": {"name": "app", "version": "1.0.0", "workspaces": ["packages/*"]},
    "node_modules/evil": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/evil/-/evil-1.0.0.tgz",
      "integrity": "sha512-v2kDEe57lecTulaDIuNTPy3Ry4gLGJ6Z1O3vE1krgXZNrsQ+LFTGHVxVjcXPs17LhbZVGedAJv8XZ1tvj5FvSg=="},
    "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
      "integrity": "sha512-6FlzubTLZG3J2a/NVCAleEhjzq5oxgHyaCU9yYXvcLsvoVaHJq/s5xXI6/XXP6tz7R9xAOtHnSO/tXtF3WRTlA=="},
    "node_modules/x/node_modules/left-pad": {"version": "1.3.0",
      "resolved": "git+ssh://git@github.com/fork/left-pad.git#0123456789abcdef0123456789abcdef01234567"},
    "node_modules/react-is-18": {"name": "react-is", "version": "18.3.1",
      "resolved": "https://registry.npmjs.org/react-is/-/react-is-18.3.1.tgz",
      "integrity": "sha512-/LLMVyas0ljjAtoYiPqYiL8VWXzUUdThrmU5+n20DZv+a+ClRoevUzw5JxU+Ieh5/c87ytoTBV9G1FiKfNJdmg=="},
    "node_modules/etl-js": {"version": "0.2.0",
      "resolved": "https://github.com/acme/etl-js/releases/download/v0.2.0/etl-js-0.2.0.tgz"},
    "node_modules/mirrored": {"version": "2.0.0",
      "resolved": "https://artifactory.example.com/artifactory/api/npm/npm-remote/mirrored/-/mirrored-2.0.0.tgz",
      "integrity": "sha512-EykJT/Q1KjTWctppgIAgfSO0tKVuZUjhgMr17kqTumMl6Afv3EISleU7qZUzoXDFTAHTDC4NOoG/ZxU3EvlMPQ=="},
    "node_modules/ws-app": {"resolved": "packages/ws-app", "link": true},
    "packages/ws-app": {"version": "0.1.0"},
    "node_modules/evil-ws": {"resolved": "packages/evil-ws", "link": true},
    "packages/evil-ws": {"version": "1.0.0"}
  }
}`

func npmOriginMalwareIndex() *malware.Index {
	idx := malware.NewIndex(nil)
	mal := func(name, ver string) *malware.OSVEntry {
		return &malware.OSVEntry{ID: "MAL-TEST-" + name, Affected: []malware.OSVAffected{{
			Package: malware.OSVPackage{Ecosystem: "npm", Name: name}, Versions: []string{ver}}}}
	}
	idx.Load([]*malware.OSVEntry{mal("evil", "1.0.0"), mal("evil-ws", "1.0.0")})
	return idx
}

func npmOriginChdir(t *testing.T) string {
	dir := guardOriginChdir(t)
	t.Setenv("npm_config_cache", filepath.Join(dir, "npm-cache")) // byte acquisition off the real cache
	return dir
}

func TestGuardPackageLockOrigins(t *testing.T) {
	for _, file := range []string{"package-lock.json", "npm-shrinkwrap.json"} {
		t.Run(file, func(t *testing.T) {
			dir := npmOriginChdir(t)
			if err := os.WriteFile(filepath.Join(dir, file), []byte(guardOriginPackageLock), 0o644); err != nil {
				t.Fatal(err)
			}
			specs := expandLockfile("npm", []string{"ci"})
			g := &localGuard{detectors: map[string]*typosquat.Detector{}, malware: npmOriginMalwareIndex()}
			verdicts, blocked := g.evaluateAll(context.Background(), specs)
			if !blocked {
				t.Fatal("evil is malicious in the index; the install must be refused")
			}
			got := map[string]int{}
			for _, v := range verdicts {
				switch {
				case v.Severity == "malicious":
					got["mal:"+v.Spec.Name]++
				case v.Severity == "" && !v.Block:
					got["clean:"+v.Spec.Name]++
				case v.Severity == guardSeverityNotAssessed && !v.Block:
					got["na:"+v.Spec.Name]++
					if v.Spec.Name == "mirrored" && !strings.Contains(v.Reason, "registry_mirrors") {
						t.Errorf("an undeclared registry must say how to declare it: %q", v.Reason)
					}
				default:
					t.Errorf("unexpected verdict %+v", v)
				}
				if v.Spec.Name == "evil-ws" && !strings.Contains(v.Reason, "local/workspace package") {
					t.Errorf("evil-ws reason %q should say the lockfile lists it as local", v.Reason)
				}
			}
			want := map[string]int{
				"mal:evil": 1, "mal:evil-ws": 1, // a workspace member keeps the malware floor
				"clean:left-pad": 1, "clean:react-is": 1, // the alias is its real package
				"na:left-pad": 1, "na:etl-js": 1, "na:mirrored": 1, // the fork does not borrow the clean verdict
			}
			if len(got) != len(want) {
				t.Errorf("verdicts %v, want %v", got, want)
			}
			for k, n := range want {
				if got[k] != n {
					t.Errorf("%s = %d, want %d (all %v)", k, got[k], n, got)
				}
			}
			var buf bytes.Buffer
			printGuardVerdicts(&buf, "chainsaw", verdicts, false)
			if strings.Contains(buf.String(), "ws-app") {
				t.Errorf("a clean workspace member must produce no output:\n%s", buf.String())
			}
			// Only registry specs reach byte acquisition.
			clean := &localGuard{detectors: map[string]*typosquat.Detector{}, malware: malware.NewIndex(nil)}
			clean.evaluateAll(context.Background(), specs)
			if clean.scanAttempted != 3 { // evil, left-pad, react-is
				t.Errorf("specs reaching byte acquisition = %d, want 3", clean.scanAttempted)
			}
		})
	}
}

// A declared registry_mirrors host is the registry: checked, with the
// lockfile's integrity as its byte anchor.
func TestGuardPackageLockDeclaredMirror(t *testing.T) {
	dir := npmOriginChdir(t)
	prev := viper.Get("registry_mirrors")
	t.Cleanup(func() { viper.Set("registry_mirrors", prev) })
	viper.Set("registry_mirrors", []any{"artifactory.example.com"})
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(guardOriginPackageLock), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, s := range expandLockfile("npm", []string{"ci"}) {
		if s.Name != "mirrored" {
			continue
		}
		if s.Origin != "" || s.Integrity != "sha512-EykJT/Q1KjTWctppgIAgfSO0tKVuZUjhgMr17kqTumMl6Afv3EISleU7qZUzoXDFTAHTDC4NOoG/ZxU3EvlMPQ==" {
			t.Fatalf("declared mirror spec = %+v, want a registry spec with its integrity", s)
		}
		return
	}
	t.Fatal("mirrored missing")
}

func TestPRScanPackageLockOrigins(t *testing.T) {
	for _, kind := range []manifestKind{kindNPMPackageLock, kindNPMShrinkwrap} {
		added, upgraded, err := diffManifest(kind, "lock", nil, []byte(guardOriginPackageLock))
		if err != nil || len(upgraded) != 0 {
			t.Fatalf("diffManifest: err=%v upgraded=%v", err, upgraded)
		}
		got := map[string]int{}
		for _, raw := range added {
			e := evaluatePREntry(raw)
			if e.Origin == "" {
				got["reg:"+e.Name]++
				continue
			}
			got["na:"+e.Name]++
			if e.Verdict == "allow" || e.Signals[0].ID != prScanNotAssessedSignalID {
				t.Errorf("%s: a not-assessed row must lead with %s and never allow: %+v", e.Name, prScanNotAssessedSignalID, e)
			}
		}
		want := map[string]int{
			"reg:evil": 1, "reg:left-pad": 1, "reg:react-is": 1,
			"na:left-pad": 1, "na:etl-js": 1, "na:mirrored": 1,
		}
		if len(got) != len(want) {
			t.Errorf("%s: rows %v, want %v (workspace members are first-party: no row)", kind, got, want)
		}
		for k, n := range want {
			if got[k] != n {
				t.Errorf("%s: %s = %d, want %d (all %v)", kind, k, got[k], n, got)
			}
		}
	}
}

// A v1 lockfile (npm 5/6) records a git/file/URL dependency's spec as its
// version, and an alias as "npm:<real>@<version>": none of those is a
// registry row.
func TestPRScanPackageLockV1Specs(t *testing.T) {
	const lock = `{"lockfileVersion": 1, "dependencies": {
	  "lodash": {"version": "4.17.21", "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"},
	  "old-ms": {"version": "npm:ms@2.0.0", "resolved": "https://registry.npmjs.org/ms/-/ms-2.0.0.tgz"},
	  "lamejs": {"version": "github:zhuker/lamejs#582bbba6a12f981b984d8fb9e1874499fed85675"},
	  "local-dir": {"version": "file:localdir"}
	}}`
	added, _, err := diffManifest(kindNPMPackageLock, "lock", nil, []byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range added {
		got[e.Name+"@"+e.Version] = e.Origin
	}
	want := map[string]string{"lodash@4.17.21": "", "ms@2.0.0": "", "lamejs@": "github:zhuker/lamejs#582bbba6a12f981b984d8fb9e1874499fed85675"}
	if len(got) != len(want) {
		t.Fatalf("rows %v, want %v", got, want)
	}
	for k, o := range want {
		if g, ok := got[k]; !ok || g != o {
			t.Errorf("%s origin = %q (present %v), want %q", k, g, ok, o)
		}
	}
}
