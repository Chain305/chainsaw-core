package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/chain305/chainsaw-core/depparser/origin"
	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

const nrSHA = "0123456789abcdef0123456789abcdef01234567"

// nrSRI is a real-shaped npm integrity (sha512 of nothing in particular).
const nrSRI = "sha512-z4PhNX7vuL3xVChQ1m2AB9Yg5AULVxXcg/SpIdNs6c5H0NE8XYXysP+DGNKHfuwvY7kxvUdBeoGlODJ6+SfaPg=="

// TestNonRegistryPolicyFacts pins the three non_registry_sources facts on
// the guard's policy input (pr-scan shares setNonRegistryFacts).
func TestNonRegistryPolicyFacts(t *testing.T) {
	prev := viper.Get("registry_mirrors")
	t.Cleanup(func() { viper.Set("registry_mirrors", prev) })
	viper.Set("registry_mirrors", []any{"npm.mirror.example"})

	for name, tc := range map[string]struct {
		spec          packageSpec
		nonReg, unpin bool
		loc           string
	}{
		"registry":        {spec: packageSpec{Ecosystem: "npm", Name: "a", Version: "1.0.0"}},
		"local dir":       {spec: parseNpmSpec("a@file:../a")},
		"unparsed lock":   {spec: unparsedLockSpec("npm", "package-lock.json")},
		"declared mirror": {spec: packageSpec{Ecosystem: "npm", Name: "a", Version: "1.0.0", Origin: "registry+https://npm.mirror.example/a/-/a-1.0.0.tgz"}},
		"git pinned (lock)": {spec: packageSpec{Ecosystem: "npm", Name: "a", Version: "1.0.0", Origin: "git+ssh://git@github.com/myorg/a.git#" + nrSHA},
			nonReg: true, loc: "github.com/myorg/a"},
		"npm github:o/r#tag": {spec: parseNpmSpec("a@github:myorg/a#v1.2"), nonReg: true, unpin: true, loc: "github.com/myorg/a"},
		"pip git @tag":       {spec: parsePipSpec("a @ git+https://github.com/myorg/a@v1.0"), nonReg: true, unpin: true, loc: "github.com/myorg/a"},
		"cargo --git branch": {spec: packageSpec{Ecosystem: "cargo", Name: "a", Origin: "git+https://github.com/myorg/a?branch=main"}, nonReg: true, unpin: true, loc: "github.com/myorg/a"},
		"tarball + integrity": {spec: packageSpec{Ecosystem: "npm", Name: "b", Version: "1.0.0", Origin: "https://cdn.example.com/b-1.0.0.tgz", Hash: origin.JoinHashes(nrSRI)},
			nonReg: true, loc: "cdn.example.com/b-1.0.0.tgz"},
		"tarball no hash":  {spec: parseNpmSpec("b@https://cdn.example.com/b-1.0.0.tgz"), nonReg: true, unpin: true, loc: "cdn.example.com/b-1.0.0.tgz"},
		"vendored archive": {spec: parseNpmSpec("b@file:vendor/b-1.0.0.tgz"), nonReg: true, unpin: true, loc: "file:vendor/b-1.0.0.tgz"},
		"undeclared registry": {spec: packageSpec{Ecosystem: "npm", Name: "c", Version: "1.0.0", Origin: "registry+https://npm.corp.example/c/-/c-1.0.0.tgz", Hash: origin.JoinHashes(nrSRI)},
			nonReg: true, loc: "npm.corp.example/c/-/c-1.0.0.tgz"},
		"credentials stripped": {spec: packageSpec{Ecosystem: "npm", Name: "a", Origin: origin.Sanitize("git+https://user:s3cr3t@github.com/myorg/a.git#main")},
			nonReg: true, unpin: true, loc: "github.com/myorg/a"},
	} {
		t.Run(name, func(t *testing.T) {
			in := guardPolicyInput(tc.spec, acquireIncomplete, behavioralVerdict{})
			if in.NonRegistrySource != tc.nonReg || in.NonRegistrySourceUnpinned != tc.unpin || in.NonRegistryOrigin != tc.loc {
				t.Fatalf("origin %q hash %q: got nonRegistrySource=%v unpinned=%v origin=%q, want %v %v %q",
					tc.spec.Origin, tc.spec.Hash, in.NonRegistrySource, in.NonRegistrySourceUnpinned, in.NonRegistryOrigin, tc.nonReg, tc.unpin, tc.loc)
			}
			if strings.Contains(in.NonRegistryOrigin, "s3cr3t") {
				t.Fatalf("nonRegistryOrigin leaks a credential: %q", in.NonRegistryOrigin)
			}
		})
	}
}

// The documented recipe (docs/POLICY_PROXY_MATRIX.md#non-registry-sources
// and the Rego reference how-to, Example 4) with the test's allow-list:
// TestNonRegistryRecipeMatchesDocs keeps them identical. Closed refuses an
// unpinned source and a source off the allow-list; warn is the same pair
// as `monitor`.
const nonRegistryAllowLine = `non_registry_allowed := ["github.com/myorg/*", "cdn.example.com/*"]`

const nonRegistryClosedRego = `package chainsaw.policy

` + nonRegistryAllowLine + `

decision contains {
	"action":  "block",
	"rule_id": "org/non-registry-unpinned",
	"message": sprintf("%s is not pinned to a commit or a content hash", [split(input.nonRegistryOrigin, "/")[0]]),
} if {
	input.nonRegistrySource == true
	input.nonRegistrySourceUnpinned == true
}

decision contains {
	"action":  "block",
	"rule_id": "org/non-registry-origin",
	"message": sprintf("%s is not an allowed source", [split(input.nonRegistryOrigin, "/")[0]]),
} if {
	input.nonRegistrySource == true
	not non_registry_origin_allowed
}

non_registry_origin_allowed if {
	some p in non_registry_allowed
	glob.match(p, ["/"], input.nonRegistryOrigin)
}
`

func writeNonRegistryBundle(t *testing.T, action string) string {
	t.Helper()
	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "non_registry.rego"), strings.ReplaceAll(nonRegistryClosedRego, `"block"`, `"`+action+`"`))
	return dir
}

// nonRegistryLock is a package-lock.json v3 with one package of each shape.
const nonRegistryLock = `{
  "name": "app", "version": "1.0.0", "lockfileVersion": 3, "requires": true,
  "packages": {
    "": {"name": "app", "version": "1.0.0"},
    "node_modules/pinned-allowed": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/myorg/pinned-allowed.git#` + nrSHA + `"},
    "node_modules/tarball-hashed": {"version": "1.0.0", "resolved": "https://cdn.example.com/tarball-hashed-1.0.0.tgz", "integrity": "` + nrSRI + `"},
    "node_modules/pinned-offlist": {"version": "2.0.0", "resolved": "git+ssh://git@github.com/other/pinned-offlist.git#` + nrSHA + `"},
    "node_modules/tarball-unhashed": {"version": "1.0.0", "resolved": "https://cdn.example.com/tarball-unhashed-1.0.0.tgz"},
    "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz", "integrity": "` + nrSRI + `"}
  }
}`

// wantClosed: which lockfile package the closed recipe refuses, and by
// which rule ("" = not refused).
var wantClosed = map[string]string{
	"pinned-allowed":   "",
	"tarball-hashed":   "",
	"pinned-offlist":   "org/non-registry-origin",
	"tarball-unhashed": "org/non-registry-unpinned",
	"left-pad":         "",
}

// TestNonRegistryClosedRecipeGuard: the install guard, fed the lockfile
// through the same parser `npm ci` uses, refuses exactly the unpinned and
// off-list packages.
func TestNonRegistryClosedRecipeGuard(t *testing.T) {
	guardPolicyTestEnv(t, writeNonRegistryBundle(t, "block"))
	reg, nonReg, err := parsePackageLockCoordinates([]byte(nonRegistryLock))
	if err != nil {
		t.Fatal(err)
	}
	g := &localGuard{detectors: map[string]*typosquat.Detector{}, malware: malware.NewIndex(nil)}
	seen := 0
	for _, spec := range npmLockSpecs(reg, nonReg) {
		rule, ok := wantClosed[spec.Name]
		if !ok {
			t.Fatalf("unexpected spec %+v", spec)
		}
		seen++
		var v guardVerdict
		if spec.Origin == "" {
			// A registry package: only the policy lane is under test here.
			v, _ = guardPolicyLane(context.Background(), spec, acquireIncomplete, behavioralVerdict{})
		} else {
			v = g.evaluateNonRegistry(context.Background(), spec)
		}
		switch {
		case rule == "" && v.Block:
			t.Errorf("%s (%s): refused, want allowed: %s", spec.Name, spec.Origin, v.Reason)
		case rule != "" && (!v.Block || !strings.Contains(v.Reason, rule)):
			t.Errorf("%s (%s): want refused by %s, got block=%v %q", spec.Name, spec.Origin, rule, v.Block, v.Reason)
		}
	}
	if seen != len(wantClosed) {
		t.Fatalf("lockfile produced %d specs, want %d", seen, len(wantClosed))
	}
}

// TestNonRegistryRecipesPRScan: pr-scan on the same lockfile — closed
// blocks exactly the unpinned and off-list rows, warn (action monitor)
// raises the same two to a named warn row and blocks nothing.
func TestNonRegistryRecipesPRScan(t *testing.T) {
	for _, action := range []string{"block", "monitor"} {
		t.Run(action, func(t *testing.T) {
			prScanPolicyTestEnv(t, writeNonRegistryBundle(t, action))
			added, _, err := diffManifest(kindNPMPackageLock, "package-lock.json", nil, []byte(nonRegistryLock))
			if err != nil {
				t.Fatal(err)
			}
			if len(added) != len(wantClosed) {
				t.Fatalf("diff produced %d rows, want %d: %+v", len(added), len(wantClosed), added)
			}
			for _, e := range added {
				row := evaluatePREntry(e)
				rule := wantClosed[e.Name]
				var fired *prScanSignal
				for i, s := range row.Signals {
					if strings.HasPrefix(s.ID, prScanPolicySignalPrefix) {
						fired = &row.Signals[i]
					}
				}
				switch {
				case rule == "" && fired != nil:
					t.Errorf("%s: policy row %+v, want none", e.Name, *fired)
				case rule != "" && (fired == nil || fired.ID != prScanPolicySignalPrefix+rule):
					t.Errorf("%s: want policy row %s, got %+v", e.Name, rule, row.Signals)
				case rule != "" && action == "block" && row.Verdict != "block":
					t.Errorf("%s: closed recipe must block, verdict %q", e.Name, row.Verdict)
				case action == "monitor" && row.Verdict == "block":
					t.Errorf("%s: warn recipe must never block, verdict %q", e.Name, row.Verdict)
				case fired != nil && (strings.Contains(fired.Reason, ".tgz") || strings.Contains(fired.Reason, "/other")):
					// The recipe prints the origin's host only: a registry
					// path can carry an access token.
					t.Errorf("%s: policy message %q prints the origin path", e.Name, fired.Reason)
				}
			}
		})
	}
}

// TestNonRegistryCargoLockHashPins: a Cargo.lock package from an undeclared
// registry is pinned by its checksum; without one it is not.
func TestNonRegistryCargoLockHashPins(t *testing.T) {
	lock := `version = 3

[[package]]
name = "private-hashed"
version = "1.0.0"
source = "sparse+https://cargo.corp.example/index/"
checksum = "` + strings.Repeat("ab", 32) + `"

[[package]]
name = "private-unhashed"
version = "1.0.0"
source = "sparse+https://cargo.corp.example/index/"
`
	_, nonReg, _ := parseCargoLock([]byte(lock))
	if len(nonReg) != 2 {
		t.Fatalf("want 2 non-registry crates, got %+v", nonReg)
	}
	for _, d := range nonReg {
		in := prScanPolicyInput(rawEntry{Ecosystem: "cargo", Name: d.Name, Version: d.Version, Origin: d.Origin, Hash: d.Hash}, nil)
		want := d.Name == "private-unhashed"
		if !in.NonRegistrySource || in.NonRegistrySourceUnpinned != want || in.NonRegistryOrigin != "cargo.corp.example/index" {
			t.Errorf("%s: got %+v, want nonRegistrySource, unpinned=%v, origin cargo.corp.example/index", d.Name, in, want)
		}
	}
}

// TestNonRegistryRecipeMatchesDocs: the recipe the docs publish is the one
// the tests above run, apart from the allow-list line. Monorepo-only (the
// docs are not in the open-core checkout): skipped when absent.
func TestNonRegistryRecipeMatchesDocs(t *testing.T) {
	allowLine := regexp.MustCompile(`(?m)^non_registry_allowed := \[.*\]$`)
	want := allowLine.ReplaceAllString(nonRegistryClosedRego, "ALLOW")
	found := 0
	for _, rel := range []string{
		"docs/POLICY_PROXY_MATRIX.md",
		"how-tos-site/content/policy-enforcement/70-policy-dsl-rego-reference.md",
		"internal/server/howtos/tutorials/70-policy-dsl-rego-reference.md",
	} {
		data, ok := readAboveCLI(rel)
		if !ok {
			continue
		}
		found++
		var recipe string
		for _, block := range strings.Split(string(data), "```rego\n")[1:] {
			block, _, _ = strings.Cut(block, "```")
			if strings.Contains(block, "org/non-registry-origin") {
				recipe = block
			}
		}
		if recipe == "" {
			t.Errorf("%s: no non-registry recipe block", rel)
			continue
		}
		if got := allowLine.ReplaceAllString(recipe, "ALLOW"); got != want {
			t.Errorf("%s: published recipe differs from the tested one:\n%s\n--- tested ---\n%s", rel, got, want)
		}
	}
	if found == 0 {
		t.Skip("docs not found above the package — open-core checkout")
	}
}

func readAboveCLI(rel string) ([]byte, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, false
	}
	for i := 0; i < 6; i++ {
		if data, err := os.ReadFile(filepath.Join(dir, rel)); err == nil {
			return data, true
		}
		dir = filepath.Dir(dir)
	}
	return nil, false
}

// TestNonRegistryMonitorRecipeGuard: with the recipe in monitor mode the
// guard refuses nothing, and the rule that fired rides along on the
// not-assessed verdict as its own "! policy" line (it was dropped before:
// evaluateNonRegistry kept only a blocking policy verdict). Break it like
// this: drop the PolicySeverity ride-along in evaluateNonRegistry.
func TestNonRegistryMonitorRecipeGuard(t *testing.T) {
	guardPolicyTestEnv(t, writeNonRegistryBundle(t, "monitor"))
	reg, nonReg, err := parsePackageLockCoordinates([]byte(nonRegistryLock))
	if err != nil {
		t.Fatal(err)
	}
	g := &localGuard{detectors: map[string]*typosquat.Detector{}, malware: malware.NewIndex(nil)}
	var verdicts []guardVerdict
	for _, spec := range npmLockSpecs(reg, nonReg) {
		if spec.Origin == "" {
			continue
		}
		v := g.evaluateNonRegistry(context.Background(), spec)
		if v.Block {
			t.Errorf("%s: refused in monitor mode: %s", spec.Name, v.Reason)
		}
		if rule := wantClosed[spec.Name]; rule != "" && !strings.Contains(v.PolicyReason, rule) {
			t.Errorf("%s: monitor rule %s not carried (PolicyReason %q)", spec.Name, rule, v.PolicyReason)
		}
		verdicts = append(verdicts, v)
	}
	var buf bytes.Buffer
	printGuardVerdicts(&buf, "chainsaw", verdicts, true)
	if !strings.Contains(buf.String(), "! policy") {
		t.Errorf("no policy line printed:\n%s", buf.String())
	}
}

// TestNonRegistryBackslashHost (red-team P1c C1/C2/C4): npm reads "\" as
// "/" in an http(s) URL, so https://evil.invalid\@github.com/… is fetched
// from evil.invalid; net/url alone reads github.com. The command line, the
// lockfile and the own-repository check must all see evil.invalid, and the
// allow-list must not match it.
func TestNonRegistryBackslashHost(t *testing.T) {
	for _, k := range []string{"server_url", "org_slug"} {
		prev := viper.Get(k)
		t.Cleanup(func() { viper.Set(k, prev) })
	}
	viper.Set("server_url", "https://chain305.com/chainproxy")
	viper.Set("org_slug", "myorg")

	check := func(what, o, hash string) {
		t.Helper()
		var in policyInputFacts
		in.set("npm", o, hash)
		if !strings.Contains(o, "evil.invalid") || !in.NonRegistrySource || origin.MatchLocation("github.com/myorg/*", in.NonRegistryOrigin) ||
			origin.MatchLocation("registry.npmjs.org/**", in.NonRegistryOrigin) {
			t.Errorf("%s: origin %q nonRegistrySource=%v location %q (want evil.invalid, non-registry, off the allow-list)",
				what, o, in.NonRegistrySource, in.NonRegistryOrigin)
		}
	}
	for _, a := range []string{
		`x@https://evil.invalid\@registry.npmjs.org/lodash/-/lodash-4.17.21.tgz`,
		`https://evil.invalid\@registry.npmjs.org/lodash/-/lodash-4.17.21.tgz`,
		`x@https://evil.invalid\@github.com/myorg/x.tgz`,
	} {
		s := parseNpmSpec(a)
		check(a, s.Origin, s.Hash)
	}
	lock := []byte(`{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
"":{"name":"app","version":"1.0.0"},
"node_modules/x":{"version":"1.0.0","resolved":"https://evil.invalid\\@github.com/myorg/x.tgz","integrity":"` + nrSRI + `"},
"node_modules/lodash":{"version":"4.17.21","resolved":"https://evil.invalid\\@registry.npmjs.org/lodash/-/lodash-4.17.21.tgz","integrity":"` + nrSRI + `"}
}}`)
	reg, nonReg, err := parsePackageLockCoordinates(lock)
	if err != nil || len(reg) != 0 || len(nonReg) != 2 {
		t.Fatalf("lockfile: err=%v registry=%+v non-registry=%+v (want both non-registry)", err, reg, nonReg)
	}
	for _, d := range nonReg {
		check("lockfile "+d.Name, d.Origin, d.Hash)
	}
	for _, o := range []string{
		`https://chain305.com/chainproxy/repository/@myorg/..\@attacker/x/-/x-1.0.0.tgz`,
	} {
		if knownRegistry("npm", o) || npmOriginIsRegistry(o) {
			t.Errorf("%s: read as the org's own Chainsaw repository", o)
		}
	}
	if !knownRegistry("npm", "https://chain305.com/chainproxy/repository/@myorg/npm/x/-/x-1.0.0.tgz") {
		t.Errorf("the org's own repository is no longer recognised")
	}
	// C2: a vendored archive named like a host is not that host.
	var in policyInputFacts
	in.set("npm", "file:github.com/myorg/x.tgz", "")
	if !in.NonRegistrySource || origin.MatchLocation("github.com/myorg/*", in.NonRegistryOrigin) {
		t.Errorf("vendored archive: %+v matches github.com/myorg/*", in)
	}
	// C4: cargo install --git --rev <full sha> is pinned; a branch is not.
	for rev, want := range map[string]bool{nrSHA: true, "main": false, "0123456": false} {
		specs, _ := parseCargoInstall([]string{"install", "foo", "--git", "https://github.com/myorg/foo", "--rev", rev})
		if len(specs) != 1 || origin.Pinned(specs[0].Origin, "") != want {
			t.Errorf("cargo install --rev %s: %+v, want pinned=%v", rev, specs, want)
		}
	}
}

// policyInputFacts is the three facts setNonRegistryFacts writes.
type policyInputFacts struct {
	NonRegistrySource, NonRegistrySourceUnpinned bool
	NonRegistryOrigin                            string
}

func (f *policyInputFacts) set(eco, o, hash string) {
	in := prScanPolicyInput(rawEntry{Ecosystem: eco, Name: "x", Version: "1.0.0", Origin: o, Hash: hash}, nil)
	f.NonRegistrySource, f.NonRegistrySourceUnpinned, f.NonRegistryOrigin = in.NonRegistrySource, in.NonRegistrySourceUnpinned, in.NonRegistryOrigin
}

// TestNonRegistryLabelsHideRegistryPaths (red-team P1c): a private
// registry's access token rides in the URL path (dl.cloudsmith.io/<token>/…)
// where Sanitize cannot see it, so pr-scan's not-assessed and
// source-changed reasons print a registry or URL source by host only; a git
// source keeps its repository and ref, which is what a reviewer needs.
// Break it like this: print origin.Label in nonRegistryReason or sourceLabel.
func TestNonRegistryLabelsHideRegistryPaths(t *testing.T) {
	const tok = "s3cr3tTOK"
	lock := func(resolved string) []byte {
		return []byte(`{"name":"app","version":"1.0.0","lockfileVersion":3,"requires":true,"packages":{
"":{"name":"app","version":"1.0.0"},
"node_modules/x":{"version":"1.0.0","resolved":"` + resolved + `","integrity":"` + nrSRI + `"}}}`)
	}
	added, upgraded, err := diffManifest(kindNPMPackageLock, "package-lock.json",
		lock("https://registry.npmjs.org/x/-/x-1.0.0.tgz"),
		lock("https://dl.cloudsmith.io/"+tok+"/acme/repo/npm/x/-/x-1.0.0.tgz"))
	if err != nil || len(added)+len(upgraded) != 1 {
		t.Fatalf("diff: err=%v added=%+v upgraded=%+v", err, added, upgraded)
	}
	row := evaluatePREntry(append(added, upgraded...)[0])
	var reasons []string
	for _, s := range row.Signals {
		reasons = append(reasons, s.Reason)
	}
	all := strings.Join(reasons, " | ")
	if strings.Contains(all, tok) || !strings.Contains(all, "source changed: the public registry → dl.cloudsmith.io") ||
		!strings.Contains(all, "not assessed (dl.cloudsmith.io)") {
		t.Errorf("reasons %q: want host-only labels, no token", all)
	}
	if r := nonRegistryReason("cargo", "git+https://github.com/feldera/etl?rev=cdfb3c7e#"+nrSHA); !strings.Contains(r, "(github.com/feldera/etl@0123456)") {
		t.Errorf("git reason %q lost its repository and ref", r)
	}
}
