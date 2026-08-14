package npm

// Tests run against REAL npm-emitted lockfiles under testdata/. They were
// produced by `npm install --package-lock-only --no-audit --no-fund` (npm
// 10.x) in a scratch directory, not hand-written — a hand-written fixture is
// exactly how the v2/v3 decode bug survived unnoticed:
//
//	lockPackage.Dependencies was typed map[string]v1Dep, but in a real v2/v3
//	lockfile every packages[<path>].dependencies VALUE is a semver range
//	STRING. encoding/json returned an UnmarshalTypeError and Parse discarded
//	the entire (otherwise fully decoded) lockfile. npm mirrors package.json's
//	runtime "dependencies" into the root packages[""] entry, so this fired for
//	every project declaring at least one runtime dependency.
//
// Regenerate with scripts equivalent to:
//
//	mkdir -p /tmp/fx && cd /tmp/fx
//	printf '{"name":"fixture-runtime","version":"1.0.0","dependencies":{"lodash":"4.17.21"}}' > package.json
//	npm install --package-lock-only --no-audit --no-fund

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	ftypes "github.com/chain305/chainsaw-core/fanal"
)

type wantPkg struct {
	name    string
	version string
	dev     bool
}

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		file string
		// want is the EXACT expected package set. Exhaustive on purpose:
		// a "contains" assertion would have passed even while Parse
		// returned nothing but an error.
		want []wantPkg
		// notWant names that must never appear (workspace root, symlinks).
		notWant []string
	}{
		{
			// The canonical B1 repro: one runtime dependency, so npm
			// mirrors {"lodash":"4.17.21"} into packages[""].dependencies
			// as a STRING value.
			name: "v3 single runtime dependency",
			file: "v3_runtime_dep.json",
			want: []wantPkg{
				{name: "lodash", version: "4.17.21"},
			},
			notWant: []string{"fixture-runtime"},
		},
		{
			name: "v3 scoped package",
			file: "v3_scoped.json",
			want: []wantPkg{
				{name: "@babel/code-frame", version: "7.24.7"},
				{name: "@babel/helper-validator-identifier", version: "7.29.7"},
				{name: "@babel/highlight", version: "7.25.9"},
				{name: "ansi-styles", version: "3.2.1"},
				{name: "chalk", version: "2.4.2"},
				{name: "color-convert", version: "1.9.3"},
				{name: "color-name", version: "1.1.3"},
				{name: "escape-string-regexp", version: "1.0.5"},
				{name: "has-flag", version: "3.0.0"},
				{name: "js-tokens", version: "4.0.0"},
				{name: "picocolors", version: "1.1.1"},
				{name: "supports-color", version: "5.5.0"},
			},
			notWant: []string{"fixture-scoped"},
		},
		{
			// chalk@4 pulls ansi-styles → color-convert → color-name and
			// supports-color → has-flag. All must surface, not just the
			// direct dep.
			name: "v3 transitive dependencies",
			file: "v3_transitive.json",
			want: []wantPkg{
				{name: "ansi-styles", version: "4.3.0"},
				{name: "chalk", version: "4.1.2"},
				{name: "color-convert", version: "2.0.1"},
				{name: "color-name", version: "1.1.4"},
				{name: "has-flag", version: "4.0.0"},
				{name: "supports-color", version: "7.2.0"},
			},
			notWant: []string{"fixture-transitive"},
		},
		{
			// devDependencies must parse AND carry Dev=true.
			name: "v3 devDependencies only",
			file: "v3_dev_only.json",
			want: []wantPkg{
				{name: "lodash", version: "4.17.21", dev: true},
			},
			notWant: []string{"fixture-dev-only"},
		},
		{
			// Workspace root ("") is skipped, and so are the
			// node_modules/@fixture/* entries, which npm writes as
			// {"link": true} symlinks into packages/. The local
			// workspace member entries (packages/pkg-a, packages/pkg-b)
			// are first-party source, not installs — Parse currently DOES
			// emit them; asserted here so the behaviour is a decision, not
			// an accident.
			name: "v3 workspaces",
			file: "v3_workspace.json",
			want: []wantPkg{
				{name: "@fixture/pkg-a", version: "1.0.0"},
				{name: "@fixture/pkg-b", version: "2.0.0"},
				{name: "lodash", version: "4.17.21"},
				{name: "ms", version: "2.1.3"},
			},
			notWant: []string{"fixture-workspace-root"},
		},
		{
			// v1 still goes through the recursive "dependencies" walk;
			// the v2/v3 "packages" map is absent entirely.
			name: "v1 recursive tree",
			file: "v1_runtime_dep.json",
			want: []wantPkg{
				{name: "ansi-styles", version: "4.3.0"},
				{name: "chalk", version: "4.1.2"},
				{name: "color-convert", version: "2.0.1"},
				{name: "color-name", version: "1.1.4"},
				{name: "has-flag", version: "4.0.0"},
				{name: "supports-color", version: "7.2.0"},
			},
			notWant: []string{"fixture-v1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatalf("open fixture: %v", err)
			}
			defer f.Close()

			got, err := Parse(f)
			if err != nil {
				t.Fatalf("Parse(%s) returned error: %v", tt.file, err)
			}
			assertPackages(t, got, tt.want)

			for _, bad := range tt.notWant {
				for _, p := range got {
					if p.Name == bad {
						t.Errorf("Parse(%s) emitted %q, which must be excluded", tt.file, bad)
					}
				}
			}
		})
	}
}

// TestParseRootPackagesEntryDependenciesAreStrings pins the exact shape that
// broke the decoder, independent of any fixture regeneration. If someone
// re-adds a typed `Dependencies` field to lockPackage this fails immediately.
func TestParseRootPackagesEntryDependenciesAreStrings(t *testing.T) {
	const lock = `{
	  "name": "x",
	  "version": "1.0.0",
	  "lockfileVersion": 3,
	  "packages": {
	    "": {
	      "name": "x",
	      "version": "1.0.0",
	      "dependencies": {"lodash": "^4.17.21"},
	      "devDependencies": {"typescript": "~5.4.0"},
	      "peerDependencies": {"react": ">=18"},
	      "optionalDependencies": {"fsevents": "^2.3.0"}
	    },
	    "node_modules/lodash": {"version": "4.17.21"}
	  }
	}`
	got, err := Parse(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertPackages(t, got, []wantPkg{{name: "lodash", version: "4.17.21"}})
}

// TestParseNestedNodeModulesName covers the deriveNameFromPath branch: a
// nested install has no explicit "name" key, so the name comes from the last
// node_modules/ segment — including the scope.
func TestParseNestedNodeModulesName(t *testing.T) {
	const lock = `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "x", "version": "1.0.0", "dependencies": {"a": "^1.0.0"}},
	    "node_modules/a": {"version": "1.0.0"},
	    "node_modules/a/node_modules/@scope/b": {"version": "2.0.0"}
	  }
	}`
	got, err := Parse(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertPackages(t, got, []wantPkg{
		{name: "@scope/b", version: "2.0.0"},
		{name: "a", version: "1.0.0"},
	})
}

// TestParsePeerMarkedDev pins the existing Dev||Peer propagation.
func TestParsePeerMarkedDev(t *testing.T) {
	const lock = `{
	  "lockfileVersion": 3,
	  "packages": {
	    "": {"name": "x", "version": "1.0.0", "dependencies": {"a": "^1.0.0"}},
	    "node_modules/a": {"version": "1.0.0", "peer": true}
	  }
	}`
	got, err := Parse(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertPackages(t, got, []wantPkg{{name: "a", version: "1.0.0", dev: true}})
}

// TestParseV1NestedTree exercises the recursive walk with genuinely nested
// "dependencies" objects and dev inheritance from parent to child.
func TestParseV1NestedTree(t *testing.T) {
	const lock = `{
	  "lockfileVersion": 1,
	  "dependencies": {
	    "top": {
	      "version": "1.0.0",
	      "dev": true,
	      "requires": {"child": "^2.0.0"},
	      "dependencies": {
	        "child": {"version": "2.0.0"}
	      }
	    }
	  }
	}`
	got, err := Parse(strings.NewReader(lock))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	assertPackages(t, got, []wantPkg{
		{name: "child", version: "2.0.0", dev: true},
		{name: "top", version: "1.0.0", dev: true},
	})
}

func TestParseInvalidJSON(t *testing.T) {
	if _, err := Parse(strings.NewReader("{not json")); err == nil {
		t.Fatal("Parse: want error on malformed JSON, got nil")
	}
}

func assertPackages(t *testing.T, got []ftypes.Package, want []wantPkg) {
	t.Helper()

	gotSorted := append([]ftypes.Package(nil), got...)
	sort.Slice(gotSorted, func(i, j int) bool {
		if gotSorted[i].Name != gotSorted[j].Name {
			return gotSorted[i].Name < gotSorted[j].Name
		}
		return gotSorted[i].Version < gotSorted[j].Version
	})
	wantSorted := append([]wantPkg(nil), want...)
	sort.Slice(wantSorted, func(i, j int) bool {
		if wantSorted[i].name != wantSorted[j].name {
			return wantSorted[i].name < wantSorted[j].name
		}
		return wantSorted[i].version < wantSorted[j].version
	})

	if len(gotSorted) != len(wantSorted) {
		t.Fatalf("package count = %d, want %d\ngot:  %s\nwant: %s",
			len(gotSorted), len(wantSorted), formatGot(gotSorted), formatWant(wantSorted))
	}
	for i := range wantSorted {
		g, w := gotSorted[i], wantSorted[i]
		if g.Name != w.name || g.Version != w.version || g.Dev != w.dev {
			t.Errorf("package[%d] = {%s %s dev=%v}, want {%s %s dev=%v}",
				i, g.Name, g.Version, g.Dev, w.name, w.version, w.dev)
		}
	}
}

func formatGot(pkgs []ftypes.Package) string {
	parts := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		parts = append(parts, p.Name+"@"+p.Version)
	}
	return "[" + strings.Join(parts, " ") + "]"
}

func formatWant(pkgs []wantPkg) string {
	parts := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		parts = append(parts, p.name+"@"+p.version)
	}
	return "[" + strings.Join(parts, " ") + "]"
}
