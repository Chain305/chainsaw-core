package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// chdirTemp moves the process into a scratch directory for the duration of the
// test. The lockfile expansion reads relative paths from the cwd.
func chdirTemp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	return dir
}

// TestGuardSpecsForLockfileSurvivesLeadingToolFlag pins G2: the lockfile scan
// must be anchored on the install VERB, not on the passthrough args.
//
// Before the fix, runGuardedPassthrough handed expandLockfile the passthrough
// args (the real tool's flags deliberately preserved), and every arm of
// expandLockfile keys on args[0] being the verb. So one package-manager flag in
// front of the verb — `npm -q ci`, `npm --loglevel silly ci` — silently disabled
// the ENTIRE lockfile scan, while `npm -q install evil@1.0.0` (the named-package
// path, already verb-anchored) still blocked. Anchoring both paths closes it.
func TestGuardSpecsForLockfileSurvivesLeadingToolFlag(t *testing.T) {
	chdirTemp(t)
	lock := `{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/electorn":{"version":"1.0.0"}}}`
	if err := os.WriteFile("package-lock.json", []byte(lock), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	cases := [][]string{
		{"ci"},
		{"-q", "ci"},
		{"--loglevel", "silly", "ci"},
		{"install"},
		{"-q", "install"},
	}
	for _, args := range cases {
		specs, recognized, fromLockfile := guardSpecsFor("npm", args, parseNpmInstall)
		if !recognized {
			t.Errorf("npm %v: want recognized install", args)
			continue
		}
		if !fromLockfile || len(specs) != 1 || specs[0].Name != "electorn" || specs[0].Version != "1.0.0" {
			t.Errorf("npm %v: want the lockfile tree scanned (electorn@1.0.0), got fromLockfile=%v specs=%+v",
				args, fromLockfile, specs)
		}
	}
}

// TestGuardSpecsForPipRequirementsSurvivesLeadingToolFlag is G2 for pip, where
// verb-anchoring is strictly better than the passthrough args: only the LEADING
// flag run is stripped, so a later `-r <file>` still reaches expandLockfile.
func TestGuardSpecsForPipRequirementsSurvivesLeadingToolFlag(t *testing.T) {
	dir := chdirTemp(t)
	req := filepath.Join(dir, "requirements.txt")
	if err := os.WriteFile(req, []byte("colourama==0.1.6\nrequests==2.31.0\n"), 0o644); err != nil {
		t.Fatalf("write requirements: %v", err)
	}

	for _, args := range [][]string{
		{"install", "-r", req},
		{"--disable-pip-version-check", "install", "-r", req},
		{"-q", "install", "-r", req},
	} {
		specs, recognized, fromLockfile := guardSpecsFor("pip", args, parsePipInstall)
		if !recognized || !fromLockfile || len(specs) != 2 {
			t.Fatalf("pip %v: want the requirements file scanned, got recognized=%v fromLockfile=%v specs=%+v",
				args, recognized, fromLockfile, specs)
		}
		if specs[0].Name != "colourama" {
			t.Errorf("pip %v: first spec = %+v, want colourama", args, specs[0])
		}
	}
}

// A named package still wins over the lockfile expansion, and a non-install
// verb still delegates untouched.
func TestGuardSpecsForNamedAndNonInstall(t *testing.T) {
	chdirTemp(t)
	lock := `{"lockfileVersion":3,"packages":{"node_modules/electorn":{"version":"1.0.0"}}}`
	if err := os.WriteFile("package-lock.json", []byte(lock), 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}

	specs, recognized, fromLockfile := guardSpecsFor("npm", []string{"-q", "install", "lodash@4.17.21"}, parseNpmInstall)
	if !recognized || fromLockfile || len(specs) != 1 || specs[0].Name != "lodash" {
		t.Fatalf("named install: got recognized=%v fromLockfile=%v specs=%+v", recognized, fromLockfile, specs)
	}

	specs, recognized, fromLockfile = guardSpecsFor("npm", []string{"run", "build"}, parseNpmInstall)
	if recognized || fromLockfile || len(specs) != 0 {
		t.Fatalf("`npm run build` must delegate untouched: recognized=%v fromLockfile=%v specs=%+v",
			recognized, fromLockfile, specs)
	}
}

// TestParseGoGetInstallAndRun pins G3: `go install pkg@version` is, since Go
// 1.17, THE documented way to install a binary (`go get` no longer installs
// one), and `go run pkg@version` fetches AND executes a module. Both were
// unrecognized, so both ran completely unguarded.
func TestParseGoGetInstallAndRun(t *testing.T) {
	specs, ok := parseGoGet([]string{"install", "github.com/belatedplanet/hypert@v1.0.0"})
	if !ok || len(specs) != 1 {
		t.Fatalf("`go install pkg@v` want recognized+1 spec, got ok=%v specs=%+v", ok, specs)
	}
	if specs[0].Name != "github.com/belatedplanet/hypert" || specs[0].Version != "v1.0.0" || specs[0].Ecosystem != "go" {
		t.Errorf("unexpected spec: %+v", specs[0])
	}

	specs, ok = parseGoGet([]string{"install", "-v", "github.com/sirupsen/logrsu@latest", "example.com/b@v2.0.0"})
	if !ok || len(specs) != 2 {
		t.Fatalf("multi-module `go install` want 2 specs, got ok=%v specs=%+v", ok, specs)
	}

	// `go run pkg@version prog-args...`: only the module is a package name.
	// Everything after it is passed to the program and must never be evaluated
	// (a bare word there would be fed to the typosquat detector).
	specs, ok = parseGoGet([]string{"run", "example.com/tool@v1.2.3", "serve", "lodahs"})
	if !ok || len(specs) != 1 || specs[0].Name != "example.com/tool" {
		t.Fatalf("`go run pkg@v args` want exactly the module, got ok=%v specs=%+v", ok, specs)
	}
}

// A LOCAL build must keep delegating with recognized=false: recognized+no-specs
// is the signal that triggers the go.sum expansion arm, and scanning the whole
// resolved module graph for `go run .` is not what the user asked for.
func TestParseGoGetLocalBuildNotRecognized(t *testing.T) {
	for _, args := range [][]string{
		{"install", "./..."},
		{"install"},
		{"run", "."},
		{"run", "./cmd/app", "--flag"},
		{"build", "./..."},
	} {
		if specs, ok := parseGoGet(args); ok || specs != nil {
			t.Errorf("`go %v` is a local build and must delegate (recognized=false), got ok=%v specs=%+v", args, ok, specs)
		}
	}
	// `go get` / `go mod download` keep their existing recognized-with-no-specs
	// contract so the go.sum expansion still runs for them.
	if _, ok := parseGoGet([]string{"mod", "download"}); !ok {
		t.Error("`go mod download` must stay recognized")
	}
	if _, ok := parseGoGet([]string{"get"}); !ok {
		t.Error("`go get` must stay recognized")
	}
}

// TestParseNpmSpecResolvesAlias pins G5 part A: `npm install react@npm:electorn`
// installs ELECTORN's code into node_modules/react. Evaluating the alias name
// checked a name npm never fetches — and because `react` is a typosquat-corpus
// member it also earned the exact-match exemption, so the malicious target was
// never looked up at all.
func TestParseNpmSpecResolvesAlias(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantVer  string
	}{
		{"react@npm:electorn", "electorn", ""},
		{"react@npm:electorn@1.0.0", "electorn", "1.0.0"}, // the double-@ form
		{"mypkg@npm:@scope/evil@2.0.0", "@scope/evil", "2.0.0"},
		{"@myscope/a@npm:electorn@1.0.0", "electorn", "1.0.0"},
		// Non-alias specs are untouched.
		{"lodash", "lodash", ""},
		{"lodash@4.17.21", "lodash", "4.17.21"},
		{"@babel/core@7.24.0", "@babel/core", "7.24.0"},
	}
	for _, c := range cases {
		got := parseNpmSpec(c.in)
		if got.Name != c.wantName || got.Version != c.wantVer {
			t.Errorf("parseNpmSpec(%q) = {%q,%q}, want {%q,%q}", c.in, got.Name, got.Version, c.wantName, c.wantVer)
		}
	}
}
