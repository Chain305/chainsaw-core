package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/typosquat"
)

// P1b red-team regressions on the CLI side: parse errors are never an empty
// lockfile, and a vendored archive is never local code.

// gemfileLongLine is the red-team PoC: head adds rest-client and a section
// with a line past bundler's scanner limit.
func gemfileLongLine() []byte {
	return []byte("GEM\n  remote: https://rubygems.org/\n  specs:\n    rest-client (1.6.13)\n\n" +
		"ZJUNK\n  " + strings.Repeat("x", 1<<20+16) + "\n\n" +
		"PLATFORMS\n  ruby\n\nDEPENDENCIES\n  rest-client\n")
}

// TestPRScanGemfileParseErrorNotSwallowed: the bundler parse error was
// dropped, so pr-scan reported added=[] err=nil for a head that adds
// rest-client. Either the file parses (rest-client listed) or the error
// reaches pr-scan's failure accounting — never neither.
func TestPRScanGemfileParseErrorNotSwallowed(t *testing.T) {
	base := []byte("GEM\n  remote: https://rubygems.org/\n  specs:\n\nPLATFORMS\n  ruby\n")
	added, _, err := diffManifest(kindGemfileLock, "Gemfile.lock", base, gemfileLongLine())
	if err != nil {
		return
	}
	for _, e := range added {
		if e.Name == "rest-client" {
			return
		}
	}
	t.Fatalf("added=%+v err=nil: the parse failure was swallowed", added)
}

// TestPRScanParseErrorsPropagate: every depparser-backed lockfile kind
// returns its parser's error rather than an empty diff.
func TestPRScanParseErrorsPropagate(t *testing.T) {
	for _, tc := range []struct {
		kind manifestKind
		file string
		data string
	}{
		{kindPNPMLock, "pnpm-lock.yaml", "packages: [\n"},
		{kindYarnLock, "yarn.lock", "__metadata:\n  version: 8\n\"x@npm:1\": [\n"},
		{kindNPMPackageLock, "package-lock.json", `{"lockfileVersion": 3, "packages": []}`},
		{kindUVLock, "uv.lock", "[[package]\n"},
	} {
		if _, _, err := diffManifest(tc.kind, tc.file, nil, []byte(tc.data)); err == nil {
			t.Errorf("%s: unparseable head gave no error", tc.file)
		}
	}
}

// TestGuardUnparsedLockfileNotSilent: a guarded `npm ci` (or `gem install`)
// whose lockfile does not parse used to scan nothing and pass silently. It
// is now one spec for the file, reported not assessed, non-blocking by
// default.
func TestGuardUnparsedLockfileNotSilent(t *testing.T) {
	for _, tc := range []struct {
		bin, verb, file, data string
	}{
		{"npm", "ci", "pnpm-lock.yaml", "packages: [\n"},
		{"npm", "ci", "package-lock.json", `{"lockfileVersion": 3, "packages": []}`},
		{"pip", "install", "uv.lock", "[[package]\n"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			dir := guardOriginChdir(t)
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.data), 0o644); err != nil {
				t.Fatal(err)
			}
			specs := expandLockfile(tc.bin, []string{tc.verb})
			if len(specs) != 1 || specs[0].Origin != unparsedLockPrefix+tc.file {
				t.Fatalf("specs = %+v, want one unparsed-lockfile spec", specs)
			}
			g := &localGuard{detectors: map[string]*typosquat.Detector{}, malware: guardOriginMalwareIndex()}
			verdicts, blocked := g.evaluateAll(context.Background(), specs)
			if blocked || len(verdicts) != 1 || verdicts[0].Severity != guardSeverityNotAssessed ||
				!strings.Contains(verdicts[0].Reason, tc.file+" could not be parsed") {
				t.Fatalf("verdicts = %+v blocked=%v, want one non-blocking not-assessed line naming the file", verdicts, blocked)
			}
		})
	}
	// The Gemfile.lock PoC: parsed (rest-client) or reported, never nothing.
	dir := guardOriginChdir(t)
	if err := os.WriteFile(filepath.Join(dir, "Gemfile.lock"), gemfileLongLine(), 0o644); err != nil {
		t.Fatal(err)
	}
	if specs := expandLockfile("gem", []string{"install"}); len(specs) == 0 {
		t.Fatal("Gemfile.lock PoC: no specs, the install would pass unchecked")
	}
}

// TestVendoredArchiveIsNotLocal: a wheel, sdist or npm tarball checked into
// the repo is third-party code. It used to be Local (malware lookup only,
// silent) in the guard and dropped from pr-scan.
func TestVendoredArchiveIsNotLocal(t *testing.T) {
	for _, o := range []string{"file:vendor/lodash-4.17.21.tgz", "file:x.tgz", "file:wheels/x-1.0-py3-none-any.whl", "file:dist/x-1.0.tar.gz"} {
		if localCode(o) {
			t.Errorf("%s: read as local code", o)
		}
	}
	for _, o := range []string{"file:.", "file:./packages/a", "file:../lib"} {
		if !localCode(o) {
			t.Errorf("%s: not read as local code", o)
		}
	}

	// pr-scan / guard Python rule.
	if _, nr, loc := pythonSource("x", "1.0", "file:wheels/x-1.0-py3-none-any.whl"); nr == nil || loc != nil {
		t.Errorf("vendored wheel: nonRegistry=%v local=%v, want a non-registry row", nr, loc)
	}
	uv := `version = 1

[[package]]
name = "x"
version = "1.0"
source = { path = "wheels/x-1.0-py3-none-any.whl" }
`
	_, nonReg, local, err := parsePythonLock("uv.lock", []byte(uv))
	if err != nil || len(nonReg) != 1 || len(local) != 0 {
		t.Errorf("uv path wheel: nonReg=%+v local=%+v err=%v", nonReg, local, err)
	}

	// npm: a file: tarball in package-lock is a pr-scan row and an Origin spec.
	lock := `{"lockfileVersion": 3, "packages": {
  "": {"name": "app", "dependencies": {"lodash": "file:vendor/lodash-4.17.21.tgz"}},
  "node_modules/lodash": {"version": "4.17.21", "resolved": "file:vendor/lodash-4.17.21.tgz"}
}}`
	added, _, err := diffManifest(kindNPMPackageLock, "package-lock.json", nil, []byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	row := false
	for _, e := range added {
		row = row || (e.Name == "lodash" && e.Origin != "")
	}
	if !row {
		t.Errorf("pr-scan: no non-registry row for a vendored tarball: %+v", added)
	}

	dir := guardOriginChdir(t)
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	g := &localGuard{detectors: map[string]*typosquat.Detector{}, malware: guardOriginMalwareIndex()}
	verdicts, _ := g.evaluateAll(context.Background(), expandLockfile("npm", []string{"ci"}))
	printed := false
	for _, v := range verdicts {
		if v.Spec.Name == "lodash" && v.Severity == guardSeverityNotAssessed && !strings.HasPrefix(v.Reason, "local path") {
			printed = true
		}
	}
	if !printed {
		t.Errorf("guard: vendored tarball not reported not assessed: %+v", verdicts)
	}
}
