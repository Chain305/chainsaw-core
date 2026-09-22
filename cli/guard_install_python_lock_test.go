package cli

// T3 tail — a bare `pip install` in a Pipfile / poetry / uv project scanned
// NOTHING.
//
// `npm install` with no named package sweeps package-lock.json, then
// npm-shrinkwrap, then pnpm-lock, then yarn.lock. `cargo build` sweeps
// Cargo.lock, `gem install` sweeps Gemfile.lock, `go get` sweeps go.sum. pip
// had exactly one path — an explicit `-r requirements.txt` — so a developer in
// a Poetry or Pipenv project, which is most modern Python, got a guard that
// recognised the command, printed nothing, and checked no packages.
//
// The parsers already existed in pr-scan (parsePipfileLock, parsePoetryLock,
// parseUVLock). Only the wiring was missing, which is what the plan said.

import (
	"os"
	"path/filepath"
	"testing"
)

const pipfileLockFixture = `{
  "default": {
    "requests": {"version": "==2.31.0"},
    "urllib3":  {"version": "==2.0.7"}
  },
  "develop": {
    "pytest": {"version": "==7.4.0"}
  }
}`

const poetryLockFixture = `[[package]]
name = "requests"
version = "2.31.0"

[[package]]
name = "urllib3"
version = "2.0.7"
`

func TestPipExpandsPipfileLock(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte(pipfileLockFixture), 0o644); err != nil {
		t.Fatal(err)
	}

	specs := expandLockfile("pip", []string{"install"})
	if len(specs) == 0 {
		t.Fatal("bare `pip install` in a Pipfile project scanned nothing")
	}
	for _, s := range specs {
		if s.Ecosystem != "pypi" {
			t.Errorf("spec %+v has ecosystem %q, want pypi", s, s.Ecosystem)
		}
		if s.Name == "" {
			t.Errorf("spec with empty name: %+v", s)
		}
	}
}

func TestPipExpandsPoetryLock(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, "poetry.lock"), []byte(poetryLockFixture), 0o644); err != nil {
		t.Fatal(err)
	}

	specs := expandLockfile("pip", []string{"install"})
	if len(specs) == 0 {
		t.Fatal("bare `pip install` in a Poetry project scanned nothing")
	}
}

// An explicit -r is the user naming their source. It must keep winning over a
// lockfile that happens to sit in the same directory, or `pip install -r
// constraints.txt` would silently scan the Pipfile tree instead.
func TestExplicitRequirementsBeatsALockfileInTheSameDir(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte(pipfileLockFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "req.txt"), []byte("flask==3.0.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	specs := expandLockfile("pip", []string{"install", "-r", "req.txt"})
	if len(specs) != 1 || specs[0].Name != "flask" {
		t.Fatalf("explicit -r did not win: got %+v", specs)
	}
}

// The guard must not invent work. No lockfile, no named package — nothing to
// scan, and expandLockfile returning specs here would mean it had read a file
// from some other project.
func TestPipWithNoLockfileScansNothing(t *testing.T) {
	chdirTemp(t)
	if specs := expandLockfile("pip", []string{"install"}); len(specs) != 0 {
		t.Fatalf("empty dir produced %d specs: %+v", len(specs), specs)
	}
}

// Precedence is fixed rather than filesystem-order dependent: two lockfiles in
// one directory must always resolve the same way, or guard coverage becomes
// non-reproducible run to run — the same reason the npm path uses coordinates
// instead of a map.
func TestPythonLockfilePrecedenceIsDeterministic(t *testing.T) {
	dir := chdirTemp(t)
	if err := os.WriteFile(filepath.Join(dir, "Pipfile.lock"), []byte(pipfileLockFixture), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "poetry.lock"), []byte(poetryLockFixture), 0o644); err != nil {
		t.Fatal(err)
	}

	first := expandLockfile("pip", []string{"install"})
	for i := 0; i < 5; i++ {
		again := expandLockfile("pip", []string{"install"})
		if len(again) != len(first) {
			t.Fatalf("run %d returned %d specs, first run returned %d — precedence is not deterministic",
				i, len(again), len(first))
		}
	}
}

// End-to-end: the wiring is only worth anything if a real malicious package
// reaches a real block THROUGH it. `colourama` is in the embedded
// known-malicious floor (the 2018 PyPI typosquat of `colorama`); before this
// change a Poetry project could install it and the guard would have scanned
// nothing at all.
func TestPoetryLockCarriesAMaliciousPackageToTheGuard(t *testing.T) {
	dir := chdirTemp(t)
	lock := `[[package]]
name = "colourama"
version = "0.1.6"

[[package]]
name = "requests"
version = "2.31.0"
`
	if err := os.WriteFile(filepath.Join(dir, "poetry.lock"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}

	specs := expandLockfile("pip", []string{"install"})
	var found bool
	for _, s := range specs {
		if s.Name == "colourama" {
			found = true
			if s.Ecosystem != "pypi" {
				t.Errorf("colourama resolved as %q, want pypi — the malware index is keyed by ecosystem, "+
					"so a wrong one here means the floor never matches", s.Ecosystem)
			}
		}
	}
	if !found {
		t.Fatalf("colourama did not survive poetry.lock expansion; got %+v", specs)
	}
}
