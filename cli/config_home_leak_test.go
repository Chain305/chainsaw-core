package cli

// config_home_leak_test.go — the package-wide rail that turns "no test writes to
// the developer's real config home" from a habit into an assertion.
//
// ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
//
// Twice now the suite has quietly written into the machine's real ~/.chainsaw:
//
//	guard_policy_pin.json  reached revision 48. Worse than untidy — the stale
//	                       pin made a real `chainsaw npm install` print a false
//	                       "policy bundle missing" security alarm, and it made
//	                       TestGuardPolicyLane_MissingConfiguredBundleIsCounted
//	                       order-dependent on residue from earlier runs.
//	                       Fixed by guardPolicyTestEnv (guard_policy_test.go).
//
//	guard_state.json       reached installs_checked > 26,000. 68 writes per full
//	                       `go test ./core/...`, all of them from the chainsaw
//	                       BINARY spawned by subprocess harnesses that built
//	                       cmd.Env from os.Environ() and so inherited the real
//	                       $HOME. Fixed in guardBypassRun, the quiet-invariant
//	                       test, and runChainsawExit.
//
// Each fix was correct and each was invisible the moment it regressed, because
// the write is best-effort: saveGuardState swallows every error, so a leak
// produces no failure, no log line, and no symptom until a developer's real
// install starts behaving oddly. The pin file got a targeted regression test
// (TestGuardPolicyPinNeverEscapesTheTestTempDir). That test can only speak for
// the helper it calls; this one speaks for the whole package.
//
// ─── WHY TestMain AND NOT A TEST ────────────────────────────────────────────
//
// The thing being asserted is a property of the ENTIRE RUN — "no test, in this
// process or in any process it spawned, touched the real config home". No
// individual test can observe that; only a before/after around m.Run() can. A
// per-helper test would also have to be written again for every new harness,
// which is exactly the maintenance the two incidents above already lost.
//
// It deliberately does NOT redirect $HOME to a sandbox, which would be the
// stronger move. The subprocess harnesses shell out to `go build`, and `go`
// resolves GOPATH/GOMODCACHE/GOCACHE under $HOME — pointing $HOME at an empty
// temp dir would send those builds off to re-download the module cache. Detect,
// report, and let the fix be an explicit CHAINSAW_CONFIG_HOME on the harness.
//
// ─── WHAT COUNTS AS DRIFT ───────────────────────────────────────────────────
//
// Any file under the real config home that appears, disappears, changes size,
// or changes mtime between the two snapshots. Content is not hashed: the config
// home can hold a several-hundred-MB OpenSSF feed, and stat is enough — a write
// moves mtime even when the bytes are identical.

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/cli/platform"
)

// configHomeDriftOptOut disables the rail. The ONLY legitimate use is a
// developer who is running a real `chainsaw` command in another terminal while
// the suite runs, which is genuine concurrent drift the rail cannot distinguish
// from a leak. It is not a way to land a leaking test.
const configHomeDriftOptOut = "CHAINSAW_ALLOW_CONFIG_HOME_DRIFT"

// configHomeEntry is the stat fingerprint of one file under the config home.
type configHomeEntry struct {
	Size    int64
	ModUnix int64
}

// snapshotConfigHome fingerprints every file under dir, keyed by path relative
// to dir. A missing dir is the normal case on CI and returns an empty map — the
// assertion then reads "the suite must not CREATE it", which is what we want.
// Unreadable subtrees are skipped rather than reported: this must never fail a
// build for a permissions quirk in somebody's home directory.
func snapshotConfigHome(dir string) map[string]configHomeEntry {
	out := map[string]configHomeEntry{}
	if dir == "" {
		return out
	}
	_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		info, ierr := d.Info()
		if ierr != nil {
			return nil
		}
		rel, rerr := filepath.Rel(dir, path)
		if rerr != nil {
			rel = path
		}
		out[rel] = configHomeEntry{Size: info.Size(), ModUnix: info.ModTime().UnixNano()}
		return nil
	})
	return out
}

// describeConfigHomeDrift returns "" when the two snapshots are identical, and
// otherwise a sorted, human-readable list naming every file that appeared,
// vanished, or was rewritten. Split out from TestMain so its behaviour is
// itself testable — see TestConfigHomeDriftDetectorIsNotVacuous.
func describeConfigHomeDrift(before, after map[string]configHomeEntry) string {
	var lines []string
	for name, a := range after {
		b, existed := before[name]
		switch {
		case !existed:
			lines = append(lines, "  CREATED  "+name)
		case a != b:
			lines = append(lines, "  MODIFIED "+name)
		}
	}
	for name := range before {
		if _, still := after[name]; !still {
			lines = append(lines, "  DELETED  "+name)
		}
	}
	if len(lines) == 0 {
		return ""
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// configHomeSandbox / realConfigHomeAtStartup point the whole package at a
// throwaway config home and remember the developer's true one, in that order.
//
// WHY THIS EXISTS AT ALL. The rail below only REPORTS a leak after the fact.
// This stops it, and it closes a race the rail cannot: t.Setenv restores the
// PREVIOUS value at cleanup, and with CHAINSAW_CONFIG_HOME unset by default the
// previous value is "unset" — which resolves to the developer's real
// ~/.chainsaw. Any write that lands after an isolated test's cleanup (a
// background goroutine, a subprocess still exiting) therefore hit the real
// machine. Making the ambient value a sandbox means "restored" is still
// contained. The leak is timing-dependent, which is why it came and went:
// instrumenting the writer perturbed the schedule enough to hide it.
//
// WHY A VAR INITIALIZER AND NOT TestMain. setup.go builds setupCmd.Long during
// init() and deliberately resolves the config path exactly once ("nothing later
// in the run can invalidate this"). os.Setenv from TestMain runs after every
// init(), so it would invalidate precisely that invariant and
// TestConfigPathHelpTextIsResolved would compare an init-time real path against
// a call-time sandbox path. The Go spec settles the ordering: every
// package-level variable initializer is evaluated before ANY init() function
// runs, so this is ordered by the language rather than by filename luck.
//
// Subprocess harnesses inherit it for free — they build cmd.Env from
// os.Environ() — so a new exec site cannot silently reintroduce the leak by
// forgetting to set it. A per-test t.Setenv still wins over this.
var configHomeSandbox, realConfigHomeAtStartup = installConfigHomeSandbox()

func installConfigHomeSandbox() (sandbox, real string) {
	// Read the real one FIRST: after the Setenv below, platform.ConfigHome()
	// answers with the sandbox and the rail would end up watching itself.
	real = platform.ConfigHome()
	dir, err := os.MkdirTemp("", "chainsaw-cli-confighome-")
	if err != nil {
		panic("cannot create config-home sandbox: " + err.Error())
	}
	if err := os.Setenv(platform.EnvConfigHome, dir); err != nil {
		panic("cannot sandbox the config home: " + err.Error())
	}
	return dir, real
}

func TestMain(m *testing.M) {
	// Captured before any test could t.Setenv CHAINSAW_CONFIG_HOME and before
	// the sandbox above redirected it. This is the developer's real one.
	realHome := realConfigHomeAtStartup
	before := snapshotConfigHome(realHome)

	code := m.Run()

	// A test that lands here rather than in its own t.TempDir() is still
	// missing isolation: the same code leaks for real in any package without
	// this sandbox. Reported, not failed — nothing reached the developer's
	// machine, and failing the build over a contained write would block on
	// files that provably never escape.
	if drift := describeConfigHomeDrift(nil, snapshotConfigHome(configHomeSandbox)); drift != "" {
		fmt.Fprintf(os.Stderr,
			"\nnote: these files landed in the package config-home sandbox rather than in\n"+
				"a t.TempDir(). Nothing escaped to %s, but the isolation is still missing:\n%s\n",
			realHome, drift)
	}
	os.RemoveAll(configHomeSandbox)

	if _, muted := os.LookupEnv(configHomeDriftOptOut); !muted && realHome != "" {
		if drift := describeConfigHomeDrift(before, snapshotConfigHome(realHome)); drift != "" {
			fmt.Fprintf(os.Stderr,
				"\nFAIL: the test suite wrote to the REAL config home %s:\n%s\n\n"+
					"A test must write only inside its own t.TempDir(). Fix it the way\n"+
					"guardPolicyTestEnv did: t.Setenv(\"CHAINSAW_CONFIG_HOME\", t.TempDir()).\n"+
					"If the writer is a SUBPROCESS (a harness that builds cmd.Env from\n"+
					"os.Environ()), t.Setenv will not reach it — add\n"+
					"\"CHAINSAW_CONFIG_HOME=\"+t.TempDir() to cmd.Env, as guardBypassRun does.\n"+
					"If a real chainsaw command was running in another terminal during this\n"+
					"suite, that is the one case %s=1 is for.\n",
				realHome, drift, configHomeDriftOptOut)
			if code == 0 {
				code = 1
			}
		}
	}
	os.Exit(code)
}

// TestConfigHomeDriftDetectorIsNotVacuous proves the rail above can actually go
// red. The rail's own failure mode is silence — if describeConfigHomeDrift ever
// returned "" unconditionally, every leak would sail through and nothing would
// say so. Everything here happens inside t.TempDir(); the real config home is
// never touched.
func TestConfigHomeDriftDetectorIsNotVacuous(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "sub")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	stable := filepath.Join(dir, "install_id")
	if err := os.WriteFile(stable, []byte("id"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	doomed := filepath.Join(nested, "doomed.json")
	if err := os.WriteFile(doomed, []byte("{}"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}

	before := snapshotConfigHome(dir)
	if len(before) != 2 {
		t.Fatalf("snapshot missed a file: %+v", before)
	}
	if drift := describeConfigHomeDrift(before, snapshotConfigHome(dir)); drift != "" {
		t.Fatalf("an untouched config home reported drift, so the rail would be flaky: %s", drift)
	}

	// The exact shape of the guard_state.json leak: a new file appears.
	leak := filepath.Join(dir, "guard_state.json")
	if err := os.WriteFile(leak, []byte(`{"installs_checked":1}`), 0o644); err != nil {
		t.Fatalf("plant: %v", err)
	}
	// And the shape of the guard_policy_pin.json leak: an existing file is
	// rewritten. Stamped rather than slept on, so the test stays fast and
	// cannot flake on a coarse filesystem timestamp.
	if err := os.WriteFile(stable, []byte("rewritten"), 0o644); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if err := os.Remove(doomed); err != nil {
		t.Fatalf("remove: %v", err)
	}

	drift := describeConfigHomeDrift(before, snapshotConfigHome(dir))
	for _, want := range []string{"CREATED  guard_state.json", "MODIFIED install_id", "DELETED  " + filepath.Join("sub", "doomed.json")} {
		if !strings.Contains(drift, want) {
			t.Errorf("drift report is missing %q — the rail would not name the offender.\ngot:\n%s", want, drift)
		}
	}
}

// TestGuardStateNeverResolvesOutsideAnIsolatedConfigHome is the in-process half
// of the same guarantee, and the direct analogue of
// TestGuardPolicyPinNeverEscapesTheTestTempDir: with CHAINSAW_CONFIG_HOME set,
// the state file must resolve under it — the writer must have no other way home.
func TestGuardStateNeverResolvesOutsideAnIsolatedConfigHome(t *testing.T) {
	home := withIsolatedConfigHome(t)

	saveGuardState(&guardState{InstallsChecked: 3})

	got := guardStatePath()
	if got == "" || !strings.HasPrefix(got, home) {
		t.Fatalf("guard_state.json resolved to %q, outside the test config home %q", got, home)
	}
	if _, err := os.Stat(got); err != nil {
		t.Fatalf("the state was expected inside the temp config home, stat: %v", err)
	}
	if st := loadGuardState(); st.InstallsChecked != 3 {
		t.Fatalf("read back the wrong state (%d installs) — the writer and reader disagree on the path", st.InstallsChecked)
	}
}
