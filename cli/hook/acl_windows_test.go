//go:build windows

package hook

import (
	"os"
	"strings"
	"testing"
)

// acl_windows_test.go — L-09, Windows arm.
//
// ⚠️ UNVERIFIED. There is no Windows CI in this project (GitHub Actions billing
// is off by decision) and this wave was developed on macOS, so nothing here has
// ever been executed. These belong on the MANUAL Windows pre-release gate; treat
// a green Linux/macOS run as saying nothing at all about them.
//
// What they are meant to catch: tightenExistingFile used to `return`
// immediately on Windows while three rendered config bodies promised the file
// was kept owner-only. The fix routes both the pre-existing-file path and the
// freshly-created-file path through secureio.RestrictToCurrentUser, which
// installs a PROTECTED DACL — protected meaning inherited ACEs are stripped,
// which is the entire point (a permissive parent directory must not leak the
// credential) and also the riskiest part (a profile that relied on inheritance
// for its own access loses it).

// TestWireRestrictsCredentialFileOnWindows asserts that a wire which embeds a
// secret leaves a file the current user can still read and write. It cannot
// assert the negative (that nobody else can) without a second account, which is
// exactly why the manual gate exists: the reviewer should also run
//
//	icacls %USERPROFILE%\.npmrc
//
// and confirm the output shows ONLY the current user, with no inherited entries.
func TestWireRestrictsCredentialFileOnWindows(t *testing.T) {
	for _, m := range All() {
		t.Run(m.Name(), func(t *testing.T) {
			sandboxHome(t)
			opts := testWireOpts()
			opts.Credentials = testCreds
			if err := m.Wire(opts); err != nil {
				t.Fatalf("Wire: %v", err)
			}
			for _, p := range managerPaths(t, m, ScopeUser) {
				// The owner must retain full access after the DACL is
				// replaced. A protected DACL that dropped the current user
				// would break every subsequent chainsaw run AND the package
				// manager itself.
				f, err := os.OpenFile(p, os.O_RDWR, 0)
				if err != nil {
					t.Fatalf("the current user lost access to %s after the ACL tighten: %v", p, err)
				}
				_ = f.Close()
			}
		})
	}
}

// TestPreExistingLooseFileIsTightenedOnWindows covers the upgrade path: a file
// written by an older chainsaw (which never touched Windows ACLs) must be
// tightened when a re-wire embeds a fresh secret.
func TestPreExistingLooseFileIsTightenedOnWindows(t *testing.T) {
	sandboxHome(t)
	m := npmManager{}
	path, err := m.ConfigPathForScope(ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("save-exact=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var notes []string
	opts := testWireOpts()
	opts.Credentials = testCreds
	opts.Notify = func(msg string) { notes = append(notes, msg) }
	if err := m.Wire(opts); err != nil {
		t.Fatal(err)
	}
	// A tighten FAILURE must be a warning, never fatal — Wire returning nil
	// above is that assertion. If it did warn, the message must name the file
	// so the operator can act.
	for _, n := range notes {
		if strings.Contains(n, "could not restrict") && !strings.Contains(n, path) {
			t.Errorf("ACL warning does not name the file: %q", n)
		}
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("config vanished: %v", err)
	}
}
