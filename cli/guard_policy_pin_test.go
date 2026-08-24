package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPolicyPin_FirstRunNoBundleIsSilent protects the onboarding case
// the fall-back-to-defaults ruling exists for. A fresh `curl | sh`
// install has no bundle and must say nothing about it — a warning on
// first use would train users to ignore the one line that matters
// later.
func TestPolicyPin_FirstRunNoBundleIsSilent(t *testing.T) {
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())
	if notice := observeGuardPolicyBundle("digest-a", "(built-in only)", 1, false); notice != "" {
		t.Fatalf("first run with no bundle must be silent, got %q", notice)
	}
	if _, pinned := readGuardPolicyPin(); pinned {
		t.Fatal("built-in-only state must not be pinned — pinning it makes every later first bundle look like a change")
	}
}

// TestPolicyPin_VanishedBundleIsLoud is the reason this file exists.
// Falling back to defaults when no bundle is present means removing the
// bundle is a downgrade. Trust-on-first-use makes "gone" distinguishable
// from "never configured", which is otherwise byte-identical.
//
// This is the inverse of the threat E5 closed: E5 made ADDING a rego
// file require a signature, and left REMOVAL silent.
func TestPolicyPin_VanishedBundleIsLoud(t *testing.T) {
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())

	// Day one: an operator bundle is present and gets pinned.
	if notice := observeGuardPolicyBundle("digest-a", "/etc/chainsaw/policy", 3, true); notice != "" {
		t.Fatalf("pinning a new bundle must be silent, got %q", notice)
	}
	pin, pinned := readGuardPolicyPin()
	if !pinned || pin.Digest != "digest-a" {
		t.Fatalf("bundle must be pinned on first sight, got %+v pinned=%v", pin, pinned)
	}

	// Day two: the bundle is gone.
	before := GuardPolicyBundleVanishedCount()
	notice := observeGuardPolicyBundle("digest-builtin", "(built-in only)", 1, false)
	if notice == "" {
		t.Fatal("a bundle that was pinned and is now absent MUST warn — silent fallback is the downgrade")
	}
	if !strings.Contains(notice, "/etc/chainsaw/policy") {
		t.Fatalf("the warning must name where the bundle used to be, got %q", notice)
	}
	if GuardPolicyBundleVanishedCount() == before {
		t.Fatal("a vanished bundle must be counted, not only printed")
	}
}

// TestPolicyPin_DoesNotBlock pins the deliberate limit. Refusing installs
// when the bundle is missing would hand a denial of service to anyone who
// can delete a file, and the only policy available at that moment is the
// built-in default. The pin makes the state loud; it does not enforce.
func TestPolicyPin_DoesNotBlock(t *testing.T) {
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())
	observeGuardPolicyBundle("digest-a", "/etc/chainsaw/policy", 3, true)
	// The API returns a string, not a verdict. If this ever grows a
	// blocking return, this test is the place that argument gets had.
	notice := observeGuardPolicyBundle("digest-builtin", "(built-in only)", 1, false)
	if notice == "" {
		t.Fatal("expected a notice")
	}
}

// TestPolicyPin_ChangedBundleUpdatesQuietly: rotating rules is normal
// operator work. It bumps the revision so the file carries the history,
// and says nothing — warning on every legitimate edit is how a warning
// becomes noise.
func TestPolicyPin_ChangedBundleUpdatesQuietly(t *testing.T) {
	t.Setenv("CHAINSAW_CONFIG_HOME", t.TempDir())
	observeGuardPolicyBundle("digest-a", "/etc/chainsaw/policy", 3, true)
	if notice := observeGuardPolicyBundle("digest-b", "/etc/chainsaw/policy", 4, true); notice != "" {
		t.Fatalf("a changed bundle must not warn, got %q", notice)
	}
	pin, _ := readGuardPolicyPin()
	if pin.Digest != "digest-b" {
		t.Fatalf("pin must follow the current bundle, got %q", pin.Digest)
	}
	if pin.Revision != 2 {
		t.Fatalf("revision must record the rotation, got %d", pin.Revision)
	}
}

// TestPolicyPin_FileIsPrivate — the pin states which rules a machine
// believes it enforces. Same 0600 posture as the allowlist, including
// the re-tighten half: os.WriteFile only applies perm on CREATE, so an
// existing loose file would otherwise stay loose forever.
func TestPolicyPin_FileIsPrivate(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("CHAINSAW_CONFIG_HOME", dir)
	p := guardPolicyPinPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	observeGuardPolicyBundle("digest-a", "/etc/chainsaw/policy", 3, true)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("pin file mode = %04o, want 0600 (an existing loose file must be re-tightened)", perm)
	}
}

// TestPolicyPin_BrokenBundleIsNotAVanishedBundle. An operator whose
// rules no longer compile still HAS rules. Treating that as "bundle
// removed" would bury the actual problem (a syntax error) under the
// wrong warning, and would rewrite the pin as if the bundle were gone.
func TestPolicyPin_BrokenBundleIsNotAVanishedBundle(t *testing.T) {
	guardPolicyResetForTest()
	t.Cleanup(guardPolicyResetForTest)
	cfg := t.TempDir()
	t.Setenv("CHAINSAW_CONFIG_HOME", cfg)

	dir := t.TempDir()
	mustWrite(t, filepath.Join(dir, "ok.rego"), "package chainsaw.policy\n")
	t.Setenv(guardPolicyBundleEnv, dir)
	guardPolicy()
	guardPolicyResetForTest()

	// Now break it.
	mustWrite(t, filepath.Join(dir, "ok.rego"), "package chainsaw.policy\n\nnot rego {{{\n")
	guardPolicy()
	notice := GuardPolicyNotice()
	if !strings.Contains(notice, "failed to compile") {
		t.Fatalf("a broken bundle must report the compile failure, got %q", notice)
	}
	if strings.Contains(notice, "missing") {
		t.Fatalf("a broken bundle must not be reported as a missing one, got %q", notice)
	}
}
