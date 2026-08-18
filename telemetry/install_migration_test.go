package telemetry

// install_migration_test.go — the canonical/legacy split-brain.
//
// core/telemetry used to carry its own copy of the config-directory resolver,
// and the copy disagreed with cli/platform.ConfigHome on every OS except
// Linux. On macOS that put config.yaml in ~/.chainsaw and install_id in
// ~/.config/chainsaw: two config directories on one machine.
//
// The dangerous half of the fix is the read path, not the write path.
// install_id is a STABLE IDENTITY — the PostHog distinct_id that the server
// later aliases onto a real account. Simply pointing the resolver at the
// canonical directory would make every existing user look brand new: the old
// id sits in the old directory, the new code looks in the new one, finds
// nothing, and mints a replacement. Install counts inflate, the alias that
// stitches a pre-signup install to its account points at an id nobody uses,
// and there is nothing to roll back to. So the tests here are mostly about
// what must NOT happen.
//
// These drive installDirsFn rather than the host's real directories: on Linux
// the canonical and legacy locations ARE the same directory, so a test that
// relied on GOOS would assert nothing at all there. install_lockstep_test.go
// covers the real resolvers.
//
// Everything below writes only into t.TempDir().

import (
	"os"
	"path/filepath"
	"testing"
)

// withInstallDirs pins the canonical and legacy directories for one test and
// clears the per-process cache on both sides of it.
func withInstallDirs(t *testing.T, canonical string, legacy ...string) {
	t.Helper()
	prev := installDirsFn
	installDirsFn = func() (string, []string, error) { return canonical, legacy, nil }
	ResetProcessInstall()
	t.Cleanup(func() {
		installDirsFn = prev
		ResetProcessInstall()
	})
}

func writeInstallID(t *testing.T, dir, value string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("MkdirAll %s: %v", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, installFilename), []byte(value+"\n"), 0o600); err != nil {
		t.Fatalf("write install_id: %v", err)
	}
}

func readInstallID(t *testing.T, dir string) (string, bool) {
	t.Helper()
	val, found, err := readInstallFile(dir)
	if err != nil {
		t.Fatalf("read install_id in %s: %v", dir, err)
	}
	return val, found
}

// twoDirs returns a fresh canonical/legacy pair under one temp root.
func twoDirs(t *testing.T) (canonical, legacy string) {
	t.Helper()
	root := t.TempDir()
	return filepath.Join(root, "canonical"), filepath.Join(root, "legacy")
}

const knownID = "0192f3c1-7a2b-7def-8000-aabbccddeeff"

// ── the id already exists, in the OLD place ──────────────────────────────────

// The headline regression. A legacy id must be READ, never replaced.
func TestProcessInstall_LegacyIDIsHonoredNotReplaced(t *testing.T) {
	clearTelemetryEnv(t)
	canonical, legacy := twoDirs(t)
	writeInstallID(t, legacy, knownID)
	withInstallDirs(t, canonical, legacy)

	got, err := ProcessInstall()
	if err != nil {
		t.Fatalf("ProcessInstall: %v", err)
	}
	if got.ID != knownID {
		t.Fatalf("ProcessInstall = %q, want the id already on disk %q. Minting over an "+
			"existing install_id makes every upgraded machine look like a brand-new "+
			"install and orphans the alias linking it to its account.", got.ID, knownID)
	}
	if again, err := ProcessInstall(); err != nil || again.ID != knownID {
		t.Fatalf("second ProcessInstall = %+v, %v; want the same id", again, err)
	}
}

func TestProcessInstall_MigratesLegacyIDToCanonical(t *testing.T) {
	clearTelemetryEnv(t)
	canonical, legacy := twoDirs(t)
	writeInstallID(t, legacy, knownID)
	withInstallDirs(t, canonical, legacy)

	if _, err := ProcessInstall(); err != nil {
		t.Fatalf("ProcessInstall: %v", err)
	}

	got, found := readInstallID(t, canonical)
	if !found {
		t.Fatal("the legacy id was not copied into the canonical directory; the split-brain survives the fix")
	}
	if got != knownID {
		t.Fatalf("canonical install_id = %q, want the unchanged legacy value %q", got, knownID)
	}

	// The legacy file stays. An older chainsaw binary on the same machine
	// (a system package beside a `go install`ed build) must still find an
	// id rather than minting a second one for a machine that has one.
	if _, still := readInstallID(t, legacy); !still {
		t.Error("the legacy install_id was deleted; an older binary on this machine would now mint a duplicate id")
	}
}

// After migration the canonical copy alone is enough — prove it by removing
// the legacy directory entirely and restarting.
func TestProcessInstall_SurvivesLegacyDirectoryRemovalAfterMigration(t *testing.T) {
	clearTelemetryEnv(t)
	canonical, legacy := twoDirs(t)
	writeInstallID(t, legacy, knownID)
	withInstallDirs(t, canonical, legacy)

	if _, err := ProcessInstall(); err != nil {
		t.Fatalf("ProcessInstall: %v", err)
	}
	if err := os.RemoveAll(legacy); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}
	ResetProcessInstall() // simulate the next process

	got, err := ProcessInstall()
	if err != nil {
		t.Fatalf("ProcessInstall after legacy removal: %v", err)
	}
	if got.ID != knownID {
		t.Fatalf("ProcessInstall = %q after the legacy dir was removed, want %q", got.ID, knownID)
	}
}

// The sticky opt-out sentinel must migrate too. If only real UUIDs moved, a
// macOS user who opted out before the fix would silently be re-minted and
// start being counted again.
func TestProcessInstall_MigratesTheDisabledSentinel(t *testing.T) {
	clearTelemetryEnv(t)
	canonical, legacy := twoDirs(t)
	writeInstallID(t, legacy, installIDDisabled)
	withInstallDirs(t, canonical, legacy)

	got, err := ProcessInstall()
	if err != nil {
		t.Fatalf("ProcessInstall: %v", err)
	}
	if !got.Disabled || got.ID != "" {
		t.Fatalf("ProcessInstall = %+v, want the opted-out record; a legacy opt-out must not be re-minted", got)
	}
	if val, found := readInstallID(t, canonical); !found || val != installIDDisabled {
		t.Fatalf("canonical holds %q (found=%v), want the %q sentinel", val, found, installIDDisabled)
	}
}

// ── the migration fails ──────────────────────────────────────────────────────

// A machine that cannot complete the copy keeps working off the legacy file.
// Losing the id, or crashing, are both worse than never migrating.
func TestProcessInstall_FailedMigrationStillReturnsTheLegacyID(t *testing.T) {
	clearTelemetryEnv(t)
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	canonical, legacy := twoDirs(t)
	writeInstallID(t, legacy, knownID)
	if err := os.MkdirAll(canonical, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.Chmod(canonical, 0o500); err != nil {
		t.Fatalf("Chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(canonical, 0o755) })
	withInstallDirs(t, canonical, legacy)

	got, err := ProcessInstall()
	if err != nil {
		t.Fatalf("ProcessInstall returned an error for an unwritable canonical dir: %v; "+
			"a best-effort migration must not fail the caller", err)
	}
	if got.ID != knownID {
		t.Fatalf("ProcessInstall = %q, want the legacy id %q to survive a failed migration", got.ID, knownID)
	}
	if _, found := readInstallID(t, legacy); !found {
		t.Fatal("the legacy install_id was removed even though the copy failed; the id is now gone for good")
	}

	// Still stable on the next process, still reading from legacy.
	ResetProcessInstall()
	again, err := ProcessInstall()
	if err != nil || again.ID != knownID {
		t.Fatalf("second process = %+v, %v; want the same legacy id", again, err)
	}
}

// ── no id anywhere ───────────────────────────────────────────────────────────

func TestProcessInstall_MintsExactlyOnceIntoTheCanonicalDir(t *testing.T) {
	clearTelemetryEnv(t)
	canonical, legacy := twoDirs(t)
	withInstallDirs(t, canonical, legacy)

	got, err := ProcessInstall()
	if err != nil || got.ID == "" {
		t.Fatalf("ProcessInstall = %+v, %v; want a freshly minted id", got, err)
	}
	minted, found := readInstallID(t, canonical)
	if !found {
		t.Fatal("nothing was written to the canonical directory")
	}
	if minted != got.ID {
		t.Fatalf("canonical holds %q but ProcessInstall returned %q", minted, got.ID)
	}
	if _, found := readInstallID(t, legacy); found {
		t.Error("a new id was written into the LEGACY directory; new installs must only ever populate the canonical one")
	}

	// "Exactly once": three more simulated processes must all reuse it.
	for i := 0; i < 3; i++ {
		ResetProcessInstall()
		again, err := ProcessInstall()
		if err != nil {
			t.Fatalf("ProcessInstall #%d: %v", i, err)
		}
		if again.ID != got.ID {
			t.Fatalf("install_id changed between processes: %q then %q", got.ID, again.ID)
		}
	}
}

// ── reading status must still not mint ───────────────────────────────────────

// The lazy-mint property a prior wave established: inspecting your privacy
// state must not create the identifier being inspected. Widening the search
// to a second directory must not have widened the write path with it.
func TestPeekProcessInstall_MintsNothingInEitherDirectory(t *testing.T) {
	clearTelemetryEnv(t)
	canonical, legacy := twoDirs(t)
	withInstallDirs(t, canonical, legacy)

	install, found, err := PeekProcessInstall()
	if err != nil {
		t.Fatalf("PeekProcessInstall: %v", err)
	}
	if found || install.ID != "" {
		t.Fatalf("PeekProcessInstall = %+v, found %v; want nothing on a machine with no record", install, found)
	}
	for _, dir := range []string{canonical, legacy} {
		if _, err := os.Stat(filepath.Join(dir, installFilename)); !os.IsNotExist(err) {
			t.Errorf("a status read minted an install_id in %s", dir)
		}
	}
}

// A peek that finds a legacy id reports it, but must not migrate it: a
// migration is a write, and the promise is that a status read writes nothing.
func TestPeekProcessInstall_ReadsLegacyWithoutWriting(t *testing.T) {
	clearTelemetryEnv(t)
	canonical, legacy := twoDirs(t)
	writeInstallID(t, legacy, knownID)
	withInstallDirs(t, canonical, legacy)

	install, found, err := PeekProcessInstall()
	if err != nil || !found {
		t.Fatalf("PeekProcessInstall = found %v, %v; want the legacy record", found, err)
	}
	if install.ID != knownID {
		t.Fatalf("PeekProcessInstall = %q, want %q", install.ID, knownID)
	}
	if _, err := os.Stat(canonical); !os.IsNotExist(err) {
		t.Errorf("a status read created the canonical directory (%v); peeks must not write", err)
	}

	// Repeated peeks stay stable and stay read-only.
	for i := 0; i < 3; i++ {
		again, found, err := PeekProcessInstall()
		if err != nil || !found || again.ID != knownID {
			t.Fatalf("PeekProcessInstall #%d = %+v, found %v, %v", i, again, found, err)
		}
	}
}

// ── reset ────────────────────────────────────────────────────────────────────

// A reset that cleared only the canonical copy would be undone by the next
// run re-reading the legacy one: the user asks to be forgotten and gets their
// old id straight back.
func TestResetInstall_ClearsTheLegacyCopyToo(t *testing.T) {
	clearTelemetryEnv(t)
	canonical, legacy := twoDirs(t)
	writeInstallID(t, legacy, knownID)
	withInstallDirs(t, canonical, legacy)

	if _, err := ProcessInstall(); err != nil {
		t.Fatalf("ProcessInstall: %v", err)
	}
	if err := ResetInstall(canonical); err != nil {
		t.Fatalf("ResetInstall: %v", err)
	}
	for _, dir := range []string{canonical, legacy} {
		if _, found := readInstallID(t, dir); found {
			t.Errorf("install_id survived the reset in %s", dir)
		}
	}

	ResetProcessInstall()
	got, err := ProcessInstall()
	if err != nil || got.ID == "" {
		t.Fatalf("ProcessInstall after reset = %+v, %v", got, err)
	}
	if got.ID == knownID {
		t.Fatal("`telemetry reset` handed the user their old id back from the legacy directory")
	}
}

// ResetInstall against some other directory must not reach out to the real
// canonical/legacy pair — that is what keeps single-directory callers (tests,
// and anything holding an explicit path) isolated.
func TestResetInstall_NonCanonicalDirTouchesOnlyThatDir(t *testing.T) {
	clearTelemetryEnv(t)
	canonical, legacy := twoDirs(t)
	writeInstallID(t, legacy, knownID)
	writeInstallID(t, canonical, knownID)
	withInstallDirs(t, canonical, legacy)

	other := t.TempDir()
	writeInstallID(t, other, "unrelated")
	if err := ResetInstall(other); err != nil {
		t.Fatalf("ResetInstall: %v", err)
	}
	if _, found := readInstallID(t, other); found {
		t.Error("ResetInstall did not clear the directory it was given")
	}
	for _, dir := range []string{canonical, legacy} {
		if _, found := readInstallID(t, dir); !found {
			t.Errorf("ResetInstall(%s) also cleared %s", other, dir)
		}
	}
}

// ── the single-directory API stays single-directory ──────────────────────────

// PeekInstall/LoadInstall take an explicit dir and must not consult anything
// else. If they walked the legacy list, every test calling LoadInstall with a
// t.TempDir() would start reading the developer's real install record.
func TestLoadInstall_IgnoresTheLegacyListEntirely(t *testing.T) {
	clearTelemetryEnv(t)
	canonical, legacy := twoDirs(t)
	writeInstallID(t, legacy, knownID)
	withInstallDirs(t, canonical, legacy)

	scratch := t.TempDir()
	got, err := LoadInstall(scratch)
	if err != nil {
		t.Fatalf("LoadInstall: %v", err)
	}
	if got.ID == knownID {
		t.Fatal("LoadInstall(dir) reached into the legacy directory; the explicit-dir API must stay explicit")
	}
	if _, found := readInstallID(t, scratch); !found {
		t.Error("LoadInstall did not mint into the directory it was given")
	}
}
