package hook

// backupsfor_test.go covers BackupsFor / PurgeBackups (L-08).
//
// The interesting case is sbt: it writes THREE files per scope
// (repositories, credentials, the coursier env snippet) and two of them
// carry the plaintext client_id:client_secret. A disclosure built on
// ConfigPathForScope instead of ConfigPathsForScope reports one third of
// the exposure and looks correct in a single-file test — so the sbt case
// is the one this file exists for.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// seedBackups writes n fake chainsaw backups next to path and returns them.
func seedBackups(t *testing.T, path string, stamps ...string) []string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	out := make([]string, 0, len(stamps))
	for _, s := range stamps {
		p := path + ".chainsaw.bak." + s
		if err := os.WriteFile(p, []byte("client_id:client_secret\n"), 0o600); err != nil {
			t.Fatalf("seed backup: %v", err)
		}
		out = append(out, p)
	}
	return out
}

func TestBackupsForReportsEveryScopeFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	sbtDir := filepath.Join(dir, ".sbt")
	repos := filepath.Join(sbtDir, "repositories")
	creds := filepath.Join(sbtDir, "credentials")
	env := filepath.Join(sbtDir, "chainsaw-coursier-env.sh")

	// One backup per file. Two of these three hold the secret, and the
	// manager's ConfigPathForScope only knows about `repositories`.
	var want []string
	want = append(want, seedBackups(t, repos, "20260101-000000.000000000")...)
	want = append(want, seedBackups(t, creds, "20260101-000000.000000000")...)
	want = append(want, seedBackups(t, env, "20260101-000000.000000000")...)

	got, err := BackupsFor(sbtManager{}, ScopeProject)
	if err != nil {
		t.Fatalf("BackupsFor: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("BackupsFor returned %d backups, want 3 (one per sbt config file): %v", len(got), got)
	}
	sort.Strings(got)
	sort.Strings(want)
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("BackupsFor[%d] = %q, want %q", i, got[i], want[i])
		}
	}

	// A single-file manager still works and reports only its own file.
	npmrc := filepath.Join(dir, ".npmrc")
	seedBackups(t, npmrc, "20260101-000000.000000000")
	npmGot, err := BackupsFor(npmManager{}, ScopeProject)
	if err != nil {
		t.Fatalf("BackupsFor(npm): %v", err)
	}
	if len(npmGot) != 1 || npmGot[0] != npmrc+".chainsaw.bak.20260101-000000.000000000" {
		t.Fatalf("BackupsFor(npm) = %v, want exactly the one .npmrc backup", npmGot)
	}
}

func TestBackupsForOrdersNewestFirst(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	npmrc := filepath.Join(dir, ".npmrc")
	seedBackups(t, npmrc,
		"20260101-000000.000000000",
		"20260601-120000.000000000",
		"20260301-120000.000000000",
	)
	got, err := BackupsFor(npmManager{}, ScopeProject)
	if err != nil {
		t.Fatalf("BackupsFor: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("want 3 backups, got %v", got)
	}
	if !strings.HasSuffix(got[0], "20260601-120000.000000000") {
		t.Fatalf("newest backup should sort first, got %v", got)
	}
	if !strings.HasSuffix(got[2], "20260101-000000.000000000") {
		t.Fatalf("oldest backup should sort last, got %v", got)
	}
}

func TestBackupsForIsEmptyWhenNothingWasBackedUp(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	got, err := BackupsFor(npmManager{}, ScopeProject)
	if err != nil {
		t.Fatalf("BackupsFor: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want no backups, got %v", got)
	}
}

func TestPurgeBackupsRemovesEveryScopeFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	sbtDir := filepath.Join(dir, ".sbt")
	seedBackups(t, filepath.Join(sbtDir, "repositories"), "20260101-000000.000000000")
	seedBackups(t, filepath.Join(sbtDir, "credentials"), "20260101-000000.000000000")
	seedBackups(t, filepath.Join(sbtDir, "chainsaw-coursier-env.sh"), "20260101-000000.000000000")

	removed, err := PurgeBackups(sbtManager{}, ScopeProject)
	if err != nil {
		t.Fatalf("PurgeBackups: %v", err)
	}
	if len(removed) != 3 {
		t.Fatalf("PurgeBackups removed %d files, want 3: %v", len(removed), removed)
	}
	left, err := BackupsFor(sbtManager{}, ScopeProject)
	if err != nil {
		t.Fatalf("BackupsFor after purge: %v", err)
	}
	if len(left) != 0 {
		t.Fatalf("backups survived the purge: %v", left)
	}
}
