package hook

// sbt_test.go pins the Wave X sbt wire shape. Background:
//   Wave V #102 live-verify (qa/smoke-evidence/20260524-wave-V/
//   48_sbt_happy.txt) proved real `sbt update` against chain305.com
//   needs THREE pieces of wiring — none of which sbt installs itself:
//
//     1. ~/.sbt/repositories — resolver chain selector
//     2. ~/.sbt/credentials  — EXACT realm string "Chainsaw repository"
//                              (generic Nexus realms silently fail)
//     3. COURSIER_CREDENTIALS env var — coursier (sbt's bootstrap
//                              resolver) IGNORES ~/.sbt/credentials
//
// These tests are the regression guard: if anyone drops one of the
// three files or weakens the exact-realm-string assertion, CI screams.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupSbt(t *testing.T) (sbtManager, string) {
	t.Helper()
	dir := t.TempDir()
	// sbt's ScopeUser path resolution uses os.UserHomeDir which is hard
	// to override portably; use ScopeProject (which reads cwd) for the
	// unit-level tests. ScopeUser is covered by the path-shape test.
	t.Chdir(dir)
	return sbtManager{}, filepath.Join(dir, ".sbt")
}

func TestSbtManager_Name(t *testing.T) {
	if name := (sbtManager{}).Name(); name != "sbt" {
		t.Errorf("Name() = %q, want %q", name, "sbt")
	}
}

func TestSbtManager_ConfigPath_UserScope(t *testing.T) {
	m := sbtManager{}
	p, err := m.ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath: %v", err)
	}
	// ConfigPath must land inside the .sbt directory and point at the
	// repositories file (the primary file of the three).
	if filepath.Base(p) != "repositories" {
		t.Errorf("ConfigPath base = %q, want %q", filepath.Base(p), "repositories")
	}
	if filepath.Base(filepath.Dir(p)) != ".sbt" {
		t.Errorf("ConfigPath parent = %q, want %q", filepath.Base(filepath.Dir(p)), ".sbt")
	}
}

func TestSbtManager_ConfigPath_ProjectScope(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	p, err := (sbtManager{}).ConfigPathForScope(ScopeProject)
	if err != nil {
		t.Fatalf("ConfigPathForScope(project): %v", err)
	}
	if !strings.HasPrefix(p, dir) {
		t.Errorf("project path %q not under cwd %q", p, dir)
	}
	if filepath.Base(p) != "repositories" {
		t.Errorf("project path base = %q, want %q", filepath.Base(p), "repositories")
	}
}

func TestSbtManager_ConfigPath_SystemScopeRejected(t *testing.T) {
	// sbt has no machine-wide config; system scope must error so the
	// caller doesn't silently get a user-scope file.
	_, err := (sbtManager{}).ConfigPathForScope(ScopeSystem)
	if err == nil {
		t.Error("ConfigPathForScope(system) returned nil error; want rejection")
	}
}

func TestSbtManager_Wire_WritesAllThreeFiles(t *testing.T) {
	// The whole point of the sbt hook is that one file isn't enough.
	// Wire MUST write repositories, credentials, AND the coursier env
	// snippet — Wave V #102 evidence.
	m, dir := setupSbt(t)
	opts := WireOpts{
		Scope:       ScopeProject,
		ServerURL:   "https://chain305.com/",
		OrgSlug:     "acme",
		Credentials: "client-x:secret-y",
	}
	if err := m.Wire(opts); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	for _, name := range []string{"repositories", "credentials", "chainsaw-coursier-env.sh"} {
		p := filepath.Join(dir, name)
		data, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("missing required file %s: %v", name, err)
			continue
		}
		if !hasSentinel(data) {
			t.Errorf("%s missing sentinel block:\n%s", name, data)
		}
	}
}

func TestSbtManager_Wire_RealmStringExact(t *testing.T) {
	// Wave V #102: the realm string in ~/.sbt/credentials MUST be
	// EXACTLY `realm=Chainsaw repository`. Generic realms like
	// `Sonatype Nexus Repository Manager` silently fail authentication
	// with no diagnostic. This is the on-the-wire invariant.
	m, dir := setupSbt(t)
	opts := WireOpts{
		Scope:       ScopeProject,
		ServerURL:   "https://chain305.com/",
		OrgSlug:     "acme",
		Credentials: "id-1:secret-2",
	}
	if err := m.Wire(opts); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "credentials"))
	if err != nil {
		t.Fatalf("read credentials: %v", err)
	}
	body := string(data)
	if !strings.Contains(body, "realm=Chainsaw repository") {
		t.Errorf("credentials file MUST contain `realm=Chainsaw repository` (Wave V #102 regression):\n%s", body)
	}
	// Defense-in-depth: forbid any of the well-known wrong realms that
	// silently break sbt auth.
	for _, bad := range []string{
		"Sonatype Nexus Repository Manager",
		"Nexus",
		"Artifactory",
		"Repository Manager",
	} {
		if strings.Contains(body, "realm="+bad) {
			t.Errorf("credentials file contains wrong realm %q (silently fails sbt auth):\n%s", bad, body)
		}
	}
}

func TestSbtManager_Wire_CoursierEnvSnippetPresent(t *testing.T) {
	// Without COURSIER_CREDENTIALS, sbt's bootstrap resolver (coursier)
	// fails BEFORE ~/.sbt/credentials is even consulted. The shell
	// snippet must export the env var in coursier's required format:
	//   `host user:password`
	m, dir := setupSbt(t)
	opts := WireOpts{
		Scope:       ScopeProject,
		ServerURL:   "https://chain305.com/",
		OrgSlug:     "acme",
		Credentials: "boot-id:boot-secret",
	}
	if err := m.Wire(opts); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "chainsaw-coursier-env.sh"))
	if err != nil {
		t.Fatalf("read coursier env: %v", err)
	}
	body := string(data)
	if !strings.Contains(body, "export COURSIER_CREDENTIALS=") {
		t.Errorf("coursier env file missing `export COURSIER_CREDENTIALS=` line:\n%s", body)
	}
	// coursier's required shape is `host user:password` — a single
	// space-separated value, NOT host:user:password or url-form.
	want := `export COURSIER_CREDENTIALS="chain305.com boot-id:boot-secret"`
	if !strings.Contains(body, want) {
		t.Errorf("coursier env line wrong shape;\nwant: %s\ngot:\n%s", want, body)
	}
}

func TestSbtManager_Wire_RepositoriesUsesOrgScopedURL(t *testing.T) {
	// BUG-A6: every install-hook ecosystem URL must be org-scoped
	// (/repository/@<orgSlug>/...) or the proxy rejects with CHW-4314.
	m, dir := setupSbt(t)
	opts := WireOpts{
		Scope:     ScopeProject,
		ServerURL: "https://chain305.com/",
		OrgSlug:   "acme-corp",
	}
	if err := m.Wire(opts); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "repositories"))
	if err != nil {
		t.Fatalf("read repositories: %v", err)
	}
	body := string(data)
	want := "chainproxy/repository/@acme-corp/maven-central/"
	if !strings.Contains(body, want) {
		t.Errorf("repositories missing org-scoped URL %q:\n%s", want, body)
	}
	// Also verify the [repositories] header (selects the resolver
	// chain — without it sbt ignores the file).
	if !strings.Contains(body, "[repositories]") {
		t.Errorf("repositories missing [repositories] header:\n%s", body)
	}
}

func TestSbtManager_Wire_RejectsMalformedCreds(t *testing.T) {
	// Up-front credential validation — must reject BEFORE touching any
	// of the three files. The wire must not leave a half-written state.
	m, dir := setupSbt(t)
	err := m.Wire(WireOpts{
		Scope:       ScopeProject,
		ServerURL:   "https://chain305.com/",
		OrgSlug:     "acme",
		Credentials: "no-colon-here",
	})
	if err == nil || !strings.Contains(err.Error(), "credentials") {
		t.Errorf("expected credentials error, got %v", err)
	}
	// No file should exist after a rejected Wire.
	for _, name := range []string{"repositories", "credentials", "chainsaw-coursier-env.sh"} {
		p := filepath.Join(dir, name)
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Errorf("file %s exists after rejected Wire; stat err = %v", name, statErr)
		}
	}
}

func TestSbtManager_Wire_RejectsControlCharURL(t *testing.T) {
	m, dir := setupSbt(t)
	err := m.Wire(WireOpts{Scope: ScopeProject, ServerURL: "https://foo.example/%0Aevil"})
	if err == nil || !strings.Contains(err.Error(), "invalid server URL") {
		t.Errorf("expected invalid server URL error, got %v", err)
	}
	for _, name := range []string{"repositories", "credentials", "chainsaw-coursier-env.sh"} {
		p := filepath.Join(dir, name)
		if _, statErr := os.Stat(p); !os.IsNotExist(statErr) {
			t.Errorf("file %s exists after rejected Wire; stat err = %v", name, statErr)
		}
	}
}

func TestSbtManager_Wire_EmptyServerUrlScaffoldsPlaceholders(t *testing.T) {
	// Empty ServerURL is the offline-scaffold path — every file gets a
	// commented template explaining the three-piece wiring.
	m, dir := setupSbt(t)
	if err := m.Wire(WireOpts{Scope: ScopeProject}); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	for _, name := range []string{"repositories", "credentials", "chainsaw-coursier-env.sh"} {
		p := filepath.Join(dir, name)
		data, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("missing %s in offline scaffold: %v", name, err)
			continue
		}
		if !strings.Contains(string(data), "Wave X") {
			t.Errorf("%s missing Wave X preamble:\n%s", name, data)
		}
	}
}

func TestSbtManager_Unwire(t *testing.T) {
	m, dir := setupSbt(t)
	// Seed a pre-existing repositories file so Unwire has user content
	// to preserve. Wire writes the block, Unwire must remove only the
	// block and leave any user content intact.
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	pre := "# my custom resolver\n"
	if err := os.WriteFile(filepath.Join(dir, "repositories"), []byte(pre), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := m.Wire(WireOpts{Scope: ScopeProject}); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	if err := m.Unwire(ScopeProject); err != nil {
		t.Fatalf("Unwire: %v", err)
	}
	// repositories should still exist, with user content preserved.
	data, err := os.ReadFile(filepath.Join(dir, "repositories"))
	if err != nil {
		t.Fatalf("read repositories after unwire: %v", err)
	}
	if hasSentinel(data) {
		t.Errorf("sentinel still present in repositories after Unwire:\n%s", data)
	}
	if !strings.Contains(string(data), "# my custom resolver") {
		t.Errorf("user content lost after Unwire:\n%s", data)
	}
}

func TestSbtManager_Unwire_NothingWiredReturnsErrNotWired(t *testing.T) {
	m, _ := setupSbt(t)
	if err := m.Unwire(ScopeProject); !errors.Is(err, ErrNotWired) {
		t.Errorf("Unwire with no files = %v, want ErrNotWired", err)
	}
}
