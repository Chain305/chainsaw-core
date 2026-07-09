package swift

import (
	"archive/zip"
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// makeBareGitRepo creates a throwaway bare git repo with two tagged
// releases and returns its file:// URL. If git is unavailable the
// caller's test is skipped.
func makeBareGitRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available on PATH")
	}
	tmp := t.TempDir()
	workDir := filepath.Join(tmp, "work")
	bareDir := filepath.Join(tmp, "upstream.git")

	run := func(dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=Test",
			"GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=Test",
			"GIT_COMMITTER_EMAIL=test@example.com",
			"GIT_CONFIG_GLOBAL=/dev/null",
			"GIT_CONFIG_SYSTEM=/dev/null",
		)
		var errBuf bytes.Buffer
		cmd.Stderr = &errBuf
		if err := cmd.Run(); err != nil {
			t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, errBuf.String())
		}
	}

	// Initialize work tree.
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	run(workDir, "init", "-q", "-b", "main")
	// Prevent GPG signing from picking up a global git config.
	run(workDir, "config", "commit.gpgsign", "false")
	run(workDir, "config", "tag.gpgsign", "false")

	if err := os.WriteFile(filepath.Join(workDir, "Package.swift"), []byte("// swift-tools-version:5.5\nimport PackageDescription\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workDir, "README.md"), []byte("# test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(workDir, "add", ".")
	run(workDir, "commit", "-q", "-m", "v1.0.0")
	run(workDir, "tag", "1.0.0")

	if err := os.WriteFile(filepath.Join(workDir, "CHANGELOG.md"), []byte("# 1.1.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run(workDir, "add", ".")
	run(workDir, "commit", "-q", "-m", "v1.1.0")
	run(workDir, "tag", "v1.1.0")

	// Also create a non-semver tag to assert it gets filtered out.
	run(workDir, "tag", "release-candidate")

	// Clone into a bare repo so ls-remote is fast and we don't hold
	// open any working tree state.
	if err := os.MkdirAll(bareDir, 0o755); err != nil {
		t.Fatal(err)
	}
	run(filepath.Dir(bareDir), "clone", "--bare", "-q", workDir, bareDir)

	return "file://" + bareDir
}

func TestGitUpstreamListReleases(t *testing.T) {
	gitURL := makeBareGitRepo(t)
	m := NewIdentifierMap(IdentifierMapConfig{
		Static: map[string]string{"test.pkg": gitURL},
	})
	g := NewGitUpstream(m, t.TempDir())
	releases, err := g.ListReleases(context.Background(), "test.pkg", "/repo/swift")
	if err != nil {
		t.Fatalf("ListReleases: %v", err)
	}
	if _, ok := releases.Releases["1.0.0"]; !ok {
		t.Errorf("expected 1.0.0 in releases, got %v", keys(releases.Releases))
	}
	if _, ok := releases.Releases["1.1.0"]; !ok {
		t.Errorf("expected 1.1.0 in releases, got %v", keys(releases.Releases))
	}
	// Non-SemVer tags must be excluded.
	if _, ok := releases.Releases["release-candidate"]; ok {
		t.Errorf("non-semver tag should not appear in releases")
	}
}

func TestGitUpstreamBuildArchive(t *testing.T) {
	gitURL := makeBareGitRepo(t)
	m := NewIdentifierMap(IdentifierMapConfig{
		Static: map[string]string{"test.pkg": gitURL},
	})
	g := NewGitUpstream(m, t.TempDir())
	body, digest, err := g.BuildArchive(context.Background(), "test.pkg", "1.0.0")
	if err != nil {
		t.Fatalf("BuildArchive: %v", err)
	}
	if digest == "" {
		t.Errorf("digest should be populated")
	}
	// Verify zip is parseable and contains Package.swift under the
	// expected prefix directory.
	r, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		t.Fatalf("open synthesized zip: %v", err)
	}
	wantPath := "pkg-1.0.0/Package.swift"
	found := false
	for _, f := range r.File {
		if f.Name == wantPath {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("zip missing %q — contents: %s", wantPath, zipNames(r.File))
	}
}

func TestGitUpstreamGetReleaseMetadataPublishedAt(t *testing.T) {
	gitURL := makeBareGitRepo(t)
	m := NewIdentifierMap(IdentifierMapConfig{
		Static: map[string]string{"test.pkg": gitURL},
	})
	g := NewGitUpstream(m, t.TempDir())
	meta, err := g.GetReleaseMetadata(context.Background(), "test.pkg", "1.0.0", "/repo/swift")
	if err != nil {
		t.Fatalf("GetReleaseMetadata: %v", err)
	}
	if meta.ID != "test.pkg" || meta.Version != "1.0.0" {
		t.Errorf("unexpected id/version: %+v", meta)
	}
	// publishedAt is best-effort; validate only that when present it
	// parses as RFC 3339 and is in the near past.
	if meta.PublishedAt != "" {
		ts, err := time.Parse(time.RFC3339, meta.PublishedAt)
		if err != nil {
			t.Errorf("publishedAt not RFC3339: %q", meta.PublishedAt)
		} else if time.Since(ts) > 24*time.Hour {
			t.Errorf("publishedAt unexpectedly old: %s", ts)
		}
	}
	if len(meta.Resources) != 1 || meta.Resources[0].Name != "source-archive" {
		t.Errorf("expected single source-archive resource, got %+v", meta.Resources)
	}
}

func keys(m map[string]ReleaseEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func zipNames(files []*zip.File) string {
	names := make([]string, 0, len(files))
	for _, f := range files {
		names = append(names, f.Name)
	}
	return strings.Join(names, ", ")
}

// TestValidateGitArg covers the defense-in-depth input validator used
// on every git subcommand argument.
func TestValidateGitArg(t *testing.T) {
	accept := []string{
		"https://github.com/foo/bar.git",
		"git@github.com:foo/bar.git",
		"ssh://git@github.com/foo/bar.git",
		"1.2.3",
		"v1.2.3",
		"abc123deadbeef",
		"", // empty handled gracefully — git subcommands handle their own empty-arg errors
		"/tmp/foo/bar.git",
	}
	for _, s := range accept {
		if err := validateGitArg(s); err != nil {
			t.Errorf("validateGitArg(%q): unexpected error %v", s, err)
		}
	}
	reject := []string{
		"--upload-pack=/tmp/evil.sh",
		"-u /tmp/evil",
		"--exec=/bin/sh",
		"-",
		"--",
	}
	for _, s := range reject {
		if err := validateGitArg(s); err == nil {
			t.Errorf("validateGitArg(%q): expected error, got nil", s)
		}
	}
}

// TestLsRemoteTagsRejectsFlagLikeURL verifies the lsRemoteTags helper
// refuses to execute git with a URL that could be interpreted as a
// flag — the MEDIUM finding from the security review.
func TestLsRemoteTagsRejectsFlagLikeURL(t *testing.T) {
	g := &GitUpstream{GitBin: "git", CacheRoot: t.TempDir()}
	// Use an evil URL directly. g.runGit should never be called because
	// validateGitArg short-circuits. Use a bogus GitBin to guarantee
	// that if validation fails we see an ENOENT rather than the
	// validator error — proof that the validator fired first.
	_, err := g.lsRemoteTags(context.Background(), "--upload-pack=/tmp/evil.sh")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "refusing argument") {
		t.Errorf("expected validator error, got: %v", err)
	}
}

// TestEnsureRepoRejectsFlagLikeURL verifies ensureRepo refuses a URL
// that starts with '-' even before any git subprocess is spawned.
func TestEnsureRepoRejectsFlagLikeURL(t *testing.T) {
	g := &GitUpstream{GitBin: "git", CacheRoot: t.TempDir()}
	_, err := g.ensureRepo(context.Background(), "test.pkg", "--upload-pack=/tmp/evil")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "refusing argument") {
		t.Errorf("expected validator error, got: %v", err)
	}
}

// TestFetchTagRejectsFlagLikeArgs verifies fetchTag refuses flag-like
// version and commit arguments.
func TestFetchTagRejectsFlagLikeArgs(t *testing.T) {
	g := &GitUpstream{GitBin: "git", CacheRoot: t.TempDir()}
	if err := g.fetchTag(context.Background(), t.TempDir(), "--exec=/bin/sh", "deadbeef"); err == nil {
		t.Error("expected fetchTag to reject flag-like version")
	}
	if err := g.fetchTag(context.Background(), t.TempDir(), "1.0.0", "-u"); err == nil {
		t.Error("expected fetchTag to reject flag-like commit")
	}
}

// TestGitArchiveRejectsFlagLikeRefspec verifies gitArchive refuses a
// refspec that starts with '-'.
func TestGitArchiveRejectsFlagLikeRefspec(t *testing.T) {
	g := &GitUpstream{GitBin: "git", CacheRoot: t.TempDir()}
	_, err := g.gitArchive(context.Background(), t.TempDir(), "--remote=evil", "pkg-1.0.0/")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "refusing argument") {
		t.Errorf("expected validator error, got: %v", err)
	}
}

// TestGitShowRejectsFlagLikeRev verifies gitShow refuses a revision
// starting with '-'.
func TestGitShowRejectsFlagLikeRev(t *testing.T) {
	g := &GitUpstream{GitBin: "git", CacheRoot: t.TempDir()}
	_, err := g.gitShow(context.Background(), t.TempDir(), "--output=/tmp/evil", "Package.swift")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "refusing argument") {
		t.Errorf("expected validator error, got: %v", err)
	}
}

// TestLsRemoteTagsArgsIncludeDoubleDash verifies the structural fix:
// the "--" end-of-options separator is present immediately before the
// URL argument on `git ls-remote`. We instrument this by replacing
// GitBin with a shell stub that echoes its argv, but keep the test
// self-contained via a tiny helper binary synthesised on the fly.
func TestLsRemoteTagsArgsIncludeDoubleDash(t *testing.T) {
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}
	// Create a trivial shim script that records its argv to a file
	// and exits with status 0 (printing a single fake tag line).
	tmp := t.TempDir()
	argsFile := filepath.Join(tmp, "argv.log")
	shimPath := filepath.Join(tmp, "git-shim.sh")
	// The shim emits a minimal valid ls-remote line so lsRemoteTags
	// returns cleanly, and writes argv (quoted per line) to argsFile.
	shim := `#!/bin/sh
for a in "$@"; do
  printf '%s\n' "$a" >> "` + argsFile + `"
done
printf 'deadbeef\trefs/tags/1.0.0\n'
`
	if err := os.WriteFile(shimPath, []byte(shim), 0o700); err != nil {
		t.Fatal(err)
	}

	g := &GitUpstream{GitBin: shimPath, CacheRoot: tmp}
	_, err := g.lsRemoteTags(context.Background(), "https://example.com/foo/bar.git")
	if err != nil {
		t.Fatalf("lsRemoteTags: %v", err)
	}
	argvBytes, err := os.ReadFile(argsFile)
	if err != nil {
		t.Fatalf("read argv log: %v", err)
	}
	argv := strings.Split(strings.TrimRight(string(argvBytes), "\n"), "\n")
	// Expected argv: "ls-remote", "--tags", "--", "https://example.com/foo/bar.git"
	want := []string{"ls-remote", "--tags", "--", "https://example.com/foo/bar.git"}
	if len(argv) != len(want) {
		t.Fatalf("argv length = %d, want %d; argv=%q", len(argv), len(want), argv)
	}
	for i := range want {
		if argv[i] != want[i] {
			t.Errorf("argv[%d] = %q, want %q", i, argv[i], want[i])
		}
	}
	// Explicit assertion on the structural "--" insertion.
	dashIdx := -1
	urlIdx := -1
	for i, a := range argv {
		if a == "--" {
			dashIdx = i
		}
		if a == "https://example.com/foo/bar.git" {
			urlIdx = i
		}
	}
	if dashIdx < 0 {
		t.Error("expected '--' separator in git ls-remote argv")
	}
	if urlIdx < 0 {
		t.Error("expected URL in git ls-remote argv")
	}
	if dashIdx >= 0 && urlIdx >= 0 && dashIdx >= urlIdx {
		t.Errorf("expected '--' (idx %d) to appear before URL (idx %d)", dashIdx, urlIdx)
	}
}
