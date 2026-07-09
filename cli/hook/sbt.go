package hook

// sbtManager wires sbt (Scala Build Tool) — which is uniquely painful
// because authenticated chainsaw proxy access requires THREE pieces of
// wiring, not one (Wave X live-verify against chain305.com).
//
// Discovered by Wave V #102 smoke run (evidence:
// qa/smoke-evidence/20260524-wave-V/48_sbt_happy.txt). Real `sbt update`
// against chain305.com needs:
//
//  1. ~/.sbt/repositories — selects the resolver chain (otherwise sbt
//     hits repo1.maven.org directly and never touches chain305).
//
//  2. ~/.sbt/credentials — required EXACTLY `realm=Chainsaw repository`.
//     Generic realm strings ("Sonatype Nexus Repository Manager", etc)
//     silently fail authentication with no diagnostic — the proxy
//     returns 401 and sbt prints "unresolved dependency" with no hint
//     that creds were even rejected.
//
//  3. COURSIER_CREDENTIALS env var — coursier (sbt's bootstrap
//     resolver, runs BEFORE build.sbt is parsed) ignores
//     ~/.sbt/credentials. The ONLY form coursier honors for bootstrap
//     is the env var: `host user:password`. Without it, the very first
//     sbt resolution (bootstrap) fails before user-level credentials
//     are loaded, and `sbt update` fails with no actionable diagnostic.
//
// sbt has no idiomatic place to set env vars, so the third piece is
// emitted as a shell snippet at ~/.sbt/chainsaw-coursier-env.sh that
// the user is told to source from their shell profile. The Wire path's
// stdout (in install_hook.go) reports the export line so customers
// don't have to read the file.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

type sbtManager struct{}

func (sbtManager) Name() string { return "sbt" }

func (sbtManager) IsInstalled() bool {
	_, err := exec.LookPath("sbt")
	return err == nil
}

func (m sbtManager) ConfigPath() (string, error) {
	return m.ConfigPathForScope(ScopeUser)
}

// ConfigPathForScope returns the primary file (~/.sbt/repositories).
// Wire also touches credentials and chainsaw-coursier-env.sh in the
// same directory — see sbtCredentialsPath and sbtCoursierEnvPath.
func (sbtManager) ConfigPathForScope(scope Scope) (string, error) {
	dir, err := sbtConfigDir(scope)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "repositories"), nil
}

// sbtConfigDir resolves the .sbt directory for the given scope. Project
// scope uses ./.sbt so a per-repo override is possible (sbt honors
// `-Dsbt.global.base=./.sbt` at invocation time). System scope is
// uncommon for sbt — there's no machine-wide path — so it returns an
// error pointing the caller at user scope.
func sbtConfigDir(scope Scope) (string, error) {
	switch scope {
	case ScopeProject:
		cwd, err := os.Getwd()
		if err != nil || cwd == "" {
			return "", fmt.Errorf("resolve working dir: %w", err)
		}
		return filepath.Join(cwd, ".sbt"), nil
	case ScopeSystem:
		return "", fmt.Errorf("sbt has no system-wide config location; use --scope user")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".sbt"), nil
}

func sbtRepositoriesPath(scope Scope) (string, error) {
	dir, err := sbtConfigDir(scope)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "repositories"), nil
}

func sbtCredentialsPath(scope Scope) (string, error) {
	dir, err := sbtConfigDir(scope)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "credentials"), nil
}

func sbtCoursierEnvPath(scope Scope) (string, error) {
	dir, err := sbtConfigDir(scope)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "chainsaw-coursier-env.sh"), nil
}

func (m sbtManager) Wire(opts WireOpts) error {
	// Validate credentials up-front so we don't half-write three files
	// then fail on the third. Mirrors bun.go's pattern.
	if creds := strings.TrimSpace(opts.Credentials); creds != "" {
		if _, _, ok := splitCreds(creds); !ok {
			return fmt.Errorf("credentials: expected \"client_id:client_secret\"")
		}
	}
	// Validate ServerURL the same way — empty is allowed (placeholder
	// mode), but a non-empty bad URL must fail BEFORE we touch any file.
	if s := strings.TrimSpace(opts.ServerURL); s != "" {
		if _, err := validateServerURL(s); err != nil {
			return err
		}
	}

	reposPath, err := sbtRepositoriesPath(opts.Scope)
	if err != nil {
		return err
	}
	credsPath, err := sbtCredentialsPath(opts.Scope)
	if err != nil {
		return err
	}
	envPath, err := sbtCoursierEnvPath(opts.Scope)
	if err != nil {
		return err
	}

	reposBody, err := sbtRepositoriesBody(opts)
	if err != nil {
		return err
	}
	credsBody, err := sbtCredentialsBody(opts)
	if err != nil {
		return err
	}
	envBody, err := sbtCoursierEnvBody(opts)
	if err != nil {
		return err
	}

	if err := writeWithBackup(reposPath, reposBody); err != nil {
		return fmt.Errorf("write repositories: %w", err)
	}
	if err := writeWithBackup(credsPath, credsBody); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}
	if err := writeWithBackup(envPath, envBody); err != nil {
		return fmt.Errorf("write coursier env snippet: %w", err)
	}
	return nil
}

func (m sbtManager) Unwire(scope Scope) error {
	reposPath, err := sbtRepositoriesPath(scope)
	if err != nil {
		return err
	}
	credsPath, err := sbtCredentialsPath(scope)
	if err != nil {
		return err
	}
	envPath, err := sbtCoursierEnvPath(scope)
	if err != nil {
		return err
	}
	// At least one of the three files must contain a sentinel for Unwire
	// to claim success. We try all three and ignore ErrNotWired on the
	// ones that don't have it (user may have hand-edited one file out).
	atLeastOne := false
	for _, p := range []string{reposPath, credsPath, envPath} {
		if err := unwireBlock(p); err == nil {
			atLeastOne = true
		} else if err != ErrNotWired {
			return err
		}
	}
	if !atLeastOne {
		return ErrNotWired
	}
	return nil
}

func (m sbtManager) Status() (Status, error) {
	// Wired only if ALL THREE files carry the sentinel — anything less
	// is a half-broken install (e.g., user deleted the coursier env file
	// but kept repositories), which the customer report needs to flag.
	reposPath, err := m.ConfigPath()
	if err != nil {
		return Status{}, err
	}
	credsPath, _ := sbtCredentialsPath(ScopeUser)
	envPath, _ := sbtCoursierEnvPath(ScopeUser)
	wired := true
	for _, p := range []string{reposPath, credsPath, envPath} {
		data, err := readOrEmpty(p)
		if err != nil || !hasSentinel(data) {
			wired = false
			break
		}
	}
	return Status{
		ConfigPath: reposPath,
		Wired:      wired,
		Installed:  m.IsInstalled(),
	}, nil
}

// sbtRepositoriesBody renders the body for ~/.sbt/repositories — the
// resolver-chain selector. The format is sbt-specific: a `[repositories]`
// header followed by `name: url, pattern` lines. The pattern string is
// the Ivy artifact-pattern sbt uses for Maven-layout repos.
func sbtRepositoriesBody(opts WireOpts) (string, error) {
	const header = "# Wave X (2026-05-24): sbt resolver chain. Without this file,\n" +
		"# sbt resolves directly against repo1.maven.org and chainsaw never\n" +
		"# sees the request. See sbt.go preamble for the full three-file\n" +
		"# wiring sbt requires.\n"
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return header +
			"# Uncomment and re-run `chainsaw --server <url> install-hook sbt`\n" +
			"# to populate the real proxy URL.\n" +
			"# [repositories]\n" +
			"#   chainsaw: https://<chainsaw-server>/chainproxy/repository/@<org>/maven-central/, [organization]/[module]/[revision]/[artifact]-[revision](-[classifier]).[ext]", nil
	}
	base, err := validateServerURL(server)
	if err != nil {
		return "", err
	}
	repoPath := OrgScopedRepoPath(opts.OrgSlug, "maven-central")
	return fmt.Sprintf(`%s[repositories]
  chainsaw: %s/%s/, [organization]/[module]/[revision]/[artifact]-[revision](-[classifier]).[ext]`,
		header, base, repoPath), nil
}

// sbtCredentialsBody renders the body for ~/.sbt/credentials — Wave V
// #102 proved the realm string MUST be EXACTLY `Chainsaw repository`.
// Generic realms like `Sonatype Nexus Repository Manager` silently fail
// authentication with no diagnostic.
func sbtCredentialsBody(opts WireOpts) (string, error) {
	const header = "# Wave X (2026-05-24): sbt credentials file. The realm string\n" +
		"# below MUST be EXACTLY `Chainsaw repository` — generic realms\n" +
		"# like `Sonatype Nexus Repository Manager` silently fail (proxy\n" +
		"# returns 401, sbt prints `unresolved dependency` with no hint\n" +
		"# that creds were even rejected). Do not edit.\n"
	server := strings.TrimSpace(opts.ServerURL)
	host := "<chainsaw-server-host>"
	if server != "" {
		base, err := validateServerURL(server)
		if err != nil {
			return "", err
		}
		host = sbtHostFromURL(base)
		if host == "" {
			return "", fmt.Errorf("invalid server URL: could not derive host")
		}
	}
	creds := strings.TrimSpace(opts.Credentials)
	user, pass := "<client_id>", "<client_secret>"
	credsNote := ""
	if creds != "" {
		id, secret, ok := splitCreds(creds)
		if !ok {
			return "", fmt.Errorf("credentials: expected \"client_id:client_secret\"")
		}
		user, pass = id, secret
		credsNote = "# chainsaw: credentials embedded in cleartext (sbt's format\n" +
			"# requires it); tighten this file's permissions (chmod 600) if\n" +
			"# your home directory is shared.\n"
	}
	return fmt.Sprintf(`%s%srealm=Chainsaw repository
host=%s
user=%s
password=%s`, header, credsNote, host, user, pass), nil
}

// sbtCoursierEnvBody renders a shell snippet the user sources from
// their shell profile. coursier (sbt's bootstrap resolver) runs BEFORE
// build.sbt is parsed and ignores ~/.sbt/credentials — the ONLY form
// it honors for bootstrap is the COURSIER_CREDENTIALS env var, shaped
// `host user:password`. Without this, bootstrap resolution fails on
// the very first `sbt update`.
func sbtCoursierEnvBody(opts WireOpts) (string, error) {
	const header = "# Wave X (2026-05-24): coursier bootstrap credentials.\n" +
		"#\n" +
		"# coursier is sbt's bootstrap resolver. It runs BEFORE build.sbt\n" +
		"# is parsed and IGNORES ~/.sbt/credentials. The ONLY form it\n" +
		"# honors for bootstrap auth is the COURSIER_CREDENTIALS env var.\n" +
		"#\n" +
		"# Source this file from your shell profile (~/.bashrc, ~/.zshrc):\n" +
		"#   echo 'source ~/.sbt/chainsaw-coursier-env.sh' >> ~/.zshrc\n" +
		"#\n" +
		"# Or run `chainsaw install-hook sbt` again to see the export line\n" +
		"# printed to stdout for one-shot copy/paste.\n"
	server := strings.TrimSpace(opts.ServerURL)
	host := "<chainsaw-server-host>"
	if server != "" {
		base, err := validateServerURL(server)
		if err != nil {
			return "", err
		}
		host = sbtHostFromURL(base)
		if host == "" {
			return "", fmt.Errorf("invalid server URL: could not derive host")
		}
	}
	creds := strings.TrimSpace(opts.Credentials)
	user, pass := "<client_id>", "<client_secret>"
	if creds != "" {
		id, secret, ok := splitCreds(creds)
		if !ok {
			return "", fmt.Errorf("credentials: expected \"client_id:client_secret\"")
		}
		user, pass = id, secret
	}
	return fmt.Sprintf(`%sexport COURSIER_CREDENTIALS="%s %s:%s"`,
		header, host, user, pass), nil
}

// sbtHostFromURL returns the host (no scheme, no path) of a validated
// server URL. coursier's COURSIER_CREDENTIALS format wants just the
// host; the sbt credentials format wants the same.
func sbtHostFromURL(serverURL string) string {
	s := strings.TrimSpace(serverURL)
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(s, prefix) {
			s = s[len(prefix):]
			break
		}
	}
	if i := strings.IndexByte(s, '/'); i >= 0 {
		s = s[:i]
	}
	return s
}
