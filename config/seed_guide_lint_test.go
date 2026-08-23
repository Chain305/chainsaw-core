package config

// seed_guide_lint_test.go — onboarding-blocker guards on the
// client_configuration_guide prose in configs/seed.yaml (and its
// dockerized/ twin).
//
// Three defects shipped in that prose at once and every one of them was a
// 100%-reproducible failure on a brand-new user's FIRST command:
//
//  1. The registry URLs carried a host-only placeholder
//     (`your-chainsaw-server`). The dashboard substituted only
//     `new URL(proxy_url).host`, discarding the deployment's ingress base
//     path, so chain305.com prod rendered
//     `https://chain305.com/repository/@slug/npmjs/` — a 404, because the
//     package repository is served under `/chainproxy`. Guides now use the
//     `your-chainsaw-base` token wherever the substituted value is followed
//     by a `/repository/...` path, and keep `your-chainsaw-server` ONLY
//     where the consuming tool demands a bare host.
//
//  2. The npm guide instructed the reader to set the token to "the base64 of
//     CLIENT_ID:CLIENT_SECRET". npm sends `_authToken` as
//     `Authorization: Bearer <token>`, and the server
//     (extractClientCredentials -> splitTokenCredential) parses a Bearer
//     token by splitting on a literal `:`. Base64 output has no colon, so
//     the credential never resolved and every install 401'd. Cargo,
//     Hugging Face, and Swift shipped the same base64-a-Bearer-token
//     mistake.
//
//  3. No guide emitted `always-auth`. Without it npm/Yarn Classic
//     authenticate the manifest request and then omit credentials on the
//     tarball fetch, so the install 401s halfway through.
//
// The Go-side snippet generator was already covered
// (internal/server/server_configsnippets_test.go asserts the prefixed
// registry URL under X-Forwarded-Prefix). The seed prose — which is what
// the client wizard's "End users & AI agents" tab actually renders — was
// not covered at all. These guards close that gap.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// hostOnlyPlaceholder is the token that stands for a BARE host, with no
// ingress base path. Legitimate only where the consuming tool rejects a
// path in that position: docker registry hosts and image refs, pip's
// `trusted-host`, `.netrc` machine lines, and the Composer / Bundler
// credential keys.
const hostOnlyPlaceholder = "your-chainsaw-server"

// basePlaceholder stands for host[:port] + ingress base path — e.g.
// "chain305.com/chainproxy". Every repository URL in the guides must use
// this so the base path survives substitution.
const basePlaceholder = "your-chainsaw-base"

// hostOnlyBeforeRepositoryPath matches the exact regression: a host-only
// placeholder immediately followed by a `/repository` path segment.
var hostOnlyBeforeRepositoryPath = regexp.MustCompile(
	regexp.QuoteMeta(hostOnlyPlaceholder) + `(:\d+)?/repository`)

// TestSeedGuidesUseBasePlaceholderForRepositoryURLs is guard (1).
//
// Deliberately narrow: it does NOT sweep every `your-chainsaw-server` in
// the file (there are ~30 legitimate host-only uses). It fails only on the
// one shape that is provably wrong — a bare host spliced directly in front
// of a `/repository/...` path.
func TestSeedGuidesUseBasePlaceholderForRepositoryURLs(t *testing.T) {
	t.Parallel()
	requireMonorepoTree(t, "configs")
	for _, path := range seedConfigPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if hostOnlyBeforeRepositoryPath.MatchString(line) {
				t.Errorf("%s:%d uses the host-only placeholder %q in front of a "+
					"/repository path:\n  %s\n"+
					"Use %q instead. The dashboard substitutes %q with host + "+
					"ingress base path (chain305.com/chainproxy) and %q with the "+
					"bare host; a bare host in a repository URL drops the "+
					"/chainproxy prefix and 404s on the user's first install. "+
					"See normalizeGuideCredentials in ui_new/src/lib/client-guide.ts.",
					path, i+1, hostOnlyPlaceholder, strings.TrimSpace(line),
					basePlaceholder, basePlaceholder, hostOnlyPlaceholder)
			}
		}
	}
}

// npmFamilyGuides are the repository names whose guides drive an
// npm-protocol client. These are the guides that must document the token
// format AND emit an always-auth equivalent.
var npmFamilyGuides = map[string]struct {
	// alwaysAuthTokens: at least one must appear in the guide. Yarn Berry
	// spells it `npmAlwaysAuth`; Bun always authenticates and is exempt
	// (empty slice).
	alwaysAuthTokens []string
}{
	"npmjs":    {alwaysAuthTokens: []string{"always-auth=true", "always-auth\" true"}},
	"yarnpkg":  {alwaysAuthTokens: []string{"always-auth=true", "npmAlwaysAuth: true"}},
	"bunjs":    {alwaysAuthTokens: nil},
	"packages": {alwaysAuthTokens: nil},
}

// TestSeedGuidesNeverInstructBase64BearerTokens is guard (2).
//
// The server accepts base64 in exactly one place: an HTTP Basic
// `Authorization: Basic <base64>` header, which is the standard and is
// correct. It NEVER accepts a base64 value in a Bearer-style token slot
// (npm `_authToken`, Yarn `npmAuthToken`, Bun `token`, Cargo
// `CARGO_REGISTRIES_*_TOKEN`, `HF_TOKEN`, `swift package-registry --token`).
//
// The guard is therefore keyed on the credential-pair-into-base64 shape
// rather than the word "base64": any line that pipes the client_id/secret
// pair through `base64` and is NOT building an `Authorization: Basic`
// header is the bug.
func TestSeedGuidesNeverInstructBase64BearerTokens(t *testing.T) {
	t.Parallel()
	requireMonorepoTree(t, "configs")
	// Matches `... CLIENT_ID:...CLIENT_SECRET... | base64` in either the
	// literal-placeholder or shell-variable form.
	encodesCredentialPair := regexp.MustCompile(
		`CLIENT_ID:\$?\{?CLIENT_SECRET\}?[^|\n]*\|\s*base64`)
	for _, path := range seedConfigPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if !encodesCredentialPair.MatchString(line) {
				continue
			}
			// `Authorization: Basic <base64>` is the one correct use.
			if strings.Contains(line, "Authorization: Basic") {
				continue
			}
			t.Errorf("%s:%d base64-encodes the client credential pair outside an "+
				"`Authorization: Basic` header:\n  %s\n"+
				"Every other token slot in these guides (npm _authToken, Yarn "+
				"npmAuthToken, Bun token, CARGO_REGISTRIES_*_TOKEN, HF_TOKEN, "+
				"swift --token) is sent as `Authorization: Bearer <token>`, and "+
				"the server splits a Bearer token on a literal ':' "+
				"(splitTokenCredential in internal/server/server_clients.go). "+
				"Base64 output contains no colon, so the credential never "+
				"resolves and the request 401s. Emit the PLAINTEXT "+
				"CLIENT_ID:CLIENT_SECRET pair instead.",
				path, i+1, strings.TrimSpace(line))
		}
	}

	// Belt and braces: the prose must not tell the reader to encode either.
	badProse := regexp.MustCompile(`(?i)base64 of ` + "`?" + `CLIENT_ID`)
	for _, path := range seedConfigPaths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if badProse.MatchString(line) {
				t.Errorf("%s:%d instructs the reader to base64 the credential "+
					"pair:\n  %s\nThat guarantees a 401 — see the comment above.",
					path, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// TestSeedNpmFamilyGuidesEmitAlwaysAuth is guard (3).
func TestSeedNpmFamilyGuidesEmitAlwaysAuth(t *testing.T) {
	t.Parallel()
	requireMonorepoTree(t, "configs")
	for _, path := range seedConfigPaths {
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load(%s): %v", path, err)
		}
		for _, repo := range cfg.Repositories {
			spec, tracked := npmFamilyGuides[strings.ToLower(repo.Name)]
			if !tracked || len(spec.alwaysAuthTokens) == 0 {
				continue
			}
			guide := repo.ClientConfigurationGuide
			if strings.TrimSpace(guide) == "" {
				continue
			}
			found := false
			for _, token := range spec.alwaysAuthTokens {
				if strings.Contains(guide, token) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("%s: the %q client_configuration_guide never emits an "+
					"always-auth directive (looked for %v).\n"+
					"npm and Yarn Classic send credentials on the manifest "+
					"request but omit them on the tarball fetch unless "+
					"always-auth is set, so the install 401s AFTER the manifest "+
					"resolves — a confusing half-success for a new user. The "+
					"server-side snippet generator already emits it "+
					"(renderNpm in internal/server/server_configsnippets.go); "+
					"the seed guide must match.",
					path, repo.Name, spec.alwaysAuthTokens)
			}
		}
	}
}

// TestSeedNpmFamilyGuidesDocumentThePlaintextTokenFormat pins the positive
// half of guard (2): every guide that references ${CHAINSAW_TOKEN} must also
// say what to put in it. The wizard's done-step renders the SELECTED OPTION
// plus the cache-cleanup section and drops the rest of the intro, so a token
// definition that lives only in a stray intro paragraph is invisible to the
// user who most needs it.
func TestSeedNpmFamilyGuidesDocumentThePlaintextTokenFormat(t *testing.T) {
	t.Parallel()
	requireMonorepoTree(t, "configs")
	for _, path := range seedConfigPaths {
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load(%s): %v", path, err)
		}
		for _, repo := range cfg.Repositories {
			guide := repo.ClientConfigurationGuide
			if !strings.Contains(guide, "CHAINSAW_TOKEN") {
				continue
			}
			if strings.Contains(guide, "CLIENT_ID:CLIENT_SECRET") {
				continue
			}
			t.Errorf("%s: the %q guide references CHAINSAW_TOKEN but never spells "+
				"out its value as the plaintext CLIENT_ID:CLIENT_SECRET pair. "+
				"A reader who guesses base64 gets a 401 on every request.",
				path, repo.Name)
		}
	}
}

// ---------------------------------------------------------------------------
// Guard (4): a guide that hands the reader a runnable POSIX `export` must
// also hand a Windows reader an equivalent.
//
// The npm / Yarn / Bun guides already do this: every `export CHAINSAW_TOKEN=`
// block is followed by a `**Windows (PowerShell):**` fence and, where the
// tool has a cmd.exe story, a `**Windows (cmd.exe):**` one. Several other
// guides shipped POSIX-only, which is a hard stop rather than a cosmetic
// gap: a Flutter-on-Windows developer following the pub guide has no way to
// set PUB_HOSTED_URL at all from the instructions given, and `export` is not
// a command on either Windows shell.
//
// The check is deliberately keyed on `export`, not on the mere presence of a
// `bash` fence. A `bash` fence that only runs the tool itself (`dotnet
// restore`, `composer install`, `cargo build`) is fine to leave as-is: those
// commands are identical on PowerShell. It is specifically the shell-builtin
// environment assignment that has no Windows equivalent.
// ---------------------------------------------------------------------------

// posixExportLine matches a runnable POSIX environment assignment.
var posixExportLine = regexp.MustCompile(`(?m)^\s*export\s+[A-Za-z_][A-Za-z0-9_]*=`)

// powerShellForm is what satisfies the guard. Any ONE of these is enough —
// a guide may reasonably use a fenced ```powershell block, or an inline
// `$env:VAR = ...` / `setx` / `[Environment]::SetEnvironmentVariable(...)`
// instruction in prose.
var powerShellForm = regexp.MustCompile(
	"(?i)(```powershell|\\$env:|\\bsetx\\b|\\[Environment\\]::SetEnvironmentVariable)")

// windowsExemptGuides are the repositories whose guides may stay POSIX-only,
// keyed to the reason. Each entry is a deliberate product decision, NOT a
// backlog item.
//
// Prefer adding a genuine Windows path over adding an entry here. An
// exemption is only correct when the ecosystem itself does not run on
// Windows — every other guide that hands out an `export` has a working
// PowerShell equivalent and must carry it.
//
// The single entry below is currently UNEXERCISED: the cocoapods-trunk
// guide has no `export` line today, so the guard never reaches the lookup
// for it. It is recorded anyway because the standing decision is easy to
// lose: CocoaPods drives Xcode and its own documented cache-clear step is
// `rm -rf ~/Library/Caches/CocoaPods`. If someone later adds an `export`
// to that guide, this pre-answers the failure instead of prompting a
// transliterated PowerShell block for a toolchain that cannot run there.
var windowsExemptGuides = map[string]string{
	"cocoapods-trunk": "CocoaPods requires Xcode; macOS-only by construction",
}

func TestSeedGuidesWithPosixExportAlsoCoverWindows(t *testing.T) {
	t.Parallel()
	requireMonorepoTree(t, "configs")
	for _, path := range seedConfigPaths {
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load(%s): %v", path, err)
		}
		for _, repo := range cfg.Repositories {
			guide := repo.ClientConfigurationGuide
			if strings.TrimSpace(guide) == "" {
				continue
			}
			if !posixExportLine.MatchString(guide) {
				continue
			}
			if _, exempt := windowsExemptGuides[strings.ToLower(repo.Name)]; exempt {
				continue
			}
			if powerShellForm.MatchString(guide) {
				continue
			}
			t.Errorf("%s: the %q client_configuration_guide hands the reader a "+
				"runnable POSIX `export` but never a Windows equivalent.\n"+
				"`export` is not a command in PowerShell or cmd.exe, so a "+
				"Windows developer cannot follow this guide at all. Add a "+
				"**Windows (PowerShell):** fence using `$env:VAR = ...` "+
				"(persisting with `setx` or "+
				"`[Environment]::SetEnvironmentVariable`), matching the "+
				"structure the npmjs guide already uses. If the ecosystem "+
				"genuinely does not run on Windows, add %q to "+
				"windowsExemptGuides with the reason.",
				path, repo.Name, repo.Name)
		}
	}
}
