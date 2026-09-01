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
// The check is NOT keyed on the mere presence of a `bash` fence. A `bash`
// fence that only runs the tool itself (`dotnet restore`, `composer install`,
// `cargo build`) is fine to leave as-is: those commands are identical on
// PowerShell. It is specifically the constructs that do not EXIST on Windows
// that leave a reader stuck.
//
// P8-29 widened this. The guard used to key on `export` alone, and that is
// exactly why it passed the pypi guide, which hands a Windows reader
// `%USERPROFILE%\_netrc` on one line and `chmod 600 ~/.netrc` on the next.
// `chmod` is no more a Windows command than `export` is. Phase 7 S-10's
// "5 guides before, 0 after" was measured with the narrow rule and therefore
// overstated the coverage it had achieved.
//
// Widening it flagged four more guides (pypi, rubygems, gomod, docker-hub)
// plus the cocoapods exemption, which the narrow rule had never reached.
// ---------------------------------------------------------------------------

// posixOnlyConstructs are the runnable constructs that simply do not exist on
// either Windows shell. Each entry carries the Windows answer, quoted back to
// the author in the failure message so the fix is obvious.
//
// Keep this list to constructs with NO Windows equivalent. `rm -rf ~/…` is
// here because both the `rm` command and the `~` expansion are POSIX-only;
// `pip install` or `go build` are not, and must not be added.
var posixOnlyConstructs = []struct {
	name    string
	windows string
	re      *regexp.Regexp
}{
	{
		name:    "export VAR=",
		windows: "`$env:VAR = '…'` (persist with `setx` or `[Environment]::SetEnvironmentVariable`)",
		re:      regexp.MustCompile(`(?m)^\s*export\s+[A-Za-z_][A-Za-z0-9_]*=`),
	},
	{
		name:    "chmod",
		windows: "`icacls <path> /inheritance:r /grant:r \"$($env:USERNAME):(R,W)\"`",
		re:      regexp.MustCompile(`(?m)^\s*chmod\s`),
	},
	{
		name:    "… | base64",
		windows: "`[Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes($pair))`",
		re:      regexp.MustCompile(`\|\s*base64\b`),
	},
	{
		name:    "rm -rf ~/…",
		windows: "`Remove-Item -Recurse -Force \"$env:USERPROFILE\\…\"`",
		re:      regexp.MustCompile(`(?m)^\s*rm\s+-rf?\s+~`),
	},
}

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
// The single entry below IS exercised as of P8-29: the widened construct
// list reaches the cocoapods-trunk guide through its `export`, `chmod` and
// `rm -rf ~/Library/Caches/CocoaPods` lines, all three of which are correct
// for a toolchain that only runs where Xcode runs. (Under the old
// `export`-only rule the lookup was never reached, so the exemption sat
// unexercised — recorded then because the standing decision is easy to lose.)
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
			var found []string
			var answers []string
			for _, c := range posixOnlyConstructs {
				if c.re.MatchString(guide) {
					found = append(found, c.name)
					answers = append(answers, c.name+" -> "+c.windows)
				}
			}
			if len(found) == 0 {
				continue
			}
			if _, exempt := windowsExemptGuides[strings.ToLower(repo.Name)]; exempt {
				continue
			}
			if powerShellForm.MatchString(guide) {
				continue
			}
			t.Errorf("%s: the %q client_configuration_guide hands the reader "+
				"runnable POSIX-only construct(s) %v but never a Windows "+
				"equivalent.\nNone of those exist in PowerShell or cmd.exe, so "+
				"a Windows developer cannot follow this guide at all. Add a "+
				"**Windows (PowerShell):** fence, matching the structure the "+
				"npmjs guide already uses:\n  %s\nIf the ecosystem genuinely "+
				"does not run on Windows, add %q to windowsExemptGuides with "+
				"the reason.",
				path, repo.Name, found, strings.Join(answers, "\n  "), repo.Name)
		}
	}
}

// ---------------------------------------------------------------------------
// Guard (5): a guide that offers a labelled PowerShell variant must offer a
// cmd.exe one too.
//
// This is about the wizard, not about prose. ui_new's splitGuideByOS
// (components/dashboard/client-wizard/lib.ts, OS_MARKERS) turns the
// `**macOS / Linux …:**` / `**Windows (PowerShell):**` / `**Windows
// (cmd.exe):**` labels into a tab axis, and it folds the axis away entirely
// when fewer than two variants are present. A guide with a PowerShell tab and
// no cmd.exe tab therefore renders as a choice that silently excludes half of
// Windows — the reader on cmd.exe is shown PowerShell syntax under a tab that
// implies it is the Windows answer.
//
// The rule is deliberately one-directional. A cmd.exe variant without a
// PowerShell one has never occurred and would be a stranger mistake; the
// asymmetry that actually shipped (huggingface, found by P8-29) is
// PowerShell-without-cmd.
//
// The labels are matched exactly as OS_MARKERS matches them, INCLUDING the
// parentheses: `**Windows PowerShell:**` is not a marker the splitter
// recognises. Three inline one-liners in the yarnpkg and bunjs guides use
// that unparenthesised form; they are prose, not tab markers, and are left
// alone here on purpose — converting them would give those guides a SECOND
// marker group, and splitGuideByOS emits one variant per group, so the wizard
// would render duplicate tabs.
// ---------------------------------------------------------------------------

var (
	powerShellVariantLabel = regexp.MustCompile(`(?im)^\s*\*\*Windows\s*\(PowerShell\)[^*]*:?\*\*`)
	cmdVariantLabel        = regexp.MustCompile(`(?im)^\s*\*\*Windows\s*\(cmd\.exe\)[^*]*:?\*\*`)
)

func TestSeedGuidesWithPowerShellVariantAlsoCoverCmd(t *testing.T) {
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
			if !powerShellVariantLabel.MatchString(guide) {
				continue
			}
			if cmdVariantLabel.MatchString(guide) {
				continue
			}
			t.Errorf("%s: the %q client_configuration_guide carries a "+
				"**Windows (PowerShell):** variant but no **Windows "+
				"(cmd.exe):** one.\nThe client wizard turns those labels into "+
				"tabs (ui_new splitGuideByOS / OS_MARKERS), so a cmd.exe "+
				"reader is shown PowerShell syntax under the tab that claims "+
				"to be the Windows answer. Add a **Windows (cmd.exe):** "+
				"block using `set VAR=value` (persist with `setx`), matching "+
				"the npmjs guide.",
				path, repo.Name)
		}
	}
}

// ---------------------------------------------------------------------------
// Guard (6): the seed guides teach the COMBINED credential vocabulary, and
// only that one. P8-30.
//
// Four surfaces name this credential differently, and the differences are
// real: `CHAINSAW_TOKEN` is one value, the plaintext `<client_id>:<client_secret>`
// pair; `CHAINSAW_CLIENT_ID` + `CHAINSAW_CLIENT_SECRET` is two values a CI job
// joins at the point of use. Neither renames into the other — a rename is a
// value change, and every pipeline holding the old name in a secret store
// breaks with a 401 that names nothing. So both vocabularies stay, and the
// map is docs/CONFIG_REFERENCE.md section B30.
//
// The guides in configs/seed.yaml are the COMBINED surface. They are rendered
// by the client wizard's "End users & AI agents" tab as copy-paste blocks for
// a developer's own machine, where one exported variable is the whole story
// and a split pair would need a join the reader has to write. Introducing the
// split-pair names here would give the same tab two vocabularies with no
// signal about which one the following fence expects.
//
// The rule is one-directional, matching guard (5)'s reasoning: the seed
// guides must not gain the SPLIT names. Nothing stops a CI page from
// mentioning the combined form, and tutorial 21's mapping table does exactly
// that on purpose.
//
// Note the substring chosen. `CLIENT_ID:CLIENT_SECRET` — the literal every
// guide already uses to spell the joined value — deliberately does NOT match:
// the guard keys on the `CHAINSAW_`-prefixed names, which are the ones a
// reader would export.
// ---------------------------------------------------------------------------

// splitPairVarNames are the CI-surface vocabulary. Their presence in a seed
// guide is the regression.
var splitPairVarNames = []string{"CHAINSAW_CLIENT_ID", "CHAINSAW_CLIENT_SECRET"}

func TestSeedGuidesTeachOnlyTheCombinedTokenVocabulary(t *testing.T) {
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
			for _, name := range splitPairVarNames {
				if !strings.Contains(guide, name) {
					continue
				}
				t.Errorf("%s: the %q client_configuration_guide introduces %s, the "+
					"CI/CD split-pair vocabulary.\nThese guides teach the COMBINED "+
					"form: one variable holding the plaintext `<client_id>:<client_secret>` "+
					"pair, which is what the proxy splits on the first colon "+
					"(splitTokenCredential in internal/server/server_clients.go). The "+
					"split pair is two secret-store entries a CI job joins itself; "+
					"mixing the two in one wizard tab leaves the reader unable to tell "+
					"which shape the next fence expects. Keep the combined form here "+
					"and see docs/CONFIG_REFERENCE.md section B30 for the map.",
					path, repo.Name, name)
			}
		}
	}
}

// TestSeedHuggingFaceGuideKeepsTheJoinedPairInHFToken pins the third surface.
// HF_TOKEN is huggingface_hub's own variable, not ours; the guide borrows it
// to carry OUR credential, and the value has to be the joined pair because
// huggingface_hub sends it as `Authorization: Bearer $HF_TOKEN` and the proxy
// splits that on the colon. A reader who assumes a real `hf_…` token, or who
// base64-encodes, gets a 401 with no hint. Guard (2) already bans the base64
// form; this pins the positive claim.
func TestSeedHuggingFaceGuideKeepsTheJoinedPairInHFToken(t *testing.T) {
	t.Parallel()
	requireMonorepoTree(t, "configs")
	for _, path := range seedConfigPaths {
		cfg, err := Load(path)
		if err != nil {
			t.Fatalf("Load(%s): %v", path, err)
		}
		checked := 0
		for _, repo := range cfg.Repositories {
			guide := repo.ClientConfigurationGuide
			if !strings.Contains(guide, "HF_TOKEN") {
				continue
			}
			checked++
			if strings.Contains(guide, "HF_TOKEN") && strings.Contains(guide, "CLIENT_ID:CLIENT_SECRET") {
				continue
			}
			t.Errorf("%s: the %q guide sets HF_TOKEN but never spells its value as the "+
				"joined CLIENT_ID:CLIENT_SECRET pair. HF_TOKEN here carries a CHAINSAW "+
				"client credential, not a huggingface.co `hf_…` token; "+
				"huggingface_hub sends it as `Authorization: Bearer $HF_TOKEN` and the "+
				"proxy splits on the colon. See docs/CONFIG_REFERENCE.md section B30.",
				path, repo.Name)
		}
		if checked == 0 {
			t.Errorf("%s: no client_configuration_guide mentions HF_TOKEN. The "+
				"huggingface guide is the only surface that teaches it; if it was "+
				"removed, drop this guard and the HF_TOKEN row in "+
				"docs/CONFIG_REFERENCE.md section B30 in the same change.", path)
		}
	}
}
