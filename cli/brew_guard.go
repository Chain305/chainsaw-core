package cli

// `chainsaw brew <args>` — the Homebrew install guard, and the on-device half
// of Homebrew support (docs/PLANS_INTELLIGENCE.md#plan-homebrew-ecosystem).
// A network proxy can enforce only the ghcr.io bottle hop; source builds,
// casks and taps never touch it. This wrapper sees all of them.
//
//   $ chainsaw brew install jq              # formula: disabled? deprecated? (+ server preflight)
//   $ chainsaw brew install --cask firefox  # cask: disabled? unpinned download? vendor installer?
//   $ chainsaw brew install user/tap/tool   # third-party tap: refused unless `guard allow`ed
//   $ chainsaw brew bundle                  # every brew/cask line of the Brewfile
//   $ chainsaw brew upgrade                 # every outdated package (`brew outdated --json=v2`)

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/depparser/origin"
	"github.com/chain305/chainsaw-core/depparser/parser/homebrew/brewfile"
	"github.com/chain305/chainsaw-core/homebrew"
)

var brewGuardCmd = &cobra.Command{
	Use:   "brew [args...]",
	Short: "Run brew through Chainsaw — refuse disabled formulae, risky casks and unvetted taps at install time",
	Long: `Run brew with an install-time supply-chain check in front of it.

Guarded: ` + "`brew install`, `brew reinstall`, `brew upgrade`" + ` (no names = every
outdated package, listed with ` + "`brew outdated --json=v2`" + `) and ` + "`brew bundle`" + `
(every brew and cask line of the Brewfile: --file, --global, HOMEBREW_BUNDLE_FILE,
else ./Brewfile). Anything else delegates immediately.

Formulae: a disabled formula is refused, a deprecated one warns. Signed in,
each formula's current version also goes to your Chainsaw server's preflight,
exactly as ` + "`chainsaw npm`" + ` does.
Casks: a disabled cask is refused; a deprecated cask, an unpinned download
(sha256 :no_check), a vendor installer (.pkg) or Ruby hooks warn; auto-updating
apps are noted.
Third-party taps (user/tap/name) are refused: nothing upstream vets them. After
reviewing one, allow it with ` + "`chainsaw guard allow homebrew:user/tap/name`" + `.

Unlike the other wrappers these checks read formulae.brew.sh — the same API brew
itself fetches (CHAINSAW_HOMEBREW_API_URL overrides it). CHAINSAW_OFFLINE=1 skips
them. A lookup that fails prints "could not verify" and the install proceeds,
like an unreachable server preflight.

Exit codes: 0 when the install proceeds (Chainsaw then returns brew's own exit
code), 1 when Chainsaw refuses.

Subcommands: ` + "`chainsaw brew env`" + ` (your org's brew.env policy) and
` + "`chainsaw brew inventory`" + ` (upload what is installed).

To make the check automatic, add the shell shims: ` + "`eval \"$(chainsaw guard init)\"`" + `.`,
	Example: `  chainsaw brew install jq
  chainsaw brew install --cask firefox
  chainsaw brew bundle --file ~/dotfiles/Brewfile
  chainsaw brew upgrade`,
	GroupID:            GrpGuard,
	DisableFlagParsing: true,
	SilenceUsage:       true,
	SilenceErrors:      true,
	Args:               cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runGuardedPassthrough("brew", args, parseBrewInstall)
	},
}

func init() {
	rootCmd.AddCommand(brewGuardCmd)
}

const (
	brewKindFormula = "formula"
	brewKindCask    = "cask"
)

// brewInstallFlags is the option grammar shared by brew install / reinstall /
// upgrade (brew 4.x). The value set lists only REQUIRED-value options
// (`--cc=clang` or `--cc clang`); see splitFlags for why that matters.
var brewInstallFlags = newFlagSet(
	"--formula --formulae --cask --casks --debug --display-times --force --verbose --dry-run --ask "+
		"--env --ignore-dependencies --only-dependencies --cc --build-from-source --force-bottle "+
		"--include-test --HEAD --fetch-HEAD --keep-tmp --debug-symbols --build-bottle --skip-post-install "+
		"--skip-link --as-dependency --bottle-arch --interactive --git --overwrite --binaries --no-binaries "+
		"--quarantine --no-quarantine --adopt --skip-cask-deps --zap --require-sha --no-require-sha --quiet "+
		"--greedy --greedy-latest --greedy-auto-updates --appdir --keyboard-layoutdir --colorpickerdir "+
		"--prefpanedir --qlplugindir --mdimporterdir --dictionarydir --fontdir --servicedir "+
		"--input-methoddir --internet-plugindir --audio-unit-plugindir --vst-plugindir --vst3-plugindir "+
		"--screen-saverdir --language --help",
	"--env --cc --bottle-arch --appdir --keyboard-layoutdir --colorpickerdir --prefpanedir --qlplugindir "+
		"--mdimporterdir --dictionarydir --fontdir --servicedir --input-methoddir --internet-plugindir "+
		"--audio-unit-plugindir --vst-plugindir --vst3-plugindir --screen-saverdir --language",
	nil)

var brewBundleFlags = newFlagSet(
	"--file --global --verbose --no-upgrade --upgrade --force --cleanup --no-lock --install --services "+
		"--all --formula --brews --cask --casks --tap --taps --mas --whalebrew --vscode --no-vscode "+
		"--describe --no-restart --zap --check --quiet --help",
	"--file", nil)

// brewCommandArgs strips chainsaw's leading globals and any leading brew
// option, so args[0] is the brew command. brew's pre-command options
// (-v, -d, -q, --verbose ...) are all boolean, so no value can be mistaken
// for the command.
func brewCommandArgs(args []string) []string {
	args = stripLeadingChainsawGlobals(args)
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			return args[i:]
		}
	}
	return nil
}

// parseBrewInstall recognizes the brew commands that install software.
func parseBrewInstall(args []string) ([]packageSpec, bool) {
	if len(args) == 0 {
		return nil, false
	}
	switch args[0] {
	case "install", "instal", "reinstall", "upgrade":
	case "bundle":
		return parseBrewBundle(args[1:])
	default:
		return nil, false
	}
	pos, flags := splitFlags(args[1:], brewInstallFlags)
	kind, source := "", ""
	for _, f := range flags {
		switch f.name {
		case "--cask", "--casks":
			kind = brewKindCask
		case "--formula", "--formulae":
			kind = brewKindFormula
		case "--build-from-source", "-s", "--HEAD", "--interactive", "-i", "--build-bottle":
			source = f.name
		}
	}
	var specs []packageSpec
	if len(pos) == 0 && args[0] == "upgrade" {
		specs = brewOutdatedSpecs(kind)
	} else {
		for _, a := range pos {
			specs = append(specs, brewSpec(a, kind))
		}
	}
	for i := range specs {
		specs[i].HomebrewSource = source
	}
	return specs, true
}

// brewSpec turns one install argument into a spec. A formula file by path
// or URL is not a Homebrew API package: it gets an Origin (not assessed).
func brewSpec(arg, kind string) packageSpec {
	if strings.Contains(arg, "://") {
		return packageSpec{Ecosystem: homebrew.Ecosystem, Origin: origin.Sanitize(lowerScheme(arg))}
	}
	if hasSuffixFold(arg, ".rb") || strings.HasPrefix(arg, ".") || strings.HasPrefix(arg, "/") || strings.HasPrefix(arg, "~") {
		return packageSpec{Ecosystem: homebrew.Ecosystem, Origin: localOrigin(arg)}
	}
	return packageSpec{Ecosystem: homebrew.Ecosystem, Name: homebrew.NormalizeName(arg), HomebrewKind: kind}
}

// parseBrewBundle: `brew bundle [install] [--file F | --global]`. Only the
// install form installs anything; dump, check, list, cleanup, exec ... pass
// through.
func parseBrewBundle(args []string) ([]packageSpec, bool) {
	pos, flags := splitFlags(args, brewBundleFlags)
	if len(pos) > 0 && pos[0] != "install" {
		return nil, false
	}
	file, global := "", false
	for _, f := range flags {
		switch f.name {
		case "--file":
			file = f.value
		case "--global":
			global = true
		}
	}
	file = brewfilePath(file, global)
	if file == "-" {
		return []packageSpec{unparsedLockSpec(homebrew.Ecosystem, "a Brewfile on stdin")}, true
	}
	data, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) {
		return nil, true // brew reports the missing Brewfile itself
	}
	if err != nil {
		return []packageSpec{unparsedLockSpec(homebrew.Ecosystem, file)}, true
	}
	entries, err := brewfile.ParseEntries(strings.NewReader(string(data)))
	if err != nil {
		return []packageSpec{unparsedLockSpec(homebrew.Ecosystem, file)}, true
	}
	var specs []packageSpec
	for _, e := range entries {
		switch e.Kind {
		case brewfile.KindFormula:
			specs = append(specs, brewSpec(e.Name, brewKindFormula))
		case brewfile.KindCask:
			specs = append(specs, brewSpec(e.Name, brewKindCask))
		}
	}
	return specs, true
}

// brewfilePath resolves the Brewfile `brew bundle` would read, mirroring
// brew 7's Homebrew::Bundle::Brewfile.path: --global wins over --file, and a
// global Brewfile lives in the user config home (XDG_CONFIG_HOME/homebrew,
// HOMEBREW_XDG_CONFIG_HOME/homebrew, else ~/.homebrew — the directory the
// brew install-hook creates) whenever that directory exists and either holds
// a Brewfile or ~/.Brewfile is absent. Checking a different file than brew
// installs from would pass every entry unchecked.
func brewfilePath(file string, global bool) string {
	if global {
		if v := os.Getenv("HOMEBREW_BUNDLE_FILE_GLOBAL"); v != "" {
			return v
		}
		home, _ := os.UserHomeDir()
		homeBrewfile := filepath.Join(home, ".Brewfile")
		if dir := brewUserConfigHome(home); dir != "" {
			userBrewfile := filepath.Join(dir, "Brewfile")
			if fileExists(userBrewfile) || !fileExists(homeBrewfile) {
				return userBrewfile
			}
		}
		return homeBrewfile
	}
	if file != "" {
		return file
	}
	if v := os.Getenv("HOMEBREW_BUNDLE_FILE"); v != "" {
		return v
	}
	return "Brewfile"
}

// brewUserConfigHome is bin/brew's HOMEBREW_USER_CONFIG_HOME, or "" when that
// directory does not exist.
func brewUserConfigHome(home string) string {
	dir := filepath.Join(home, ".homebrew")
	if v := os.Getenv("XDG_CONFIG_HOME"); v != "" {
		dir = filepath.Join(v, "homebrew")
	} else if v := os.Getenv("HOMEBREW_XDG_CONFIG_HOME"); v != "" {
		dir = filepath.Join(v, "homebrew")
	}
	if st, err := os.Stat(dir); err == nil && st.IsDir() {
		return dir
	}
	return ""
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// brewOutput runs the REAL brew (exec.LookPath resolves the binary, never
// the shell function) with auto-update off. Swapped in tests.
var brewOutput = func(args ...string) ([]byte, error) {
	path, err := exec.LookPath("brew")
	if err != nil {
		return nil, fmt.Errorf("brew not found on PATH: %w", err)
	}
	c := exec.Command(path, args...)
	c.Env = append(os.Environ(), "HOMEBREW_NO_AUTO_UPDATE=1")
	c.Stderr = os.Stderr
	return c.Output()
}

// brewOutdatedSpecs lists what a bare `brew upgrade` would upgrade. A
// failure becomes a not-assessed spec, printed, never a silent pass.
func brewOutdatedSpecs(kind string) []packageSpec {
	args := []string{"outdated", "--json=v2"}
	switch kind {
	case brewKindCask:
		args = append(args, "--cask")
	case brewKindFormula:
		args = append(args, "--formula")
	}
	out, err := brewOutput(args...)
	var doc struct {
		Formulae []struct{ Name string } `json:"formulae"`
		Casks    []struct{ Name string } `json:"casks"`
	}
	if err == nil {
		err = json.Unmarshal(out, &doc)
	}
	if err != nil {
		return []packageSpec{unparsedLockSpec(homebrew.Ecosystem, "`brew outdated --json=v2`")}
	}
	var specs []packageSpec
	for _, f := range doc.Formulae {
		specs = append(specs, brewSpec(f.Name, brewKindFormula))
	}
	for _, c := range doc.Casks {
		specs = append(specs, brewSpec(c.Name, brewKindCask))
	}
	return specs
}

// ── preflight ──────────────────────────────────────────────────────────────

// Severities of the Homebrew lanes. Every one is printed by
// printGuardVerdicts (the blocking arm, or its catch-all warning arm, which
// --quiet never suppresses).
const (
	guardSeverityHomebrewDisabled   = "homebrew-disabled"
	guardSeverityHomebrewDeprecated = "homebrew-deprecated"
	guardSeverityHomebrewTap        = "homebrew-third-party-tap"
	guardSeverityHomebrewCask       = "homebrew-cask"
	guardSeverityHomebrewSource     = "homebrew-source-build"
)

// brewAPIClient is the Homebrew API client (SSRF-guarded, shared upstream
// budget). Swapped in tests.
var brewAPIClient = func() homebrew.Doer { return homebrew.SharedClient() }

// brewPreflightConcurrency bounds parallel API lookups (a Brewfile can name
// a hundred packages; the shared upstream limiter still paces them).
const brewPreflightConcurrency = 8

func runBrewPreflight(ctx context.Context, specs []packageSpec) ([]packageSpec, []guardVerdict, []string) {
	if envTruthy(os.Getenv("CHAINSAW_OFFLINE")) {
		return specs, nil, []string{"Homebrew metadata not checked (CHAINSAW_OFFLINE): disabled formulae and cask risks are unverified"}
	}
	return brewPreflight(ctx, brewAPIClient(), homebrew.ConfiguredAPIBase(), specs)
}

// homebrewThirdPartyTap: a tap-qualified name outside homebrew/core and
// homebrew/cask.
func homebrewThirdPartyTap(name string) bool { return homebrew.IsThirdPartyTapName(name) }

// brewPreflight checks every homebrew spec against the Homebrew API. It
// returns the specs with each resolved formula's Version set to its current
// pkg_version (and HomebrewKind resolved), the verdicts, and notices for
// lookups that could not be completed.
func brewPreflight(ctx context.Context, client homebrew.Doer, apiBase string, specs []packageSpec) ([]packageSpec, []guardVerdict, []string) {
	out := append([]packageSpec(nil), specs...)
	verdicts := make([]*guardVerdict, len(out))
	notices := make([]string, len(out))

	sem := make(chan struct{}, brewPreflightConcurrency)
	var wg sync.WaitGroup
	for i := range out {
		s := &out[i]
		if s.Ecosystem != homebrew.Ecosystem || s.Name == "" || s.Origin != "" {
			continue
		}
		if homebrewThirdPartyTap(s.Name) {
			verdicts[i] = brewTapVerdict(*s)
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, s *packageSpec) {
			defer wg.Done()
			defer func() { <-sem }()
			verdicts[i], notices[i] = brewLookup(ctx, client, apiBase, s)
		}(i, s)
	}
	wg.Wait()

	var vs []guardVerdict
	var ns []string
	for i := range out {
		if verdicts[i] != nil {
			verdicts[i].Spec = out[i]
			vs = append(vs, *verdicts[i])
		}
		if v := brewSourceVerdict(out[i]); v != nil {
			vs = append(vs, *v)
		}
		if notices[i] != "" {
			ns = append(ns, notices[i])
		}
	}
	return out, vs, ns
}

// brewSourceVerdict warns on a formula built from source. No bottle is
// fetched, so neither the proxy's bottle check nor brew verify's keg check
// covers what gets installed, and brew has no setting that forbids it.
func brewSourceVerdict(s packageSpec) *guardVerdict {
	if s.HomebrewSource == "" || s.HomebrewKind == brewKindCask || s.Ecosystem != homebrew.Ecosystem {
		return nil
	}
	return &guardVerdict{Spec: s, Severity: guardSeverityHomebrewSource,
		Reason: s.HomebrewSource + " builds from source: no bottle is fetched, so the Chainsaw proxy's bottle check does not cover what gets installed"}
}

// brewTapVerdict refuses a third-party tap unless the local allowlist names
// it. An allowed tap still prints (never a silent pass).
func brewTapVerdict(s packageSpec) *guardVerdict {
	if _, ok := cachedGuardAllowSet()[guardAllowKey(s.Ecosystem, s.Name)]; ok {
		return &guardVerdict{Severity: guardSeverityHomebrewTap,
			Reason: "third-party tap, allowed by your local allowlist (undo: chainsaw guard allow --remove " + guardHintCoordinate(s) + ")"}
	}
	return &guardVerdict{Block: true, Severity: guardSeverityHomebrewTap,
		Reason: "third-party tap: nothing upstream reviews it, and brew builds it from the tap's own Ruby; after reviewing the tap, allow it with: chainsaw guard allow " + guardHintCoordinate(s)}
}

// brewLookup resolves one name: formula first unless the user said --cask,
// then cask when brew would fall back to one.
func brewLookup(ctx context.Context, client homebrew.Doer, apiBase string, s *packageSpec) (*guardVerdict, string) {
	var ferr error
	if s.HomebrewKind != brewKindCask {
		f, err := homebrew.FetchFormula(ctx, client, apiBase, s.Name)
		if err == nil {
			s.HomebrewKind, s.Version = brewKindFormula, f.PkgVersion()
			return formulaVerdict(f), ""
		}
		if !errors.Is(err, homebrew.ErrNotFound) || s.HomebrewKind == brewKindFormula {
			return nil, brewUnverified(*s, err)
		}
		ferr = err
	}
	c, err := homebrew.FetchCask(ctx, client, apiBase, s.Name)
	if err != nil {
		if ferr != nil && errors.Is(err, homebrew.ErrNotFound) {
			// Neither a core formula nor a cask by that exact token. brew may
			// still resolve it: an alias (python, openssl — the per-name API
			// 404s them) or a formula from an installed third-party tap.
			// Ask brew what it would install rather than waving it through.
			if v, ok := brewResolveViaLocal(ctx, client, apiBase, s); ok {
				return v, ""
			}
			return nil, fmt.Sprintf("could not verify homebrew:%s — not a formula or cask in the Homebrew API; continuing", sanitizeForTerminal(s.Name))
		}
		return nil, brewUnverified(*s, err)
	}
	s.HomebrewKind, s.Version = brewKindCask, c.Version
	return caskVerdict(c.Flags()), ""
}

// brewLocalInfo asks the local brew what a name resolves to: its full name
// and tap. ok=false when brew cannot resolve it (or is not installed).
// Swapped in tests.
var brewLocalInfo = func(name string) (fullName, tap string, ok bool) {
	path, err := exec.LookPath("brew")
	if err != nil {
		return "", "", false
	}
	c := exec.Command(path, "info", "--json=v2", "--", name)
	c.Env = append(os.Environ(), "HOMEBREW_NO_AUTO_UPDATE=1")
	out, err := c.Output()
	if err != nil {
		return "", "", false
	}
	var doc struct {
		Formulae []struct {
			FullName string `json:"full_name"`
			Tap      string `json:"tap"`
		} `json:"formulae"`
		Casks []struct {
			FullToken string `json:"full_token"`
			Tap       string `json:"tap"`
		} `json:"casks"`
	}
	if json.Unmarshal(out, &doc) != nil {
		return "", "", false
	}
	switch {
	case len(doc.Formulae) == 1:
		return doc.Formulae[0].FullName, doc.Formulae[0].Tap, true
	case len(doc.Casks) == 1:
		return doc.Casks[0].FullToken, doc.Casks[0].Tap, true
	}
	return "", "", false
}

// brewResolveViaLocal resolves a name the API 404ed through the local brew:
// a third-party-tap name is refused like a tap-qualified one, and a core
// alias is judged as its canonical formula (version set, so the server
// preflight sees it). ok=false leaves the caller's "could not verify".
func brewResolveViaLocal(ctx context.Context, client homebrew.Doer, apiBase string, s *packageSpec) (*guardVerdict, bool) {
	full, tap, ok := brewLocalInfo(s.Name)
	if !ok || full == "" {
		return nil, false
	}
	if homebrewThirdPartyTap(full) {
		s.Name = full
		return brewTapVerdict(*s), true
	}
	canonical := homebrew.NormalizeName(full)
	if tap != "homebrew/core" || canonical == homebrew.NormalizeName(s.Name) {
		return nil, false
	}
	f, err := homebrew.FetchFormula(ctx, client, apiBase, canonical)
	if err != nil {
		return nil, false
	}
	s.Name, s.HomebrewKind, s.Version = f.Name, brewKindFormula, f.PkgVersion()
	return formulaVerdict(f), true
}

func brewUnverified(s packageSpec, err error) string {
	return fmt.Sprintf("could not verify homebrew:%s (%v); continuing with offline guard", sanitizeForTerminal(s.Name), err)
}

func formulaVerdict(f *homebrew.Formula) *guardVerdict {
	switch {
	case f.Disabled:
		return &guardVerdict{Block: true, Severity: guardSeverityHomebrewDisabled,
			Reason: lifecycleReason("formula disabled by Homebrew", f.DisableDate, f.DisableReason, f.DisableReplacement)}
	case f.Deprecated:
		return &guardVerdict{Severity: guardSeverityHomebrewDeprecated,
			Reason: lifecycleReason("formula deprecated by Homebrew", f.DeprecationDate, f.DeprecationReason, f.DeprecationReplacement)}
	}
	return nil
}

func lifecycleReason(what, date, why, replacement string) string {
	r := what
	if date != "" {
		r += " on " + date
	}
	if why != "" {
		r += " (" + why + ")"
	}
	if replacement != "" {
		r += "; replacement: " + replacement
	}
	return r
}

// caskVerdict folds a cask's risk facts into ONE verdict per cask: refused
// when disabled, otherwise a warning listing every fact that applies.
func caskVerdict(fl homebrew.CaskFlags) *guardVerdict {
	if fl.Disabled {
		return &guardVerdict{Block: true, Severity: guardSeverityHomebrewDisabled,
			Reason: lifecycleReason("cask disabled by Homebrew", "", fl.Reason, "")}
	}
	var facts []string
	sev := guardSeverityHomebrewCask
	if fl.Deprecated {
		facts = append(facts, lifecycleReason("deprecated by Homebrew", "", fl.Reason, ""))
		sev = guardSeverityHomebrewDeprecated
	}
	if fl.NoChecksum {
		facts = append(facts, "download is not checksum-pinned (sha256 :no_check): brew installs whatever the vendor serves today")
	}
	if fl.RunsInstaller {
		facts = append(facts, "runs a vendor installer (.pkg/installer) outside brew's sandbox, usually as root")
	}
	if fl.HasHooks {
		facts = append(facts, "runs preflight/postflight Ruby hooks")
	}
	if fl.AutoUpdates {
		facts = append(facts, "note: the app updates itself outside Homebrew")
	}
	if len(facts) == 0 {
		return nil
	}
	return &guardVerdict{Severity: sev, Reason: "cask: " + strings.Join(facts, "; ")}
}
