package cli

// `chainsaw brew verify`: is this machine's Homebrew still what brew put
// there and what upstream published?
//
// The 2026 Binance intrusion started with a trojanised Homebrew installer
// and persisted by swapping the pyenv binary under /opt/homebrew, a prefix
// owned by the user. Nothing stops those writes; this command detects them:
//
//   --links  every name a linked keg exports in bin/ and sbin/, and every
//            name in root's baseline, is still a symlink into a keg; opt/
//            lands on a keg (offline, homebrew.CheckLinks).
//   --brew   brew's own code (bin/brew, Library/Homebrew, completions) is
//            byte-identical to the upstream Homebrew/brew commit HEAD names,
//            and that commit is on upstream main (server: /api/homebrew/
//            brew-tree); and /etc/homebrew/brew.env is root-owned and ends
//            with your org's policy values.
//
// It reads files only; nothing under the prefix is executed. Run it as root
// from MDM (enforcement/mdm/jamf/macos.sh, CHAINSAW_BREW_VERIFY_TOKEN): run as
// the user, malware running as that user can make it lie.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/cli/hook"
	"github.com/chain305/chainsaw-core/homebrew"
)

var brewVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Detect tampering with Homebrew's links, brew's own code and the system brew.env",
	Long: `Check that this machine's Homebrew has not been modified since brew installed it.

  --links  every name a linked formula ships in bin/ and sbin/, and every
           name a root run of this command has seen brew own, is still a
           symlink into a Cellar keg that ships it, and opt/ links land on a
           keg. Offline. Catches a binary swapped into the prefix. Run as
           root, it records those names in /var/db/chainsaw (the baseline),
           so deleting brew's own link records cannot hide a swap.
  --brew   brew's own code (bin/brew, Library/Homebrew, completions) is
           byte-identical to the upstream Homebrew/brew commit it claims to be,
           with no file missing or added, that commit is on upstream main and
           not months old, and .git/config and .git/hooks run nothing; the
           portable Ruby brew runs and every gem it loads match, file by
           file, the artifacts brew's own pins name (vendor/portable-ruby-*,
           Gemfile.lock CHECKSUMS); /etc/homebrew/brew.env is root-owned and ends with your org's policy
           values. Needs the server.

With neither flag, both run, over every Homebrew prefix found (or --prefix).
Nothing under the Homebrew prefix is executed.
This is detection, not prevention: the prefix is writable by its user. Run it
as root from MDM so malware running as the user cannot fake the result.

Not covered: files changed inside a keg (only its links) or a fake keg
directory, anything changed before the first root run, casks, taps,
gem native extensions compiled on the device (listed, not compared), and
persistence outside the prefix (~/.zshrc, ~/.gitconfig, shims, LaunchAgents).

Exit codes: 0 everything requested was checked and is clean; 1 tampering
(verdict tamper) or brew.env differing from policy (verdict drift) found; 2 a requested check could not run (prefix unreadable,
server or GitHub unreachable); 12 checks ran but something in scope could not
be assessed (brew update in progress, or brew too far behind upstream), so
the result is not provably clean.`,
	Example: `  chainsaw brew verify
  chainsaw brew verify --links
  sudo chainsaw brew verify --repo homebrew --json --out /var/db/chainsaw/brew-verify.json
  sudo chainsaw brew verify --links --reset-baseline`,
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runBrewVerify,
}

func init() {
	brewVerifyCmd.Flags().Bool("links", false, "Check the bin/, sbin/ and opt/ link farm (offline)")
	brewVerifyCmd.Flags().Bool("brew", false, "Check brew's own code against upstream and /etc/homebrew/brew.env against org policy")
	brewVerifyCmd.Flags().String("prefix", "", "Homebrew prefix (default: /opt/homebrew, then /usr/local, then /home/linuxbrew/.linuxbrew)")
	brewVerifyCmd.Flags().String("repo", "", "Homebrew repository name on the server, as given to `chainsaw brew env --repo`")
	brewVerifyCmd.Flags().Bool("reset-baseline", false, "Root only: discard the stored link baseline and record the current links as the new one")
	brewVerifyCmd.Flags().Bool("attest", false, "Post the result to the server as this device's homebrew-integrity entry (needs a key with compliance:root-attest; the MDM daemon does this)")
	brewVerifyCmd.Flags().String("device-id", "", "Device ID for --attest (default: hostname/$USER, as doctor --attest uses)")
	brewVerifyCmd.Flags().Bool("json", false, "Print the result as JSON")
	brewVerifyCmd.Flags().String("out", "", "Also write the JSON result to this file (atomically)")
	brewGuardCmd.AddCommand(brewVerifyCmd)
}

// BrewVerifySchema names the JSON layout doctor --strict reads.
const BrewVerifySchema = "chainsaw.brew-verify/1"

// Brew verify verdicts.
const (
	brewVerdictClean      = "clean"
	brewVerdictTamper     = "tamper"
	brewVerdictDrift      = "drift" // brew.env differs from policy; usually a policy edit the MDM has not re-fetched yet
	brewVerdictIncomplete = "incomplete"
	brewVerdictError      = "error"
)

type brewVerifyResult struct {
	Schema      string                   `json:"schema"`
	CheckedAt   time.Time                `json:"checked_at"`
	Prefix      string                   `json:"prefix"`
	Verdict     string                   `json:"verdict"`
	Links       *homebrew.LinkReport     `json:"links,omitempty"`
	Brew        *homebrew.BrewTreeReport `json:"brew,omitempty"`
	Ruby        *brewRubyReport          `json:"ruby,omitempty"`
	Env         *brewVerifyEnv           `json:"env,omitempty"`
	Tamper      []string                 `json:"tamper"`
	Drift       []string                 `json:"drift"`
	NotAssessed []string                 `json:"not_assessed"`
	Errors      []string                 `json:"errors"`
	// AttestError is set when --attest could not deliver the result.
	AttestError string `json:"attest_error,omitempty"`
}

type brewVerifyEnv struct {
	Path  string   `json:"path"`
	Drift []string `json:"drift"`
	Extra []string `json:"extra"`
}

// Seams swapped in tests.
var (
	brewVerifyPrefixes  = []string{"/opt/homebrew", "/usr/local", "/home/linuxbrew/.linuxbrew"}
	brewVerifyEnvPath   = hook.BrewSystemEnvPath
	brewVerifyNow       = time.Now
	brewVerifyFetchTree = func(commit string, out any) error {
		return newClient().Get("/api/homebrew/brew-tree?commit="+commit, out)
	}
	brewVerifyFetchEnv    = func(path string) ([]byte, error) { return newClient().GetText(path) }
	brewVerifyPostRoot    = func(body any) error { return newClient().Post("/api/attestations/root", body, nil) }
	brewVerifyFetchVendor = func(query string, out any) error {
		return newClient().Get("/api/homebrew/vendor-manifest?"+query, out)
	}
	brewVerifyFileSecure = rootOwnedNotWritable
	brewVerifySleep      = time.Sleep
	brewVerifyGeteuid    = os.Geteuid
	// brewLinksBaselineDir holds the names a root run saw brew own, per
	// prefix. Outside the prefix and root-only, so the user cannot rewrite
	// what "brew's" means; see homebrew.CheckLinks.
	brewLinksBaselineDir = "/var/db/chainsaw"
)

func runBrewVerify(cmd *cobra.Command, _ []string) error {
	links, _ := cmd.Flags().GetBool("links")
	brewSec, _ := cmd.Flags().GetBool("brew")
	if !links && !brewSec {
		links, brewSec = true, true
	}
	prefix, _ := cmd.Flags().GetString("prefix")
	repoName, _ := cmd.Flags().GetString("repo")
	asJSON, _ := cmd.Flags().GetBool("json")
	out, _ := cmd.Flags().GetString("out")
	reset, _ := cmd.Flags().GetBool("reset-baseline")
	if reset && brewVerifyGeteuid() != 0 {
		return &ExitCodeError{Code: ExitOpError, Err: errors.New("--reset-baseline needs root: the link baseline is root's record")}
	}
	if reset {
		links = true
	}

	res := verifyBrew(prefix, repoName, links, brewSec, reset)
	if attest, _ := cmd.Flags().GetBool("attest"); attest {
		dev, _ := cmd.Flags().GetString("device-id")
		if strings.TrimSpace(dev) == "" {
			dev, _ = deriveDeviceIdentity()
		}
		body := map[string]any{"device_id": dev, "ecosystems": map[string]ecosystemState{brewIntegrityName: brewIntegrityState(res)}}
		if err := brewVerifyPostRoot(body); err != nil {
			res.AttestError = err.Error()
		}
	}

	body, _ := json.MarshalIndent(res, "", "  ")
	body = append(body, '\n')
	if out != "" {
		if err := writeFileAtomic(out, body, 0o644); err != nil {
			return &ExitCodeError{Code: ExitOpError, Err: fmt.Errorf("writing %s: %w", out, err)}
		}
	}
	w := cmd.OutOrStdout()
	if asJSON {
		_, _ = w.Write(body)
	} else {
		printBrewVerify(w, res)
	}
	if res.AttestError != "" {
		fmt.Fprintf(cmd.ErrOrStderr(), "attest failed: %s\n", res.AttestError)
	}
	switch res.Verdict {
	case brewVerdictTamper:
		return &ExitCodeError{Code: ExitBlocked, Err: errors.New("Homebrew tampering found")}
	case brewVerdictDrift:
		return &ExitCodeError{Code: ExitBlocked, Err: errors.New("brew.env differs from org policy")}
	case brewVerdictError:
		return &ExitCodeError{Code: ExitOpError, Err: errors.New("a requested check could not run: " + strings.Join(res.Errors, "; "))}
	case brewVerdictIncomplete:
		return &ExitCodeError{Code: policyScanIncompleteExitCode, Err: errors.New("not assessed: " + strings.Join(res.NotAssessed, "; "))}
	}
	if res.AttestError != "" {
		return &ExitCodeError{Code: ExitOpError, Err: errors.New("clean, but the result was not delivered: " + res.AttestError)}
	}
	return nil
}

// verifyBrew runs the requested sections over --prefix, or over EVERY
// Homebrew prefix found (an Apple-silicon Mac with a Rosetta /usr/local
// install has two, and checking only the first would call the other clean).
// The verdict ranks tamper over drift over an error over not-assessed: a
// found swap is reported even if another section could not run, and a
// partial run is never clean. links/brew/env detail in the JSON is the first
// prefix's; findings from every prefix are in the lists, path-qualified.
func verifyBrew(prefix, repoName string, links, brewSec, resetBaseline bool) brewVerifyResult {
	res := brewVerifyResult{Schema: BrewVerifySchema, CheckedAt: brewVerifyNow().UTC(),
		Tamper: []string{}, Drift: []string{}, NotAssessed: []string{}, Errors: []string{}}
	prefixes := []string{prefix}
	if prefix == "" {
		prefixes = nil
		for _, p := range brewVerifyPrefixes {
			if fi, err := os.Stat(filepath.Join(p, "Cellar")); err == nil && fi.IsDir() {
				prefixes = append(prefixes, p)
			}
		}
	}
	res.Prefix = strings.Join(prefixes, ",")
	if len(prefixes) == 0 {
		res.Errors = append(res.Errors, "no Homebrew prefix found (pass --prefix)")
	}
	for _, p := range prefixes {
		label := ""
		if len(prefixes) > 1 {
			label = p + ": "
		}
		if links {
			verifyLinks(&res, p, label, resetBaseline)
		}
		if brewSec {
			verifyBrewCode(&res, p, label)
		}
	}
	if brewSec && len(prefixes) > 0 {
		verifyBrewEnv(&res, repoName)
	}
	switch {
	case len(res.Tamper) > 0:
		res.Verdict = brewVerdictTamper
	case len(res.Drift) > 0:
		res.Verdict = brewVerdictDrift
	case len(res.Errors) > 0:
		res.Verdict = brewVerdictError
	case len(res.NotAssessed) > 0:
		res.Verdict = brewVerdictIncomplete
	default:
		res.Verdict = brewVerdictClean
	}
	return res
}

// verifyLinks checks the link farm against the stored baseline and, run as
// root, stores the next one. A baseline a non-root user could have written
// is TAMPER and is neither trusted nor overwritten.
func verifyLinks(res *brewVerifyResult, prefix, label string, reset bool) {
	sum := sha256.Sum256([]byte(prefix))
	path := filepath.Join(brewLinksBaselineDir, "brew-links-"+hex.EncodeToString(sum[:8])+".json")
	var base map[string]string
	trusted := true
	if !reset {
		if _, err := os.Lstat(path); err == nil {
			if err := brewVerifyFileSecure(path); err != nil {
				res.Tamper = append(res.Tamper, label+"link baseline "+path+": "+err.Error())
				trusted = false
			} else if b, err := os.ReadFile(path); err != nil {
				res.Errors = append(res.Errors, label+"link baseline: "+err.Error())
				trusted = false
			} else if err := json.Unmarshal(b, &base); err != nil {
				res.Errors = append(res.Errors, label+"link baseline "+path+": not valid JSON")
				trusted = false
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			res.Errors = append(res.Errors, label+"link baseline: "+err.Error())
			trusted = false
		}
	}
	r, err := homebrew.CheckLinks(prefix, base)
	if err != nil {
		res.Errors = append(res.Errors, label+"links: "+err.Error())
		return
	}
	if res.Links == nil {
		res.Links = &r
	}
	for _, f := range r.Findings {
		if f.Severity == homebrew.SeverityTamper {
			res.Tamper = append(res.Tamper, label+f.Path+": "+f.Reason)
		}
	}
	if trusted && brewVerifyGeteuid() == 0 {
		body, _ := json.Marshal(r.Baseline)
		err := os.MkdirAll(brewLinksBaselineDir, 0o755)
		if err == nil {
			err = writeFileAtomic(path, body, 0o644)
		}
		if err != nil {
			res.Errors = append(res.Errors, label+"saving link baseline: "+err.Error())
		}
	}
}

func verifyBrewCode(res *brewVerifyResult, prefix, label string) {
	repo, err := homebrew.FindBrewRepo(prefix)
	if err != nil {
		res.Errors = append(res.Errors, label+"brew: "+err.Error())
		return
	}
	tamper := func(msg string) { res.Tamper = append(res.Tamper, label+msg) }
	// Intel: the brew on PATH is prefix/bin/brew, a link into the checkout
	// at prefix/Homebrew. Re-pointing that link runs another brew entirely.
	if repo != prefix {
		want := filepath.Join(repo, "bin", "brew")
		if t, err := os.Readlink(filepath.Join(prefix, "bin", "brew")); err != nil {
			tamper("bin/brew: not a symlink to " + want)
		} else if homebrew.ResolveLink(filepath.Join(prefix, "bin"), t) != want {
			tamper("bin/brew: points at " + t + ", not " + want)
		}
	}
	gitFindings, err := homebrew.CheckGitConfig(repo)
	if err != nil {
		res.Errors = append(res.Errors, label+"brew: "+err.Error())
	}
	for _, f := range gitFindings {
		if f.Severity == homebrew.SeverityTamper {
			tamper(f.Path + ": " + f.Reason)
		}
	}
	if homebrew.UpdateInProgress(repo, brewVerifyNow()) {
		brewVerifySleep(30 * time.Second) // one retry: most updates finish well inside this
		if homebrew.UpdateInProgress(repo, brewVerifyNow()) {
			res.NotAssessed = append(res.NotAssessed, label+"brew: update in progress; re-run shortly")
			return
		}
	}
	head, err := homebrew.ReadHead(repo)
	if err != nil {
		res.Errors = append(res.Errors, label+"brew: "+err.Error())
		return
	}
	var tree struct {
		Upstream  string               `json:"upstream"`
		Behind    int                  `json:"behind"`
		Truncated bool                 `json:"truncated"`
		Entries   []homebrew.TreeEntry `json:"entries"`
	}
	if err := brewVerifyFetchTree(head, &tree); err != nil {
		res.Errors = append(res.Errors, label+"brew: upstream tree: "+err.Error())
		return
	}
	switch {
	case tree.Upstream == "not_upstream":
		tamper("brew: HEAD " + head + " is not a commit on upstream Homebrew/brew main")
		return
	case tree.Upstream == "too_old":
		// An old upstream brew is byte-identical to upstream and may predate
		// the brew.env settings the policy relies on. Never clean.
		res.NotAssessed = append(res.NotAssessed, fmt.Sprintf("%sbrew: %s is %d commits behind upstream main; run `brew update`", label, head[:12], tree.Behind))
		return
	case tree.Upstream != "ancestor":
		res.Errors = append(res.Errors, label+"brew: server answered upstream="+tree.Upstream)
		return
	case tree.Truncated:
		res.NotAssessed = append(res.NotAssessed, label+"brew: GitHub truncated the tree for "+head)
		return
	}
	r, err := homebrew.CompareBrewTree(repo, head, tree.Entries)
	if err != nil {
		res.Errors = append(res.Errors, label+"brew: "+err.Error())
		return
	}
	// A `brew update` that ran during the hash compares old HEAD with new
	// files. Check again; a moved HEAD or a fresh update makes the run
	// "not assessed" rather than a false TAMPER.
	if again, err := homebrew.ReadHead(repo); err != nil || again != head || homebrew.UpdateInProgress(repo, brewVerifyNow()) {
		res.NotAssessed = append(res.NotAssessed, label+"brew: updated while being checked; re-run shortly")
		return
	}
	if res.Brew == nil {
		res.Brew = &r
	}
	codeTampered := false
	for _, f := range r.Findings {
		if f.Severity == homebrew.SeverityTamper {
			tamper(f.Path + ": " + f.Reason)
			codeTampered = true
		}
	}
	// The Ruby pins are tracked files: they are upstream's only once the
	// comparison above found nothing.
	if !codeTampered {
		verifyRubyVendor(res, repo, prefix, label)
	}
}

// brewRubyReport summarises the portable Ruby and gem comparison.
type brewRubyReport struct {
	Version     string             `json:"portable_ruby"`
	Files       int                `json:"files_compared"`
	Gems        int                `json:"gems_compared"`
	NotCompared []string           `json:"compiled_not_compared"`
	Findings    []homebrew.Finding `json:"findings"`
}

// portableRubyArch is the vendor/portable-ruby-<arch> file brew reads: an
// Intel prefix (/usr/local) runs x86_64 Ruby even on Apple silicon.
func portableRubyArch(prefix string) string {
	osName := runtime.GOOS
	proc := map[string]string{"arm64": "arm64", "amd64": "x86_64"}[runtime.GOARCH]
	if osName == "darwin" && prefix == "/usr/local" {
		proc = "x86_64"
	}
	return proc + "-" + osName
}

func verifyRubyVendor(res *brewVerifyResult, repo, prefix, label string) {
	rr := &brewRubyReport{NotCompared: []string{}, Findings: []homebrew.Finding{}}
	if res.Ruby == nil {
		res.Ruby = rr
	}
	vendor := homebrew.VendorDir(repo)
	rel := func(p string) string { r, _ := filepath.Rel(repo, p); return filepath.ToSlash(r) }
	tamper := func(msg string) { res.Tamper = append(res.Tamper, label+msg) }
	record := func(fs []homebrew.Finding) {
		for _, f := range fs {
			rr.Findings = append(rr.Findings, f)
			if f.Severity == homebrew.SeverityTamper {
				tamper(f.Path + ": " + f.Reason)
			}
		}
	}
	version, sum, err := homebrew.PortableRubyPin(repo, portableRubyArch(prefix))
	if err != nil {
		res.Errors = append(res.Errors, label+"ruby: "+err.Error())
		return
	}
	rr.Version = version
	rubyDir := filepath.Join(vendor, "portable-ruby", version)
	// brew runs portable-ruby/current/bin/ruby.
	switch cur, err := os.Readlink(filepath.Join(vendor, "portable-ruby", "current")); {
	case errors.Is(err, fs.ErrNotExist):
		// Linux brew runs a recent enough system Ruby instead.
		res.NotAssessed = append(res.NotAssessed, label+"ruby: brew does not run portable Ruby here; its Ruby and gems are not compared")
		return
	case err != nil || strings.ContainsAny(cur, "/\\") || cur == ".." || cur == ".":
		tamper(rel(filepath.Join(vendor, "portable-ruby", "current")) + ": not a link to an installed portable Ruby version")
		return
	case cur != version:
		res.NotAssessed = append(res.NotAssessed, fmt.Sprintf("%sruby: brew runs portable Ruby %s, the pin is %s; run any brew command to install it", label, cur, version))
		return
	}
	var m struct {
		Unavailable string                `json:"unavailable"`
		Extensions  bool                  `json:"extensions"`
		Files       []homebrew.VendorFile `json:"files"`
	}
	if err := brewVerifyFetchVendor("kind=portable-ruby&sha256="+sum, &m); err != nil {
		res.Errors = append(res.Errors, label+"ruby: manifest: "+err.Error())
		return
	}
	if m.Unavailable != "" {
		res.NotAssessed = append(res.NotAssessed, label+"ruby: portable Ruby "+version+": "+m.Unavailable)
	} else {
		n, found, err := homebrew.CompareVendorDir(rubyDir, rel(rubyDir), "portable-ruby/"+version+"/", []string{""}, m.Files, false)
		if err != nil {
			res.Errors = append(res.Errors, label+"ruby: "+err.Error())
			return
		}
		rr.Files += n
		record(found)
	}
	gems, exts, err := homebrew.GemPins(repo)
	if err != nil {
		res.Errors = append(res.Errors, label+"gems: "+err.Error())
		return
	}
	// Gem.ruby_api_version: major.minor.0 of the running Ruby.
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		res.Errors = append(res.Errors, label+"gems: cannot derive the Ruby API version from "+version)
		return
	}
	apiDir := filepath.Join(vendor, "bundle", "ruby", parts[0]+"."+parts[1]+".0")
	// Extension directories are on the load path too: only their compiled
	// .bundle files go uncompared.
	for _, e := range exts {
		matches, _ := filepath.Glob(filepath.Join(apiDir, "extensions", "*", "*", e))
		if len(matches) > 0 {
			rr.NotCompared = append(rr.NotCompared, e)
		}
		for _, d := range matches {
			found, err := homebrew.CheckExtensionDir(d, rel(d))
			if err != nil {
				res.Errors = append(res.Errors, label+"gems: "+err.Error())
				return
			}
			record(found)
		}
	}
	present := 0
	for _, g := range gems {
		dir := filepath.Join(apiDir, "gems", g.Dir)
		if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
			continue // a bundler group brew did not install: nothing to load
		}
		present++
		if g.SHA256 == "" {
			res.NotAssessed = append(res.NotAssessed, label+"gems: "+g.Dir+" has no checksum in Gemfile.lock")
			continue
		}
		m.Unavailable, m.Extensions, m.Files = "", false, nil
		if err := brewVerifyFetchVendor("kind=gem&name="+url.QueryEscape(g.Dir)+"&sha256="+g.SHA256, &m); err != nil {
			res.Errors = append(res.Errors, label+"gems: manifest: "+err.Error())
			return
		}
		if m.Unavailable != "" {
			res.NotAssessed = append(res.NotAssessed, label+"gems: "+g.Dir+": "+m.Unavailable)
			continue
		}
		n, found, err := homebrew.CompareVendorDir(dir, rel(dir), "", g.Loads, m.Files, m.Extensions)
		if err != nil {
			res.Errors = append(res.Errors, label+"gems: "+err.Error())
			return
		}
		rr.Files += n
		rr.Gems++
		record(found)
	}
	if present == 0 {
		res.NotAssessed = append(res.NotAssessed, label+"gems: none of the gem directories setup.rb names exist under "+rel(apiDir))
	}
}

func verifyBrewEnv(res *brewVerifyResult, repoName string) {
	path := "/api/homebrew/brew.env"
	if repoName != "" {
		path += "?repo=" + url.QueryEscape(repoName)
	}
	want, err := brewVerifyFetchEnv(path)
	if err != nil {
		res.Errors = append(res.Errors, "brew.env: fetching policy: "+err.Error())
		return
	}
	env := &brewVerifyEnv{Path: brewVerifyEnvPath, Drift: []string{}, Extra: []string{}}
	res.Env = env
	var local []byte
	fi, err := os.Lstat(brewVerifyEnvPath)
	if err == nil && !fi.Mode().IsRegular() {
		err = fmt.Errorf("%s is not a regular file", brewVerifyEnvPath) // never follow a symlink as root
	} else if err == nil {
		local, err = os.ReadFile(brewVerifyEnvPath)
	}
	if errors.Is(err, fs.ErrNotExist) {
		env.Drift = append(env.Drift, "file missing")
	} else if err != nil {
		res.Errors = append(res.Errors, "brew.env: "+err.Error())
		return
	} else {
		if err := brewVerifyFileSecure(brewVerifyEnvPath); err != nil {
			// A brew.env the user can write is a policy the user controls.
			res.Tamper = append(res.Tamper, brewVerifyEnvPath+": "+err.Error())
		}
		drift, extra := homebrew.EnvDrift(string(local), string(want))
		env.Drift = append(env.Drift, drift...)
		env.Extra = extra
	}
	for _, d := range env.Drift {
		res.Drift = append(res.Drift, brewVerifyEnvPath+": "+d)
	}
}

func printBrewVerify(w io.Writer, res brewVerifyResult) {
	fmt.Fprintf(w, "Homebrew prefix: %s\n", res.Prefix)
	if res.Links != nil {
		fmt.Fprintf(w, "links: %d linked formulae, %d links checked, %d unmanaged entries (not Homebrew's; listed in --json)\n",
			res.Links.LinkedKegs, res.Links.Checked, len(res.Links.Unmanaged))
		for _, f := range res.Links.Findings {
			if f.Severity == homebrew.SeverityWarn {
				fmt.Fprintf(w, "  warn %s: %s\n", f.Path, f.Reason)
			}
		}
	}
	if res.Brew != nil {
		fmt.Fprintf(w, "brew: %d files compared with upstream Homebrew/brew %s\n", res.Brew.Compared, res.Brew.Commit[:12])
	}
	if res.Ruby != nil && res.Ruby.Version != "" {
		fmt.Fprintf(w, "ruby: portable Ruby %s and %d gems, %d files compared with their pinned artifacts; %d compiled extensions not compared\n",
			res.Ruby.Version, res.Ruby.Gems, res.Ruby.Files, len(res.Ruby.NotCompared))
		for _, f := range res.Ruby.Findings {
			if f.Severity == homebrew.SeverityWarn {
				fmt.Fprintf(w, "  warn %s: %s\n", f.Path, f.Reason)
			}
		}
	}
	if res.Env != nil && len(res.Env.Drift) == 0 {
		fmt.Fprintf(w, "brew.env: %s matches org policy\n", res.Env.Path)
	}
	for _, t := range res.Tamper {
		fmt.Fprintf(w, "TAMPER %s\n", t)
	}
	for _, d := range res.Drift {
		fmt.Fprintf(w, "DRIFT %s\n", d)
	}
	for _, n := range res.NotAssessed {
		fmt.Fprintf(w, "not assessed: %s\n", n)
	}
	for _, e := range res.Errors {
		fmt.Fprintf(w, "error: %s\n", e)
	}
	fmt.Fprintf(w, "verdict: %s\n", res.Verdict)
	if res.Verdict == brewVerdictClean {
		fmt.Fprintln(w, "(detection only: the prefix is writable by its user; run from MDM as root)")
	}
}

// writeFileAtomic writes via a temp file in the same directory and renames,
// so a reader never sees a half-written result.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
