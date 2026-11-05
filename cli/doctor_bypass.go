package cli

// `chainsaw doctor --bypass-check` reads the user's local package-manager
// config files and reports any registry URL that points away from the
// configured Chainsaw server.
//
// Scope: this is a pure read of *config files* (the same posture as
// existing doctor checks). It does not parse user source code, scan
// repositories, or contact any registry. Missing config files are
// treated as "n/a" — no error, no scary output, just a status line.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/spf13/cobra"

	"github.com/chain305/chainsaw-core/cli/hook"
	"github.com/chain305/chainsaw-core/redact"
)

// bypassFinding is one row in the bypass-check report.
type bypassFinding struct {
	Ecosystem  string `json:"ecosystem"`
	ConfigPath string `json:"config_path"`
	Status     string `json:"status"` // ok | drift | missing | error
	Configured string `json:"configured,omitempty"`
	Expected   string `json:"expected,omitempty"`
	Note       string `json:"note,omitempty"`
	// InBlock is true when the value sits inside a chainsaw-managed block.
	// False with a value set means someone else wrote it: pasted from the
	// docs, or left by an older chainsaw. uninstall-hook never removes it.
	InBlock bool `json:"in_chainsaw_block"`
	// Probe is the HTTP status (or transport error) of an unauthenticated
	// GET against the upstream; Unreachable marks a 5xx or no answer, which
	// fails every install routed there. Plain `doctor` only.
	Probe       string `json:"probe,omitempty"`
	Unreachable bool   `json:"unreachable,omitempty"`
}

type bypassReport struct {
	ChainsawURL string          `json:"chainsaw_url"`
	Findings    []bypassFinding `json:"findings"`
}

func runDoctorBypassCheck(cmd *cobra.Command, _ []string) error {
	expected := strings.TrimSpace(cfgServerURL())
	if expected == "" {
		expected = strings.TrimSpace(os.Getenv("CHAINSAW_SERVER"))
	}

	rep := bypassReport{ChainsawURL: expected}

	rep.Findings = upstreamFindings(expected, false)

	if useJSON(cmd) {
		enc := json.NewEncoder(cmd.OutOrStdout())
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	}

	printBypassReport(cmd.OutOrStdout(), rep)

	emit("cli.doctor.bypass_check", map[string]any{
		"chainsaw_url": expected,
		"findings":     len(rep.Findings),
	})
	return nil
}

func printBypassReport(w io.Writer, rep bypassReport) {
	if rep.ChainsawURL == "" {
		fmt.Fprintln(w, "warning: no Chainsaw server URL configured (run `chainsaw setup` or set CHAINSAW_SERVER); reporting raw values only")
		fmt.Fprintln(w)
	} else {
		fmt.Fprintf(w, "Comparing local config files against: %s\n\n", rep.ChainsawURL)
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ECOSYSTEM\tSTATUS\tCONFIG\tCONFIGURED")
	for _, f := range rep.Findings {
		configured := f.Configured
		if configured == "" {
			configured = "—"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f.Ecosystem, f.Status, f.ConfigPath, configured)
	}
	tw.Flush()
	fmt.Fprintln(w)
	for _, f := range rep.Findings {
		if f.Status == "drift" {
			fmt.Fprintf(w, "drift in %s (%s):\n", f.Ecosystem, f.ConfigPath)
			fmt.Fprintf(w, "  configured: %s\n", f.Configured)
			fmt.Fprintf(w, "  expected:   %s\n", f.Expected)
			fmt.Fprintf(w, "  remediation: re-run `chainsaw install-hook %s` or update the file directly.\n\n", f.Ecosystem)
		}
	}
}

// driftCompare returns "ok" / "drift" given two URL-shaped strings.
// "Same" means same scheme + host + port. Path differences are ignored
// — chainsaw's npm proxy lives at /<repo>/, but the registry root is
// what npm cares about for routing.
//
// The comparison is on PARSED authorities, not on string prefixes. The
// previous `HasPrefix(c,e) || HasPrefix(e,c)` had no host boundary, so
// the one check whose entire job is "is my registry pointing away from
// chainsaw" answered "ok" for a lookalike host that merely EXTENDS the
// expected one:
//
//	expected   https://chainsaw.example.com
//	configured https://chainsaw.example.com.attacker.net/repository/npm/
//
// and the reverse arm accepted a truncated host (https://chainsaw.example)
// just as happily.
//
// Only when a side cannot be parsed as an authority do we fall back — and
// then to EXACT equality, never to a prefix, because a prefix rule on
// unparseable input is exactly the hole being closed.
func driftCompare(configured, expected string) string {
	if configured == "" {
		return "missing"
	}
	if expected == "" {
		// No reference URL; can't decide. Report informational only.
		return "ok"
	}
	cScheme, cHost, cOK := parseCompareTarget(configured)
	eScheme, eHost, eOK := parseCompareTarget(expected)
	if !cOK || !eOK {
		if normalizeURL(configured) == normalizeURL(expected) {
			return "ok"
		}
		return "drift"
	}
	if cScheme == eScheme && cHost == eHost {
		return "ok"
	}
	return "drift"
}

// parseCompareTarget splits a config value into its scheme and normalised
// host:port, reporting false when the value carries no authority to compare.
//
// The transport-prefix strip is load-bearing for cargo: parseCargoIndex
// returns `sparse+https://host/…` (and git dependencies use `git+https://`),
// which url.Parse reads as the scheme "sparse+https". A naive parse would
// therefore make EVERY correctly-wired cargo config report drift — a fresh
// false alarm introduced by the fix for a different one.
func parseCompareTarget(raw string) (scheme, host string, ok bool) {
	s := strings.TrimSpace(raw)
	for _, prefix := range []string{"sparse+", "git+", "registry+"} {
		s = strings.TrimPrefix(s, prefix)
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", "", false
	}
	scheme = strings.ToLower(u.Scheme)
	host = strings.ToLower(u.Host)
	// An explicitly-written default port names the same endpoint as an
	// omitted one; treating them as different hosts would be a new false
	// "drift" for anyone who spells out :443.
	switch {
	case scheme == "https" && strings.HasSuffix(host, ":443"):
		host = strings.TrimSuffix(host, ":443")
	case scheme == "http" && strings.HasSuffix(host, ":80"):
		host = strings.TrimSuffix(host, ":80")
	}
	return scheme, host, true
}

func normalizeURL(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimRight(s, "/")
	s = strings.ToLower(s)
	return s
}

// checkNpmrc reads ~/.npmrc and returns the registry= line.
func checkNpmrc(expected string) bypassFinding {
	home, err := os.UserHomeDir()
	if err != nil {
		return bypassFinding{Ecosystem: "npm", Status: "error", Note: err.Error()}
	}
	path := filepath.Join(home, ".npmrc")
	f := bypassFinding{Ecosystem: "npm", ConfigPath: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			f.Status = "n/a"
			f.Note = "no ~/.npmrc; npm will use its built-in default"
			return f
		}
		f.Status = "error"
		f.Note = err.Error()
		return f
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "registry") {
			if i := strings.Index(line, "="); i >= 0 {
				f.Configured = strings.TrimSpace(line[i+1:])
				break
			}
		}
	}
	f.InBlock = hook.BlockContains(data, f.Configured)
	f.Expected = expected
	f.Status = driftCompare(f.Configured, expected)
	f.Configured = redactConfigured(f.Configured)
	return f
}

// redactConfigured strips the password out of a registry URL lifted from a
// user's config file, and is the LAST thing every check does to
// bypassFinding.Configured.
//
// `install-hook pip` writes
//
//	index-url = https://<client_id>:<client_secret>@host/repository/@org/pypi/simple/
//
// and npm/cargo/gemrc have the same shape. That string was printed in the
// CONFIGURED column, printed again in the drift block, and emitted verbatim
// by `--bypass-check --json` — the exact artefact users attach to support
// tickets and paste into terminal recordings.
//
// Two properties matter. It runs AFTER driftCompare, so no verdict can
// change: the comparison still sees the real value. And it is applied at
// ASSIGNMENT rather than at each renderer, so the table, the drift block,
// and the JSON encoder are covered by construction — a future fourth sink
// cannot reintroduce the leak. The username survives (see redact.URL): the
// operator's question here is "which client_id is wired to this host", and
// answering it is the point of the diagnostic.
func redactConfigured(s string) string {
	return redact.URL(s)
}

// checkPipConf reads the user's pip.conf. Path varies by OS:
//   - macOS:   ~/Library/Application Support/pip/pip.conf  (also ~/.pip/pip.conf)
//   - Linux:   ~/.config/pip/pip.conf  (also ~/.pip/pip.conf)
//   - Windows: %APPDATA%/pip/pip.ini
//
// pip reads the legacy file and then the modern one, and a later file wins
// key by key, so the effective index-url is the last one set. On macOS the
// modern file is ~/Library/Application Support/pip only when that directory
// exists; otherwise pip falls back to ~/.config/pip (pip's appdirs rule).
func checkPipConf(expected string) bypassFinding {
	home, _ := os.UserHomeDir()
	candidates := []string{filepath.Join(home, ".pip", "pip.conf")}
	switch runtime.GOOS {
	case "darwin":
		dir := filepath.Join(home, "Library", "Application Support", "pip")
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			dir = filepath.Join(home, ".config", "pip")
		}
		candidates = append(candidates, filepath.Join(dir, "pip.conf"))
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			candidates = append(candidates, filepath.Join(appdata, "pip", "pip.ini"))
		}
	default:
		dir := os.Getenv("XDG_CONFIG_HOME")
		if dir == "" {
			dir = filepath.Join(home, ".config")
		}
		candidates = append(candidates, filepath.Join(dir, "pip", "pip.conf"))
	}
	if p := os.Getenv("PIP_CONFIG_FILE"); p != "" {
		candidates = append(candidates, p)
	}

	f := bypassFinding{Ecosystem: "pip"}
	found := false
	for _, p := range candidates {
		data, err := os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			f.ConfigPath, f.Status, f.Note = p, "error", err.Error()
			return f
		}
		if !found {
			f.ConfigPath = p
		}
		found = true
		if v := parsePipIndexURL(string(data)); v != "" {
			f.ConfigPath, f.Configured = p, v
			f.InBlock = hook.BlockContains(data, v)
		}
	}
	if v := strings.TrimSpace(os.Getenv("PIP_INDEX_URL")); v != "" {
		f.ConfigPath, f.Configured, f.InBlock, found = "$PIP_INDEX_URL", v, false, true
	}
	if !found {
		f.ConfigPath = candidates[len(candidates)-1]
		f.Status = "n/a"
		f.Note = "no pip.conf found at any standard location"
		return f
	}
	f.Expected = expected
	f.Status = driftCompare(f.Configured, expected)
	f.Configured = redactConfigured(f.Configured)
	return f
}

// parsePipIndexURL returns the index-url value from a pip.conf body.
// The file is INI-style; we only care about [global] index-url.
func parsePipIndexURL(body string) string {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "index-url") || strings.HasPrefix(line, "index_url") {
			if i := strings.Index(line, "="); i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

// checkGemrc reads ~/.gemrc.
func checkGemrc(expected string) bypassFinding {
	home, _ := os.UserHomeDir()
	path := filepath.Join(home, ".gemrc")
	f := bypassFinding{Ecosystem: "gem", ConfigPath: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			f.Status = "n/a"
			f.Note = "no ~/.gemrc; gem will use its built-in default"
			return f
		}
		f.Status = "error"
		f.Note = err.Error()
		return f
	}
	// .gemrc is YAML-ish; rather than pulling in a YAML parser, scan
	// for `:sources:` and grab the first list item — sufficient for the
	// drift signal.
	body := string(data)
	if i := strings.Index(body, ":sources:"); i >= 0 {
		tail := body[i:]
		for _, line := range strings.Split(tail, "\n")[1:] {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "-") {
				v := strings.TrimSpace(strings.TrimPrefix(line, "-"))
				v = strings.Trim(v, `"' `)
				f.Configured = v
				break
			}
			if line != "" && !strings.HasPrefix(line, "#") {
				break
			}
		}
	}
	f.Expected = expected
	f.Status = driftCompare(f.Configured, expected)
	f.Configured = redactConfigured(f.Configured)
	return f
}

// checkCargoConfig reads $CARGO_HOME/config.toml (or the legacy
// extensionless config) and reports where crates.io traffic actually goes.
func checkCargoConfig(expected string) bypassFinding {
	cargoHome := os.Getenv("CARGO_HOME")
	if cargoHome == "" {
		home, _ := os.UserHomeDir()
		cargoHome = filepath.Join(home, ".cargo")
	}
	candidates := []string{
		filepath.Join(cargoHome, "config.toml"),
		filepath.Join(cargoHome, "config"),
	}
	f := bypassFinding{Ecosystem: "cargo"}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			f.ConfigPath = p
			data, err := os.ReadFile(p)
			if err != nil {
				f.Status = "error"
				f.Note = err.Error()
				return f
			}
			f.Configured, err = parseCargoUpstream(string(data))
			if err != nil {
				f.Status = "error"
				f.Note = "cannot parse as TOML: " + err.Error()
				return f
			}
			f.InBlock = hook.BlockContains(data, f.Configured)
			f.Expected = expected
			f.Status = driftCompare(f.Configured, expected)
			f.Configured = redactConfigured(f.Configured)
			return f
		}
	}
	f.ConfigPath = candidates[0]
	f.Status = "n/a"
	f.Note = "no cargo config found at any standard location"
	return f
}

// parseCargoUpstream returns the index cargo fetches crates.io packages
// from: it follows `[source.crates-io] replace-with` (through any chain of
// replacements) to the `registry` of the [source.<name>] it names, or the
// `index` of a [registries.<name>]. Empty when crates.io is not replaced.
//
// This is the shape every chainsaw doc tells users to paste, and the one
// the old `index =` line scan could not see: a replaced crates.io pointing
// at a dead host read as "missing" while every `cargo build` failed.
func parseCargoUpstream(body string) (string, error) {
	var cfg struct {
		Source map[string]struct {
			ReplaceWith string `toml:"replace-with"`
			Registry    string `toml:"registry"`
		} `toml:"source"`
		Registries map[string]struct {
			Index string `toml:"index"`
		} `toml:"registries"`
	}
	if _, err := toml.Decode(body, &cfg); err != nil {
		return "", err
	}
	name := "crates-io"
	for range 8 { // cargo rejects cycles; the bound only stops a bad file looping us
		src, ok := cfg.Source[name]
		if !ok {
			if r, ok := cfg.Registries[name]; ok {
				return r.Index, nil
			}
			return "", nil
		}
		if src.ReplaceWith == "" {
			if name == "crates-io" {
				return "", nil
			}
			return src.Registry, nil
		}
		name = src.ReplaceWith
	}
	return "", nil
}

// checkGoProxy reports the first proxy in the effective GOPROXY: the
// environment wins over the go env file, as in the go command.
func checkGoProxy(expected string) bypassFinding {
	f := bypassFinding{Ecosystem: "go"}
	raw := os.Getenv("GOPROXY")
	var data []byte
	if raw != "" {
		f.ConfigPath = "$GOPROXY"
	} else {
		p, err := hook.GoEnvFile()
		if err != nil {
			f.Status, f.Note = "error", err.Error()
			return f
		}
		f.ConfigPath = p
		data, err = os.ReadFile(p)
		if err != nil {
			if os.IsNotExist(err) {
				f.Status = "n/a"
				f.Note = "no go env file; go uses its built-in default"
				return f
			}
			f.Status, f.Note = "error", err.Error()
			return f
		}
		for _, line := range strings.Split(string(data), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "GOPROXY="); ok {
				raw = v // go reads the last assignment
			}
		}
		f.InBlock = hook.BlockContains(data, "GOPROXY="+raw)
	}
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == '|' }) {
		if part = strings.TrimSpace(part); part != "" && part != "direct" && part != "off" {
			f.Configured = part
			break
		}
	}
	f.Expected = expected
	f.Status = driftCompare(f.Configured, expected)
	f.Configured = redactConfigured(f.Configured)
	return f
}

// upstreamFindings is every registry redirect the local config files make,
// whoever wrote them. With probe set, each configured upstream also gets an
// unauthenticated GET, so a dead host shows up before an install does.
func upstreamFindings(expected string, probe bool) []bypassFinding {
	fs := []bypassFinding{
		checkNpmrc(expected),
		checkPipConf(expected),
		checkGemrc(expected),
		checkCargoConfig(expected),
		checkGoProxy(expected),
	}
	if probe {
		probeUpstreams(fs)
	}
	return fs
}

// probeUpstream is swapped in tests so they never touch the network.
var probeUpstream = func(ctx context.Context, target string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("User-Agent", "chainsaw-doctor")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	return resp.StatusCode, nil
}

func probeUpstreams(fs []bypassFinding) {
	var wg sync.WaitGroup
	for i := range fs {
		// A public default is not a finding and is not printed, so it is not
		// worth a request either.
		target := upstreamProbeURL(fs[i].Ecosystem, fs[i].Configured)
		if target == "" || isPublicRegistry(fs[i].Ecosystem, fs[i].Configured) {
			continue
		}
		wg.Add(1)
		go func(f *bypassFinding) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()
			code, err := probeUpstream(ctx, target)
			switch {
			case err != nil:
				f.Probe, f.Unreachable = "no answer: "+shortNetErr(err), true
			case code >= 500:
				f.Probe, f.Unreachable = fmt.Sprintf("HTTP %d", code), true
			default:
				// 401/403/404 still prove a live server; only a dead one
				// fails every install, and that is all this check claims.
				f.Probe = fmt.Sprintf("HTTP %d", code)
			}
		}(&fs[i])
	}
	wg.Wait()
}

// upstreamProbeURL turns a configured value into the URL the manager itself
// would fetch first, minus credentials (the probe never sends them). Empty
// for anything that is not plain http(s).
func upstreamProbeURL(eco, configured string) string {
	s := strings.TrimSpace(configured)
	sparse := strings.HasPrefix(s, "sparse+")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "sparse+"), "registry+")
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return ""
	}
	u.User = nil
	if eco == "cargo" && sparse {
		u.Path = strings.TrimSuffix(u.Path, "/") + "/config.json"
	}
	return u.String()
}

func shortNetErr(err error) string {
	msg := err.Error()
	if i := strings.LastIndex(msg, ": "); i >= 0 {
		msg = msg[i+2:]
	}
	return msg
}

// publicRegistryHost is each manager's own default; a redirect to it is not
// a finding.
var publicRegistryHost = map[string][]string{
	"npm":   {"registry.npmjs.org", "registry.yarnpkg.com"},
	"pip":   {"pypi.org"},
	"cargo": {"index.crates.io", "github.com"},
	"gem":   {"rubygems.org"},
	"go":    {"proxy.golang.org"},
}

func isPublicRegistry(eco, configured string) bool {
	_, host, ok := parseCompareTarget(configured)
	if !ok {
		return false
	}
	for _, h := range publicRegistryHost[eco] {
		if host == h {
			return true
		}
	}
	return false
}

// foreignUpstreamFix says how to undo a redirect chainsaw did not write;
// uninstall-hook cannot, because it only removes its own blocks.
func foreignUpstreamFix(f bypassFinding) string {
	switch f.Ecosystem {
	case "cargo":
		return fmt.Sprintf("remove `replace-with` from [source.crates-io] and the [source.*] table it names in %s", f.ConfigPath)
	case "npm":
		return fmt.Sprintf("remove the registry= line from %s", f.ConfigPath)
	case "pip":
		if f.ConfigPath == "$PIP_INDEX_URL" {
			return "unset PIP_INDEX_URL in your shell profile"
		}
		return fmt.Sprintf("remove the index-url line from %s", f.ConfigPath)
	case "gem":
		return "gem sources --remove " + f.Configured
	case "go":
		if f.ConfigPath == "$GOPROXY" {
			return "unset GOPROXY in your shell profile"
		}
		return "go env -u GOPROXY"
	}
	return "edit " + f.ConfigPath
}

// printUpstreams is plain doctor's view of where installs actually go. It
// shows every non-default upstream, and says loudly when one does not
// answer: that is what turned every `cargo build` into a 502 while the
// table above read "shim".
func printUpstreams(w io.Writer, fs []bypassFinding, probed bool) {
	var shown []bypassFinding
	for _, f := range fs {
		if f.Configured != "" && !isPublicRegistry(f.Ecosystem, f.Configured) {
			shown = append(shown, f)
		}
	}
	if len(shown) == 0 {
		return
	}
	g := glyphs()
	fmt.Fprintln(w, "\nRegistry upstreams (set in your config files, whoever wrote them)")
	for _, f := range shown {
		verdict := "not probed (CHAINSAW_OFFLINE)"
		if probed {
			verdict = g.ok + " " + f.Probe
			if f.Unreachable {
				verdict = g.fail + " " + f.Probe
			}
			if f.Probe == "" {
				verdict = "not probed"
			}
		}
		fmt.Fprintf(w, "  %-6s %s  %s\n", f.Ecosystem, f.Configured, verdict)
		origin := "inside the chainsaw block"
		if !f.InBlock {
			origin = "outside any chainsaw block (pasted by hand or by an older chainsaw)"
		}
		fmt.Fprintf(w, "         from %s, %s\n", f.ConfigPath, origin)
		if f.Status == "drift" {
			fmt.Fprintf(w, "         not your chainsaw server (%s)\n", f.Expected)
		}
		if f.Unreachable || f.Status == "drift" {
			if f.Unreachable {
				fmt.Fprintf(w, "         every %s install routed here fails while this stands\n", f.Ecosystem)
			}
			if f.InBlock {
				fmt.Fprintf(w, "         fix: chainsaw install-hook %s (or uninstall-hook %s)\n", f.Ecosystem, f.Ecosystem)
			} else {
				fmt.Fprintf(w, "         fix: %s\n", foreignUpstreamFix(f))
			}
		}
	}
}

// foreignUpstream is the redirect a manager's config makes outside any
// chainsaw block, if any: the thing uninstall-hook used to call "nothing to
// do" while it kept every install pointed at a host chainsaw no longer owns.
func foreignUpstream(manager string) (bypassFinding, bool) {
	checks := map[string]func(string) bypassFinding{
		"npm": checkNpmrc, "pip": checkPipConf, "cargo": checkCargoConfig, "go": checkGoProxy,
	}
	check, ok := checks[manager]
	if !ok {
		return bypassFinding{}, false
	}
	f := check("")
	return f, f.Configured != "" && !f.InBlock && !isPublicRegistry(manager, f.Configured)
}
