package hook

// Bundler and gem wirers.
//
// Both tools rewrite their config file wholesale — `bundle config set`
// re-serialises ~/.bundle/config and `gem sources --add` re-dumps ~/.gemrc —
// so a comment sentinel is wiped by the user's next ordinary command. Our
// lines still go inside a sentinel block (it carries the credential note and
// makes a fresh install easy to read), but ownership is by KEY and VALUE,
// recorded in an out-of-band <config>.chainsaw file (owned.go). Unwire
// removes our block, and outside it only the keys whose value still matches
// what we recorded.
//
// Bundler (https://bundler.io/man/bundle-config.1.html):
//   - global config: $BUNDLE_CONFIG, else $BUNDLE_USER_CONFIG, else
//     $BUNDLE_USER_HOME/config, else ~/.bundle/config (global_config_file).
//   - lookup order per key: the local ./.bundle/config (or
//     $BUNDLE_APP_CONFIG/config), then the environment, then the global
//     config. $BUNDLE_IGNORE_CONFIG drops both files.
//   - `mirror.https://rubygems.org` is stored as the key
//     BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/ (Bundler normalises a trailing
//     slash onto URI keys, then "." -> "__", "-" -> "___", upcase). Gemfile
//     and Gemfile.lock keep naming rubygems.org; Bundler swaps the fetch URL.
//   - credentials are looked up for the MIRROR's host (`credentials_for`
//     tries the full URI, then uri.host — no port), so they live under
//     BUNDLE_<HOST>, out of the URL.
//   - mirror.<uri>.fallback_timeout is never set: it makes Bundler fall back
//     to rubygems.org when the mirror is slow or down, which is a bypass.
//     mirror.all wins over every per-URI mirror. Either one, wherever Bundler
//     reads settings, means chainsaw's mirror is not the one in use, so Wire
//     refuses and Status reports not wired (bundlerBypassKey).
//   - Bundler 1.x's key_for does not map "-" to "___", so a dashed proxy host
//     gets its credential under both spellings.
//   - comment lines are not comments to Bundler's YAMLSerializer: a line
//     containing ": " is read as a key and written back as one by the next
//     `bundle config`. Our comments never contain ": " (bundlerSafeComments),
//     and the junk keys older builds caused are removed on wire and unwire.
//
// gem (RubyGems Gem::ConfigFile): every RubyGems reads ~/.gemrc when it
// exists. RubyGems 3.0 (macOS system Ruby) reads nothing else; newer releases
// read $XDG_CONFIG_HOME/gem/gemrc only while ~/.gemrc is absent. So chainsaw
// writes ~/.gemrc, and refuses when only the XDG file exists: creating
// ~/.gemrc would make newer RubyGems stop reading it. Files named in $GEMRC
// are merged OVER the user gemrc. `:sources:` is a YAML list; gem takes
// credentials inline in the source URL.

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/chain305/chainsaw-core/redact"
)

const bundlerMirrorKey = "BUNDLE_MIRROR__HTTPS://RUBYGEMS__ORG/"

// rubygemsSourceURL is the org-scoped proxy source, trailing slash included
// (RubyGems sources are directory-like). userinfo is "" or "id:secret@".
func rubygemsSourceURL(opts WireOpts, withCreds bool) (string, *url.URL, error) {
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return "", nil, fmt.Errorf("a server URL is required: run `chainsaw auth login` or pass --server, then re-run install-hook")
	}
	base, err := validateServerURL(server)
	if err != nil {
		return "", nil, err
	}
	repo, err := orgScopedRepoPath(opts.OrgSlug, "rubygems")
	if err != nil {
		return "", nil, err
	}
	u, err := url.Parse(base)
	if err != nil {
		return "", nil, fmt.Errorf("invalid server URL: %w", err)
	}
	if !withCreds || strings.TrimSpace(opts.Credentials) == "" {
		return base + "/" + repo + "/", u, nil
	}
	id, secret, err := parseCreds(opts.Credentials)
	if err != nil {
		return "", nil, err
	}
	scheme, rest := splitScheme(base)
	return fmt.Sprintf("%s%s:%s@%s/%s/", scheme, url.PathEscape(id), url.PathEscape(secret), rest, repo), u, nil
}

// bundlerKeyFor mirrors Bundler::Settings.key_for for a bare host.
func bundlerKeyFor(host string) string {
	k := strings.ReplaceAll(host, ".", "__")
	k = strings.ReplaceAll(k, "-", "___")
	return "BUNDLE_" + strings.ToUpper(k)
}

// parseBundlerLine splits a `KEY: "value"` line the way Bundler's
// YAMLSerializer reads it. Keys contain ":" (BUNDLE_MIRROR__HTTPS://...), so
// the separator is a colon followed by a space or end of line.
func parseBundlerLine(line string) (key, value string, ok bool) {
	t := strings.TrimSpace(line)
	if t == "" || strings.HasPrefix(t, "#") || t == "---" {
		return "", "", false
	}
	if i := strings.Index(t, ": "); i > 0 {
		key, value = t[:i], strings.TrimSpace(t[i+2:])
	} else if strings.HasSuffix(t, ":") {
		key = strings.TrimSuffix(t, ":")
	} else {
		return "", "", false
	}
	if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
		value = value[1 : len(value)-1]
	}
	return key, value, true
}

// bundlerCredentialKeys is every key Bundler may look a host's credential up
// under: Bundler 2.x maps "-" to "___", Bundler 1.x (macOS system Ruby ships
// 1.17) leaves it alone. Same key twice for an undashed host, so deduped.
func bundlerCredentialKeys(host string) []string {
	keys := []string{bundlerKeyFor(host)}
	if v1 := "BUNDLE_" + strings.ToUpper(strings.ReplaceAll(host, ".", "__")); v1 != keys[0] {
		keys = append(keys, v1)
	}
	return keys
}

// bundlerBypassKey says why a Bundler setting defeats chainsaw's
// mirror.https://rubygems.org, or "" when it does not. key is the stored
// form, from a config file or the environment.
//
//   - mirror.all: Mirrors#for returns it ahead of any per-URI mirror, so every
//     source goes there (probed with Bundler 1.17: the lock fetched only from
//     the mirror.all host).
//   - <mirror>.fallback_timeout: Bundler TCP-probes the mirror and uses the
//     original source when it does not answer in time, so a slow or stopped
//     proxy means installs from rubygems.org. A timeout of 0 (or "false")
//     turns the probe off and never falls back (Bundler::Settings::Mirror:
//     "true" is 0.1s, "false" is 0, anything else is String#to_i), so that
//     one is not a bypass.
func bundlerBypassKey(key, value string) string {
	k := strings.TrimSuffix(strings.ToUpper(strings.TrimSpace(key)), "/")
	switch {
	case !strings.HasPrefix(k, "BUNDLE_MIRROR__"):
		return ""
	case strings.HasSuffix(k, "__FALLBACK_TIMEOUT") && !bundlerFallsBack(value):
		return ""
	case strings.HasSuffix(k, "__FALLBACK_TIMEOUT"):
		return bundlerSettingName(key) + " (falls back to the original source when the mirror is slow or down)"
	case k == "BUNDLE_MIRROR__ALL":
		return "mirror.all (overrides every per-source mirror, chainsaw's included)"
	}
	return ""
}

// bundlerFallsBack reports whether a fallback_timeout value makes Bundler
// probe the mirror and fall back to the original source.
func bundlerFallsBack(v string) bool {
	v = strings.TrimSpace(v)
	if v == "true" {
		return true
	}
	if v == "false" {
		return false
	}
	// String#to_i: an optional sign and leading digits, anything else 0.
	n, i := 0, 0
	if i < len(v) && (v[i] == '-' || v[i] == '+') {
		i++
	}
	for ; i < len(v) && v[i] >= '0' && v[i] <= '9'; i++ {
		n = n*10 + int(v[i]-'0')
		if n > 0 {
			return true
		}
	}
	return false
}

// bundlerFileBypasses lists the bypassing settings a Bundler config file sets.
func bundlerFileBypasses(path string, data []byte) []string {
	var out []string
	lines, _ := splitLines(data)
	for _, ln := range lines {
		if k, v, ok := parseBundlerLine(ln); ok {
			if why := bundlerBypassKey(k, v); why != "" {
				out = append(out, why+" in "+path)
			}
		}
	}
	return out
}

// bundlerEnvBypasses lists the bypassing settings the environment sets.
// BUNDLE_IGNORE_CONFIG counts: Bundler then reads no config file at all, so
// the mirror chainsaw wrote is never seen. Bundler tests that variable for
// presence (Settings#ignore_config? is ENV["BUNDLE_IGNORE_CONFIG"], and ""
// is truthy in Ruby), so an empty value counts too.
func bundlerEnvBypasses() []string {
	var out []string
	for _, kv := range os.Environ() {
		k, v, _ := strings.Cut(kv, "=")
		if k == "BUNDLE_IGNORE_CONFIG" {
			out = append(out, "$BUNDLE_IGNORE_CONFIG (Bundler reads no config file, so it never sees chainsaw's mirror)")
			continue
		}
		if strings.TrimSpace(v) == "" {
			continue
		}
		if why := bundlerBypassKey(k, v); why != "" {
			out = append(out, why+" in the environment ($"+k+")")
		}
	}
	return out
}

// bundlerIgnoresConfig is Settings#ignore_config?: set at all, even empty.
func bundlerIgnoresConfig() bool {
	_, ok := os.LookupEnv("BUNDLE_IGNORE_CONFIG")
	return ok
}

// bundlerSafeComments rewrites the comment lines of a block so Bundler's
// YAMLSerializer does not read them as keys: it treats any line containing
// ": " (or ending in ":") as `key: value`, and `bundle config` then writes
// "# generated-at" back out as a setting that outlives unwire.
func bundlerSafeComments(block []byte) []byte {
	lines, trailingNL := splitLines(block)
	for i, ln := range lines {
		if strings.HasPrefix(strings.TrimSpace(ln), "#") {
			ln = strings.ReplaceAll(ln, ": ", " - ")
			lines[i] = strings.TrimSuffix(ln, ":")
		}
	}
	return joinLines(lines, "\n", trailingNL)
}

// isBundlerJunk reports a line that only exists because Bundler read one of
// the comments an earlier chainsaw block carried as a key and wrote it back:
// `# generated-at: "..."`, `# chainsaw: "..."`. Bundler always quotes what it
// writes, which is what tells these apart from a comment the user typed.
func isBundlerJunk(line string) bool {
	t := strings.TrimSpace(line)
	k, v, ok := strings.Cut(t, ": ")
	if !ok || !strings.HasPrefix(v, `"`) {
		return false
	}
	if k == "# generated-at" {
		return true
	}
	for _, sc := range []Scope{ScopeUser, ScopeSystem} {
		for _, s := range credentialNoteSentences("x", WireOpts{Credentials: "a:b", Scope: sc}) {
			if jk, _, ok := strings.Cut("# "+s, ": "); ok && jk == k {
				return true
			}
		}
	}
	return false
}

// ── bundler ──────────────────────────────────────────────────────────────────

type bundlerManager struct{}

func (bundlerManager) Name() string { return "bundler" }

func (bundlerManager) IsInstalled() bool {
	_, err := exec.LookPath("bundle")
	return err == nil
}

func (m bundlerManager) ConfigPath() (string, error) { return m.ConfigPathForScope(ScopeUser) }

func (bundlerManager) ConfigPathForScope(scope Scope) (string, error) {
	if scope != ScopeUser && scope != "" {
		return "", fmt.Errorf("bundler: only --scope user is supported (a project .bundle/config is often committed, and it would carry the credential)")
	}
	return bundlerUserConfigPath()
}

func bundlerUserConfigPath() (string, error) {
	if p := strings.TrimSpace(os.Getenv("BUNDLE_CONFIG")); p != "" {
		return p, nil
	}
	if p := strings.TrimSpace(os.Getenv("BUNDLE_USER_CONFIG")); p != "" {
		return p, nil
	}
	if h := strings.TrimSpace(os.Getenv("BUNDLE_USER_HOME")); h != "" {
		return filepath.Join(h, "config"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".bundle", "config"), nil
}

type kv struct{ key, value string }

func (m bundlerManager) Wire(opts WireOpts) error {
	path, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	source, u, err := rubygemsSourceURL(opts, false)
	if err != nil {
		return err
	}
	want := []kv{{bundlerMirrorKey, source}}
	if creds := strings.TrimSpace(opts.Credentials); creds != "" {
		if _, _, err := parseCreds(creds); err != nil {
			return err
		}
		for _, k := range bundlerCredentialKeys(u.Hostname()) {
			want = append(want, kv{k, creds})
		}
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := checkSentinelIntegrity("bundler", path, data, hashMarker); err != nil {
		return err
	}
	if bp := append(bundlerFileBypasses(path, data), bundlerEnvBypasses()...); len(bp) > 0 {
		return refuse(`Bundler would not use chainsaw's mirror: %s.

Remove it (bundle config unset --global <setting>, or unset the variable),
then re-run install-hook bundler`, strings.Join(bp, "; "))
	}
	rec := readOwned(path)

	// Lines inside our block are ours by marker. Outside it, a line is ours
	// only when its value matches the record; any other line setting a key
	// we want to write is the user's, and we refuse rather than overwrite.
	lines, trailingNL := splitLines(data)
	bs, be, hasBlock := findSentinelLines(lines)
	var keep []string
	for i, ln := range lines {
		if hasBlock && i >= bs && i <= be {
			keep = append(keep, ln)
			continue
		}
		if isBundlerJunk(ln) {
			continue // a comment of ours Bundler re-wrote as a key
		}
		k, v, ok := parseBundlerLine(ln)
		if ok && rec.owns(k, v) {
			continue // ours, relocated by a Bundler rewrite: re-emitted below
		}
		if ok {
			for _, w := range want {
				if k == w.key {
					return refuse(`%s already sets %s outside chainsaw's control.

chainsaw will not overwrite a mirror or credential it did not write. Remove
it (bundle config unset --global %s), then re-run install-hook bundler`,
						path, k, bundlerSettingName(k))
				}
			}
		}
		keep = append(keep, ln)
	}
	var body strings.Builder
	if len(want) > 1 {
		body.WriteString(credentialHeaderNote("the BUNDLE_<host> credential lines below", opts))
	}
	body.WriteString("# Routes every `source \"https://rubygems.org\"` through chainsaw; Gemfile.lock is unchanged.\n")
	for _, w := range want {
		fmt.Fprintf(&body, "%s: %q\n", w.key, w.value)
	}
	var buf strings.Builder
	nl := detectNewline(data)
	for i, ln := range keep {
		buf.WriteString(ln)
		if i < len(keep)-1 || trailingNL {
			buf.WriteString(nl)
		}
	}
	out := replaceOrAppend([]byte(buf.String()), bundlerSafeComments(buildBlock(body.String())))
	if len(data) > 0 {
		if err := backupAndNotify(path, opts); err != nil {
			return err
		}
	}
	if err := writeConfigFile(path, out, opts); err != nil {
		return err
	}
	next := ownedRecord{Entries: map[string]string{}}
	for _, w := range want {
		next.Entries[w.key] = valueHash(w.value)
	}
	return writeOwned(path, next)
}

// bundlerSettingName turns a stored key back into the name `bundle config`
// takes, for the refusal message.
func bundlerSettingName(key string) string {
	k := strings.TrimPrefix(key, "BUNDLE_")
	k = strings.ReplaceAll(k, "___", "-")
	k = strings.ReplaceAll(k, "__", ".")
	return strings.TrimSuffix(strings.ToLower(k), "/")
}

func (m bundlerManager) Unwire(scope Scope) error {
	if scope != ScopeUser && scope != "" {
		return ErrNotWired
	}
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	rec := readOwned(path)
	out, removed := removeSentinel(data)
	lines, trailingNL := splitLines(out)
	var keep []string
	for _, ln := range lines {
		if k, v, ok := parseBundlerLine(ln); ok && rec.owns(k, v) {
			removed = true
			continue
		}
		if isBundlerJunk(ln) {
			removed = true
			continue
		}
		keep = append(keep, ln)
	}
	if !removed {
		return ErrNotWired
	}
	if _, err := backup(path); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	var buf strings.Builder
	nl := detectNewline(data)
	for i, ln := range keep {
		buf.WriteString(ln)
		if i < len(keep)-1 || trailingNL {
			buf.WriteString(nl)
		}
	}
	if err := writeAtomic(path, []byte(buf.String())); err != nil {
		return err
	}
	return removeOwned(path)
}

func (m bundlerManager) Status() (Status, error) {
	path, err := m.ConfigPath()
	if err != nil {
		return Status{}, err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return Status{ConfigPath: path, Installed: m.IsInstalled()}, err
	}
	rec := readOwned(path)
	wired := false
	lines, _ := splitLines(data)
	for _, ln := range lines {
		if k, v, ok := parseBundlerLine(ln); ok && k == bundlerMirrorKey && rec.owns(k, v) {
			wired = true
		}
	}
	// Our mirror on disk is not proof Bundler uses it. The mirror in effect
	// is resolved the way Bundler does (./.bundle/config, then the
	// environment, then this file): a project or environment mirror wins
	// over ours, and mirror.all, a fallback_timeout or BUNDLE_IGNORE_CONFIG
	// anywhere routes around it.
	st := Status{ConfigPath: path, Wired: wired, Installed: m.IsInstalled()}
	if !wired {
		return st, nil
	}
	r := BundlerRubygemsRoute()
	switch {
	case len(r.Bypass) > 0:
		st.Wired, st.Bypassed = false, "Bundler routes around chainsaw's mirror: "+strings.Join(r.Bypass, "; ")
	case r.Mirror == "":
		st.Wired, st.Bypassed = false, "Bundler sees no https://rubygems.org mirror here"
	case !rec.owns(bundlerMirrorKey, r.Mirror):
		st.Wired, st.Bypassed = false, "Bundler uses "+redact.URL(r.Mirror)+" as the https://rubygems.org mirror, set in "+r.Source
	}
	return st, nil
}

// BundlerRoute is what Bundler does with `source "https://rubygems.org"` in
// the current directory.
type BundlerRoute struct {
	// Mirror is the mirror.https://rubygems.org value in effect, "" for none.
	Mirror string
	// Source names where Mirror came from: a file path or "env <KEY>".
	Source string
	// Bypass lists every setting, in any place Bundler reads, that routes
	// around a per-source mirror (mirror.all, a fallback_timeout,
	// BUNDLE_IGNORE_CONFIG). Any entry means Mirror is not reliably used.
	Bypass []string
}

// BundlerRubygemsRoute resolves the rubygems.org mirror with Bundler's own
// precedence (Settings#[]): the local app config (./.bundle/config, or
// $BUNDLE_APP_CONFIG/config), then the environment, then the global config
// ($BUNDLE_CONFIG first). $BUNDLE_IGNORE_CONFIG drops both files.
func BundlerRubygemsRoute() BundlerRoute {
	var r BundlerRoute
	r.Bypass = bundlerEnvBypasses()
	ignoreFiles := bundlerIgnoresConfig()
	var local, global string
	if app := strings.TrimSpace(os.Getenv("BUNDLE_APP_CONFIG")); app != "" {
		local = filepath.Join(app, "config")
	} else if cwd, err := os.Getwd(); err == nil {
		local = filepath.Join(cwd, ".bundle", "config")
	}
	if p, err := bundlerUserConfigPath(); err == nil {
		global = p
	}
	fileMirror := func(f string) string {
		if f == "" || ignoreFiles {
			return ""
		}
		data, err := readOrEmpty(f)
		if err != nil {
			return ""
		}
		r.Bypass = append(r.Bypass, bundlerFileBypasses(f, data)...)
		lines, _ := splitLines(data)
		for _, ln := range lines {
			k, v, ok := parseBundlerLine(ln)
			if ok && strings.TrimSuffix(k, "/") == strings.TrimSuffix(bundlerMirrorKey, "/") && v != "" {
				return v
			}
		}
		return ""
	}
	envMirror := func() (string, string) {
		for _, k := range []string{bundlerMirrorKey, strings.TrimSuffix(bundlerMirrorKey, "/")} {
			if v := strings.TrimSpace(os.Getenv(k)); v != "" {
				return v, "env " + k
			}
		}
		return "", ""
	}
	// Every file is read (for its bypass keys) even after a mirror is found.
	lm, gm := fileMirror(local), fileMirror(global)
	em, esrc := envMirror()
	switch {
	case lm != "":
		r.Mirror, r.Source = lm, local
	case em != "":
		r.Mirror, r.Source = em, esrc
	case gm != "":
		r.Mirror, r.Source = gm, global
	}
	return r
}

// ── gem ──────────────────────────────────────────────────────────────────────

type gemManager struct{}

func (gemManager) Name() string { return "gem" }

func (gemManager) IsInstalled() bool {
	_, err := exec.LookPath("gem")
	return err == nil
}

func (m gemManager) ConfigPath() (string, error) { return m.ConfigPathForScope(ScopeUser) }

func (gemManager) ConfigPathForScope(scope Scope) (string, error) {
	if scope != ScopeUser && scope != "" {
		return "", fmt.Errorf("gem: only --scope user is supported")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	// ~/.gemrc is the one file every RubyGems reads (see the package
	// comment); the XDG gemrc is read only by newer RubyGems, and only while
	// ~/.gemrc is absent. Wire refuses that case rather than guess.
	return filepath.Join(home, ".gemrc"), nil
}

// gemXDGConfigPath is the gemrc newer RubyGems reads when ~/.gemrc is absent.
func gemXDGConfigPath() string {
	xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME"))
	if xdg == "" {
		home, _ := os.UserHomeDir()
		xdg = filepath.Join(home, ".config")
	}
	return filepath.Join(xdg, "gem", "gemrc")
}

func fileExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// GemSources returns the :sources: list gem uses and the file it comes from.
// RubyGems merges the files named in $GEMRC (split on ":" or ";", later ones
// winning) over the user gemrc, so the last $GEMRC file that sets :sources:
// wins, else ~/.gemrc. found is false when none sets it: gem then uses
// https://rubygems.org/. A file that does not parse is skipped, as gem does.
func GemSources() (path string, sources []string, found bool) {
	var files []string
	if p, err := (gemManager{}).ConfigPath(); err == nil {
		files = append(files, p)
	}
	for _, f := range strings.FieldsFunc(os.Getenv("GEMRC"), func(r rune) bool { return r == ':' || r == ';' }) {
		if f = strings.TrimSpace(f); f != "" {
			files = append(files, f)
		}
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var doc map[string]any
		if yaml.Unmarshal(data, &doc) != nil {
			continue
		}
		raw, ok := doc[":sources"]
		if !ok {
			continue
		}
		list, _ := raw.([]any)
		srcs := make([]string, 0, len(list))
		for _, s := range list {
			srcs = append(srcs, fmt.Sprint(s))
		}
		path, sources, found = f, srcs, true
	}
	return path, sources, found
}

// gemDefaultSources are the values a `:sources:` list may hold for chainsaw
// to replace it: RubyGems' own default. Anything else is a choice the user
// made (a corporate mirror, a private server), and we refuse.
var gemDefaultSources = map[string]bool{"https://rubygems.org/": true, "https://rubygems.org": true}

// gemSourcesRegion finds the top-level `:sources:` key outside [skipFrom,
// skipTo] and its list items. end is inclusive. inline is the text after the
// key on the same line.
func gemSourcesRegion(lines []string, skipFrom, skipTo int) (start, end int, items []string, inline string, found bool) {
	for i := 0; i < len(lines); i++ {
		if i >= skipFrom && i <= skipTo {
			continue
		}
		if !strings.HasPrefix(lines[i], ":sources:") {
			continue
		}
		start, end = i, i
		inline = strings.TrimSpace(strings.TrimPrefix(lines[i], ":sources:"))
		for j := i + 1; j < len(lines); j++ {
			t := strings.TrimSpace(lines[j])
			if !strings.HasPrefix(t, "- ") && t != "-" {
				break
			}
			items = append(items, strings.Trim(strings.TrimSpace(strings.TrimPrefix(t, "-")), `"'`))
			end = j
		}
		return start, end, items, inline, true
	}
	return -1, -1, nil, "", false
}

func joinLines(lines []string, nl string, trailingNL bool) []byte {
	var b strings.Builder
	for i, ln := range lines {
		b.WriteString(ln)
		if i < len(lines)-1 || trailingNL {
			b.WriteString(nl)
		}
	}
	return []byte(b.String())
}

func (m gemManager) Wire(opts WireOpts) error {
	path, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	source, _, err := rubygemsSourceURL(opts, true)
	if err != nil {
		return err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := checkSentinelIntegrity("gem", path, data, hashMarker); err != nil {
		return err
	}
	if xdg := gemXDGConfigPath(); len(data) == 0 && !fileExists(path) && fileExists(xdg) {
		return refuse(`your gem settings live in %s, and %s does not exist.

RubyGems 3.0 (the macOS system Ruby) reads only ~/.gemrc, so a source added
to %s is ignored there; and creating ~/.gemrc would make newer RubyGems stop
reading %s. Move it (mv %s %s), then re-run install-hook gem`, xdg, path, xdg, xdg, xdg, path)
	}
	rec := readOwned(path)
	nl := detectNewline(data)
	lines, trailingNL := splitLines(data)
	bs, be, hasBlock := findSentinelLines(lines)
	if !hasBlock {
		bs, be = -1, -1
	}

	// A source the user listed in hook_trusted_sources stays in :sources:
	// beside chainsaw's (R2-S10: a private gem server plus rubygems.org had
	// no way through). Status still reports it: gem resolves from every
	// source, so it can serve any gem name without chainsaw.
	var kept []string
	if _, _, items, _, found := gemSourcesRegion(lines, bs, be); found {
		for _, it := range items {
			if !rec.owns("sources", it) && !gemDefaultSources[it] && isTrustedSource(opts, it) {
				kept = append(kept, it)
			}
		}
	} else if hasBlock {
		// Re-wire: the trusted sources sit in our block already.
		_, _, items, _, _ := gemSourcesRegion(lines, -1, -1)
		for _, it := range items {
			if !rec.owns("sources", it) && isTrustedSource(opts, it) {
				kept = append(kept, it)
			}
		}
	}
	var body strings.Builder
	body.WriteString(credentialHeaderNote("the :sources: URL below", opts))
	body.WriteString(":sources:\n- " + fmt.Sprintf("%q", source) + "\n")
	for _, k := range kept {
		body.WriteString("- " + fmt.Sprintf("%q", k) + "\n")
		opts.notify("gem: %s is in hook_trusted_sources, so it stays in :sources:; doctor --strict still reports it, because gem resolves from every source", redact.URL(k))
	}
	block := strings.Split(strings.TrimRight(string(buildBlock(body.String())), "\n"), "\n")

	original := rec.Original
	var result []byte
	if st, e, items, inline, found := gemSourcesRegion(lines, bs, be); found {
		// A user (or gem-rewritten) :sources: key. Replace it IN PLACE with
		// our block, so Unwire can put the original back exactly there.
		if hasBlock {
			return refuse("%s has two :sources: keys (chainsaw's block and another); remove one by hand, then re-run install-hook gem", path)
		}
		if inline != "" && inline != "[]" {
			return gemSourcesConflict(path, inline)
		}
		var remaining []string
		for _, it := range items {
			if !rec.owns("sources", it) {
				remaining = append(remaining, it)
			}
		}
		for _, r := range remaining {
			if !gemDefaultSources[r] && !isTrustedSource(opts, r) {
				return gemSourcesConflict(path, strings.Join(remaining, ", "))
			}
		}
		if len(remaining) > 0 && len(original) == 0 {
			original = append([]string(nil), lines[st:e+1]...)
		}
		out := append(append(append([]string{}, lines[:st]...), block...), lines[e+1:]...)
		result = joinLines(out, nl, trailingNL)
	} else if hasBlock {
		// Re-wire: refresh our block where it already sits.
		out := append(append(append([]string{}, lines[:bs]...), block...), lines[be+1:]...)
		result = joinLines(out, nl, trailingNL)
	} else {
		result = replaceOrAppend(data, []byte(strings.Join(block, "\n")+"\n"))
	}

	// Never write a gemrc gem cannot load, or one whose sources are not
	// exactly ours.
	var doc map[string]any
	if err := yaml.Unmarshal(result, &doc); err != nil {
		return fmt.Errorf("%s: the result would not be valid YAML (%v); chainsaw did not write it", path, err)
	}
	if got, _ := doc[":sources"].([]any); len(got) != 1+len(kept) || got[0] != source {
		return fmt.Errorf("%s: :sources: would not be exactly the chainsaw source (and the trusted ones) after the edit; chainsaw did not write it", path)
	}

	if len(data) > 0 {
		if err := backupAndNotify(path, opts); err != nil {
			return err
		}
	}
	if err := writeConfigFile(path, result, opts); err != nil {
		return err
	}
	if strings.TrimSpace(opts.Credentials) != "" {
		// RubyGems 3.0's `gem sources` lists the source URL verbatim.
		opts.notify("gem: `gem sources` (and `gem env`) print the source URL with the client secret in it; do not paste their output into tickets or chat")
	}
	return writeOwned(path, ownedRecord{Entries: map[string]string{"sources": valueHash(source)}, Original: original})
}

func gemSourcesConflict(path, what string) error {
	return refuse(`%s sets :sources: to %s.

chainsaw replaces only RubyGems' default source (https://rubygems.org/). Any
other source is a choice you made, and adding chainsaw beside it would leave
gem resolving from both. Remove it (gem sources --remove <url>), or list it
in hook_trusted_sources to keep it beside chainsaw; then re-run
install-hook gem`, path, what)
}

func (m gemManager) Unwire(scope Scope) error {
	if scope != ScopeUser && scope != "" {
		return ErrNotWired
	}
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	rec := readOwned(path)
	nl := detectNewline(data)
	lines, trailingNL := splitLines(data)
	var out []string
	removed := false
	if bs, be, ok := findSentinelLines(lines); ok {
		removed = true
		if len(rec.Original) > 0 {
			out = append(append(append([]string{}, lines[:bs]...), rec.Original...), lines[be+1:]...)
		} else {
			stripped, _ := removeSentinel(data)
			out, trailingNL = splitLines(stripped)
		}
	} else if s, e, items, _, found := gemSourcesRegion(lines, -1, -1); found {
		// gem rewrote the file: our markers are gone, our source may remain.
		var remaining []string
		for _, it := range items {
			if rec.owns("sources", it) {
				removed = true
				continue
			}
			remaining = append(remaining, it)
		}
		if removed {
			out = append(out, lines[:s]...)
			switch {
			case len(remaining) > 0:
				out = append(out, ":sources:")
				for _, r := range remaining {
					out = append(out, "- "+r)
				}
			case len(rec.Original) > 0:
				out = append(out, rec.Original...)
			}
			out = append(out, lines[e+1:]...)
		}
	}
	if !removed {
		return ErrNotWired
	}
	if _, err := backup(path); err != nil {
		return fmt.Errorf("backup: %w", err)
	}
	if err := writeAtomic(path, joinLines(out, nl, trailingNL)); err != nil {
		return err
	}
	return removeOwned(path)
}

func (m gemManager) Status() (Status, error) {
	path, err := m.ConfigPath()
	if err != nil {
		return Status{}, err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return Status{ConfigPath: path, Installed: m.IsInstalled()}, err
	}
	rec := readOwned(path)
	wired := false
	lines, _ := splitLines(data)
	bypassed := ""
	if _, _, items, _, found := gemSourcesRegion(lines, -1, -1); found && len(items) > 0 {
		// gem resolves from EVERY listed source, so ours must be the only one
		// (`gem sources --add X` after wiring leaves both).
		ours, other := false, ""
		for _, it := range items {
			if rec.owns("sources", it) {
				ours = true
			} else {
				other = it
			}
		}
		wired = ours && other == ""
		if ours && other != "" {
			bypassed = path + " also lists " + other + " in :sources:, and gem resolves from every source"
		}
	}
	// A $GEMRC file that sets :sources: is merged over ~/.gemrc and wins.
	if p, _, found := GemSources(); wired && found && p != path {
		wired, bypassed = false, "$GEMRC names "+p+", whose :sources: override "+path
	}
	return Status{ConfigPath: path, Wired: wired, Installed: m.IsInstalled(), Bypassed: bypassed}, nil
}
