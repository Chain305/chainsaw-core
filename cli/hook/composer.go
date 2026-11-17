package hook

// composerManager wires Composer's GLOBAL config: $COMPOSER_HOME/config.json
// gets a "chainsaw" composer repository and "packagist.org": false, and
// $COMPOSER_HOME/auth.json gets the http-basic credential for the proxy host.
// Composer merges global repositories into every project, so no
// composer.json is touched — and project scope is refused outright, because
// composer.json is committed.
//
// Both files are strict JSON with no comment syntax, so there is no sentinel.
// The choice between docker's two options — refuse any existing file, or
// merge — goes to a STRUCTURED, ORDER-PRESERVING merge:
//
//   - Refusing would make the wirer useless for most users: config.json
//     exists as soon as anyone has run `composer config -g` once, and auth.json
//     as soon as they have a GitHub token.
//   - The merge never rewrites a value it did not write. Each top-level and
//     repository entry is kept as the exact bytes it was (json.RawMessage) in
//     its original order, and only the whitespace is re-indented. Order is
//     not cosmetic in `repositories`: it is the priority Composer queries
//     them in, so chainsaw's repository is APPENDED after the user's own,
//     the slot packagist.org normally occupies, and a private package keeps
//     resolving from the private repository instead of a public namesake.
//   - What chainsaw wrote is recorded out of band (owned.go). Unwire removes
//     the repository only while it still carries the recorded URL,
//     "packagist.org": false only if chainsaw set it, and the http-basic
//     entry only while it still holds the recorded credential.
//
// Anything it cannot reason about is refused with the file named: invalid
// JSON, a "chainsaw" repository or http-basic entry chainsaw did not write, a
// packagist.org override that is not `false` (a mirror the user chose), or a
// repository that would resolve packages around chainsaw (composerRepoBypass).
// `repositories` may be the keyed object or the list Composer 2.10 writes;
// either is edited in place, in its own form.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/chain305/chainsaw-core/redact"
)

type composerManager struct{}

func (composerManager) Name() string { return "composer" }

func (composerManager) IsInstalled() bool {
	_, err := exec.LookPath("composer")
	return err == nil
}

func (m composerManager) ConfigPath() (string, error) { return m.ConfigPathForScope(ScopeUser) }

func (composerManager) ConfigPathForScope(scope Scope) (string, error) {
	if scope != ScopeUser && scope != "" {
		return "", fmt.Errorf("composer: only --scope user is supported; a project's composer.json is committed, so chainsaw writes the global $COMPOSER_HOME/config.json, which Composer merges into every project")
	}
	home, err := composerHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "config.json"), nil
}

// extraPaths: auth.json carries the secret, so its backups count too.
func (composerManager) extraPaths(scope Scope) ([]string, error) {
	if scope != ScopeUser && scope != "" {
		return nil, nil
	}
	home, err := composerHome()
	if err != nil {
		return nil, err
	}
	return []string{filepath.Join(home, "auth.json")}, nil
}

// composerEtcXDG is the directory whose existence makes Composer use XDG
// paths even with no XDG_* variable set. A variable so tests can move it.
var composerEtcXDG = "/etc/xdg"

// composerHome mirrors Composer\Factory::getHomeDir:
//
//  1. $COMPOSER_HOME.
//  2. Windows: %APPDATA%/Composer.
//  3. Otherwise, when Composer "uses XDG" (any environment variable whose
//     name starts with XDG_, or /etc/xdg exists), $XDG_CONFIG_HOME/composer
//     (default ~/.config/composer) is a candidate; ~/.composer always is.
//     The first candidate that exists as a directory wins; if none does, the
//     first candidate. So a typical macOS host (no XDG_* vars, no /etc/xdg)
//     gets ~/.composer, and a Linux desktop gets ~/.config/composer.
func composerHome() (string, error) {
	if h := os.Getenv("COMPOSER_HOME"); h != "" {
		return h, nil
	}
	if runtime.GOOS == "windows" {
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return "", fmt.Errorf("the APPDATA or COMPOSER_HOME environment variable must be set for composer")
		}
		return filepath.Join(appdata, "Composer"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	var dirs []string
	if composerUsesXDG() {
		xdg := os.Getenv("XDG_CONFIG_HOME")
		if xdg == "" {
			xdg = filepath.Join(home, ".config")
		}
		dirs = append(dirs, filepath.Join(xdg, "composer"))
	}
	dirs = append(dirs, filepath.Join(home, ".composer"))
	for _, d := range dirs {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			return d, nil
		}
	}
	return dirs[0], nil
}

func composerUsesXDG() bool {
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "XDG_") {
			return true
		}
	}
	fi, err := os.Stat(composerEtcXDG)
	return err == nil && fi.IsDir()
}

// ── order-preserving JSON object ─────────────────────────────────────────────

type jsonField struct {
	Key string
	Val json.RawMessage
}

type jsonObject []jsonField

// parseJSONObject decodes a JSON object, keeping every member's bytes and
// order. Empty input is an empty object.
func parseJSONObject(data []byte) (jsonObject, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return jsonObject{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, fmt.Errorf("top level is not a JSON object")
	}
	var obj jsonObject
	seen := map[string]bool{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		if seen[key] {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		obj = append(obj, jsonField{key, raw})
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("trailing data after the JSON object")
	}
	return obj, nil
}

func (o jsonObject) get(key string) (json.RawMessage, bool) {
	for _, f := range o {
		if f.Key == key {
			return f.Val, true
		}
	}
	return nil, false
}

func (o *jsonObject) set(key string, val json.RawMessage) {
	for i, f := range *o {
		if f.Key == key {
			(*o)[i].Val = val
			return
		}
	}
	*o = append(*o, jsonField{key, val})
}

func (o *jsonObject) del(key string) bool {
	for i, f := range *o {
		if f.Key == key {
			*o = append((*o)[:i], (*o)[i+1:]...)
			return true
		}
	}
	return false
}

func (o jsonObject) raw() json.RawMessage {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, f := range o {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(f.Key)
		b.Write(k)
		b.WriteByte(':')
		b.Write(f.Val)
	}
	b.WriteByte('}')
	return b.Bytes()
}

// document renders the object the way Composer writes its own files: four
// spaces, trailing newline.
func (o jsonObject) document() ([]byte, error) {
	var out bytes.Buffer
	if err := json.Indent(&out, o.raw(), "", "    "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

func mustJSON(v any) json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(b.Bytes(), "\n")
}

// ── wire / unwire / status ───────────────────────────────────────────────────

const (
	composerRepoKey      = "chainsaw"
	composerOwnedRepo    = "repositories.chainsaw"
	composerFlagPackagis = "packagist_disabled_by_chainsaw"
)

// composerTarget is what a wire with these options writes.
type composerTarget struct {
	repoURL  string
	authHost string // host[:port] — Composer keys http-basic on the origin
	user     string
	pass     string
}

func composerTargetFor(opts WireOpts) (composerTarget, error) {
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return composerTarget{}, fmt.Errorf("a server URL is required: run `chainsaw auth login` or pass --server, then re-run install-hook composer")
	}
	base, err := validateServerURL(server)
	if err != nil {
		return composerTarget{}, err
	}
	repo, err := orgScopedRepoPath(opts.OrgSlug, "packagist")
	if err != nil {
		return composerTarget{}, err
	}
	u, err := url.Parse(base)
	if err != nil {
		return composerTarget{}, fmt.Errorf("invalid server URL: %w", err)
	}
	t := composerTarget{repoURL: base + "/" + repo + "/", authHost: u.Host}
	if creds := strings.TrimSpace(opts.Credentials); creds != "" {
		if t.user, t.pass, err = parseCreds(creds); err != nil {
			return composerTarget{}, err
		}
	}
	return t, nil
}

func readJSONObjectFile(path string) (jsonObject, []byte, error) {
	data, err := readOrEmpty(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}
	obj, err := parseJSONObject(data)
	if err != nil {
		return nil, nil, fmt.Errorf("%s is not a JSON object chainsaw can edit safely (%v); fix it by hand or move it aside, then re-run install-hook composer", path, err)
	}
	return obj, data, nil
}

func repoURLOf(raw json.RawMessage) string {
	var r struct {
		URL string `json:"url"`
	}
	_ = json.Unmarshal(raw, &r)
	return r.URL
}

// ComposerRepo is one entry of a Composer "repositories" value.
type ComposerRepo struct {
	Name     string // map key, or the "name" member (Composer 2.x list form); "" when anonymous
	Type     string
	URL      string
	Disabled bool // {"<name>": false}
	Raw      json.RawMessage
}

// ComposerRepos parses "repositories" in either form Composer accepts: the
// keyed object (`composer config -g repositories.x` on Composer 1/early 2) or
// the list Composer 2.10 writes and prepends to, whose entries are
// {"name": …, "type": …, "url": …} or {"packagist.org": false}. Order is
// kept: it is the order Composer queries them in.
func ComposerRepos(raw json.RawMessage) ([]ComposerRepo, bool, error) {
	one := func(name string, v json.RawMessage) ComposerRepo {
		r := ComposerRepo{Name: name, Raw: v}
		if string(bytes.TrimSpace(v)) == "false" {
			r.Disabled = true
			return r
		}
		var body struct{ Name, Type, URL string }
		_ = json.Unmarshal(v, &body)
		if r.Name == "" {
			r.Name = body.Name
		}
		r.Type, r.URL = body.Type, body.URL
		return r
	}
	if obj, err := parseJSONObject(raw); err == nil {
		out := make([]ComposerRepo, 0, len(obj))
		for _, f := range obj {
			out = append(out, one(f.Key, f.Val))
		}
		return out, false, nil
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, false, err
	}
	var out []ComposerRepo
	for _, e := range list {
		// {"packagist.org": false} is a one-member object keyed by the name.
		if obj, err := parseJSONObject(e); err == nil && len(obj) == 1 && string(bytes.TrimSpace(obj[0].Val)) == "false" {
			out = append(out, one(obj[0].Key, obj[0].Val))
			continue
		}
		out = append(out, one("", e))
	}
	return out, true, nil
}

// composerMirrorHosts are Packagist mirrors whose host does not say
// "packagist" (https://packagist.org/mirrors).
var composerMirrorHosts = map[string]bool{
	"mirrors.aliyun.com":        true,
	"mirrors.cloud.tencent.com": true,
	"mirrors.tencent.com":       true,
	"mirrors.huaweicloud.com":   true,
	"repo.huaweicloud.com":      true,
}

// IsPackagistMirror reports whether a composer repository URL serves the
// public Packagist catalogue: packagist.org itself (repo.packagist.org),
// Private Packagist (*.packagist.com, which mirrors Packagist by default),
// a regional mirror (any host naming "packagist": packagist.jp, packagist.kr,
// packagist.phpcomposer.com, …) or one of composerMirrorHosts. A repository
// like that anywhere in the list resolves public packages around chainsaw:
// ahead of it Composer asks it first, and behind it Composer falls through
// to it for any package chainsaw refuses outright.
//
// ponytail: host heuristic. A corporate Artifactory/Nexus proxy of Packagist
// on an unrelated host is invisible to it; doctor --strict flags any
// non-chainsaw composer repository in a project instead.
func IsPackagistMirror(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	h := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	return strings.Contains(h, "packagist") || composerMirrorHosts[h]
}

// composerRepoHasOnly reports a repository restricted to named packages with
// a non-empty "only" list: Composer asks it for nothing else, so it cannot
// serve a public package around chainsaw.
func composerRepoHasOnly(raw json.RawMessage) bool {
	var r struct {
		Only []string `json:"only"`
	}
	return json.Unmarshal(raw, &r) == nil && len(r.Only) > 0
}

// composerRepoBypass says why repository r resolves packages around
// chainsaw's repository, or "". ahead is true when Composer asks r first.
//
// Composer repositories are canonical by default: the first one that has a
// package is the only one asked for it. So a composer-type repository ahead
// of chainsaw answers for every package it serves, public names included,
// and a Packagist mirror anywhere serves the public catalogue (behind
// chainsaw, for any package chainsaw refuses). vcs, path, artifact and
// package repositories serve the packages they declare. A repository with an
// "only" list is limited to those names (R2-S10: Private Packagist with
// mirroring off is set up that way).
func composerRepoBypass(r ComposerRepo, ahead bool) string {
	if r.Disabled || r.Name == composerRepoKey || composerRepoHasOnly(r.Raw) {
		return ""
	}
	name := r.Name
	if name == "" {
		name = "(unnamed)"
	}
	switch {
	case IsPackagistMirror(r.URL):
		return fmt.Sprintf("repository %q (%s) serves the public Packagist catalogue around chainsaw", name, r.URL)
	case ahead && r.Type == "composer":
		return fmt.Sprintf(`repository %q (%s) is asked before chainsaw for every package it serves; give it an "only" list of the packages it is for`, name, r.URL)
	}
	return ""
}

// composerRepoSet is a "repositories" value in either form, order kept.
// entries[i].Key is the map key in the keyed form and "" in the list form.
type composerRepoSet struct {
	list    bool
	entries []jsonField
}

func parseComposerRepoSet(raw json.RawMessage) (composerRepoSet, error) {
	if obj, err := parseJSONObject(raw); err == nil {
		return composerRepoSet{entries: obj}, nil
	}
	var list []json.RawMessage
	if err := json.Unmarshal(raw, &list); err != nil {
		return composerRepoSet{}, err
	}
	s := composerRepoSet{list: true}
	for _, e := range list {
		s.entries = append(s.entries, jsonField{Val: e})
	}
	return s, nil
}

func (s composerRepoSet) raw() json.RawMessage {
	if !s.list {
		return jsonObject(s.entries).raw()
	}
	var b bytes.Buffer
	b.WriteByte('[')
	for i, e := range s.entries {
		if i > 0 {
			b.WriteByte(',')
		}
		b.Write(e.Val)
	}
	b.WriteByte(']')
	return b.Bytes()
}

// repos parses the entries; one ComposerRepo per entry, same order.
func (s composerRepoSet) repos() []ComposerRepo {
	out, _, _ := ComposerRepos(s.raw())
	return out
}

func (s composerRepoSet) index(name string) int {
	for i, r := range s.repos() {
		if r.Name == name {
			return i
		}
	}
	return -1
}

// set replaces the named entry in place, or appends it.
func (s *composerRepoSet) set(name string, body map[string]string) {
	var val json.RawMessage
	if s.list {
		withName := map[string]string{"name": name}
		for k, v := range body {
			withName[k] = v
		}
		val = mustJSON(withName)
	} else {
		val = mustJSON(body)
	}
	s.put(name, val)
}

// disable sets {"<name>": false} in place, or appends it.
func (s *composerRepoSet) disable(name string) {
	val := json.RawMessage("false")
	if s.list {
		val = mustJSON(map[string]bool{name: false})
	}
	s.put(name, val)
}

func (s *composerRepoSet) put(name string, val json.RawMessage) {
	if i := s.index(name); i >= 0 {
		s.entries[i].Val = val
		return
	}
	key := name
	if s.list {
		key = ""
	}
	s.entries = append(s.entries, jsonField{key, val})
}

func (s *composerRepoSet) del(name string) bool {
	if i := s.index(name); i >= 0 {
		s.entries = append(s.entries[:i], s.entries[i+1:]...)
		return true
	}
	return false
}

// isTrustedSource reports whether url is one of opts.TrustedSources, credentials
// and a trailing slash ignored.
func isTrustedSource(opts WireOpts, url string) bool {
	m := registryMatcher(url)
	for _, t := range opts.TrustedSources {
		if m != nil && m(t) {
			return true
		}
	}
	return false
}

func composerMirrorError(path string, r ComposerRepo) error {
	name := r.Name
	if name == "" {
		name = "(unnamed)"
	}
	return refuse(`%s has a repository %s at %s, which serves the public Packagist catalogue.

Composer would resolve public packages from it around chainsaw (it asks
repositories in order, and falls through to later ones for a package chainsaw
refuses). Remove it (composer config -g --unset repositories.%s), then re-run
install-hook composer`, path, name, r.URL, name)
}

func (m composerManager) Wire(opts WireOpts) error {
	cfgPath, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	authPath := filepath.Join(filepath.Dir(cfgPath), "auth.json")
	t, err := composerTargetFor(opts)
	if err != nil {
		return err
	}

	// Plan both files completely before writing either.
	cfg, cfgData, err := readJSONObjectFile(cfgPath)
	if err != nil {
		return err
	}
	rec := readOwned(cfgPath)
	repos := composerRepoSet{}
	if raw, ok := cfg.get("repositories"); ok {
		if repos, err = parseComposerRepoSet(raw); err != nil {
			return refuse(`%s has a "repositories" value that is neither an object nor a list (%v); fix it by hand, then re-run install-hook composer`, cfgPath, err)
		}
	}
	all := repos.repos()
	ci := repos.index(composerRepoKey)
	if ci >= 0 && !rec.owns(composerOwnedRepo, all[ci].URL) {
		return refuse(`%s already has a "chainsaw" repository that chainsaw did not write. Remove it (composer config -g --unset repositories.chainsaw), then re-run install-hook composer`, cfgPath)
	}
	pi := repos.index("packagist.org")
	if pi >= 0 && !all[pi].Disabled {
		return refuse(`%s overrides "packagist.org" with a repository of its own. chainsaw disables Packagist so resolution cannot escape the proxy, and will not replace a mirror you chose; point that mirror at chainsaw or remove it, then re-run install-hook composer`, cfgPath)
	}
	// chainsaw keeps its slot on a re-wire and is appended on a first one,
	// so everything before that slot is asked first.
	slot := ci
	if slot < 0 {
		slot = len(all)
	}
	for i, r := range all {
		if i == pi {
			continue
		}
		why := composerRepoBypass(r, i < slot)
		switch {
		case why == "":
		case isTrustedSource(opts, r.URL):
			opts.notify("composer: %s is in hook_trusted_sources, so it was left in place; doctor --strict still reports it, because %s", redact.URL(r.URL), redact.Text(why))
		case IsPackagistMirror(r.URL):
			return composerMirrorError(cfgPath, r)
		default:
			return refuse(`%s: %s.

Composer would install those packages from it without asking chainsaw. Add
"only": [...] naming the packages it is for, remove it, or list its URL in
hook_trusted_sources to wire anyway; then re-run install-hook composer`, cfgPath, why)
		}
	}
	disabledByUs := rec.Flags[composerFlagPackagis] || pi < 0
	repos.set(composerRepoKey, map[string]string{"type": "composer", "url": t.repoURL})
	repos.disable("packagist.org")
	cfg.set("repositories", repos.raw())

	var auth jsonObject
	var authData []byte
	authRec := readOwned(authPath)
	hostKey := "http-basic." + t.authHost
	if t.user != "" || len(authRec.Entries) > 0 {
		if auth, authData, err = readJSONObjectFile(authPath); err != nil {
			return err
		}
		basic := jsonObject{}
		if raw, ok := auth.get("http-basic"); ok {
			if basic, err = parseJSONObject(raw); err != nil {
				return fmt.Errorf("%s: \"http-basic\" is not an object (%v)", authPath, err)
			}
		}
		// Drop entries we wrote earlier (a re-wire, or a moved server).
		for k := range authRec.Entries {
			host := strings.TrimPrefix(k, "http-basic.")
			if raw, ok := basic.get(host); ok && authRec.owns(k, canonicalJSON(raw)) {
				basic.del(host)
			}
		}
		if t.user != "" {
			if _, ok := basic.get(t.authHost); ok {
				return refuse(`%s already has http-basic credentials for %s that chainsaw did not write. Remove them (composer config -g --unset http-basic.%s), then re-run install-hook composer`, authPath, t.authHost, t.authHost)
			}
			basic.set(t.authHost, mustJSON(map[string]string{"username": t.user, "password": t.pass}))
		}
		if len(basic) == 0 {
			auth.del("http-basic")
		} else {
			auth.set("http-basic", basic.raw())
		}
	}

	cfgOut, err := cfg.document()
	if err != nil {
		return fmt.Errorf("render %s: %w", cfgPath, err)
	}
	if len(cfgData) > 0 {
		if err := backupAndNotify(cfgPath, opts); err != nil {
			return err
		}
	}
	if err := writeConfigFile(cfgPath, cfgOut, opts); err != nil {
		return err
	}
	nextRec := ownedRecord{Entries: map[string]string{composerOwnedRepo: valueHash(t.repoURL)}, Flags: map[string]bool{composerFlagPackagis: disabledByUs}}
	if err := writeOwned(cfgPath, nextRec); err != nil {
		return err
	}
	if auth == nil {
		return nil
	}
	authOut, err := auth.document()
	if err != nil {
		return fmt.Errorf("render %s: %w", authPath, err)
	}
	if len(authData) > 0 {
		if err := backupAndNotify(authPath, opts); err != nil {
			return err
		}
	}
	if err := writeConfigFile(authPath, authOut, opts); err != nil {
		return err
	}
	if t.user == "" {
		return removeOwned(authPath)
	}
	entry, _ := json.Marshal(map[string]string{"username": t.user, "password": t.pass})
	opts.notify("composer: %s holds the client secret in cleartext (JSON has no comments to say so in the file); chainsaw restricts it to your user account", authPath)
	return writeOwned(authPath, ownedRecord{Entries: map[string]string{hostKey: valueHash(canonicalJSON(entry))}})
}

// canonicalJSON re-encodes a JSON value with sorted keys and no whitespace,
// so an ownership hash survives Composer re-indenting auth.json.
func canonicalJSON(raw []byte) string {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	return string(mustJSON(v))
}

func (m composerManager) Unwire(scope Scope) error {
	if scope != ScopeUser && scope != "" {
		return ErrNotWired
	}
	cfgPath, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	authPath := filepath.Join(filepath.Dir(cfgPath), "auth.json")
	removed := false

	cfg, cfgData, err := readJSONObjectFile(cfgPath)
	if err != nil {
		return err
	}
	rec := readOwned(cfgPath)
	if raw, ok := cfg.get("repositories"); ok {
		if repos, perr := parseComposerRepoSet(raw); perr == nil {
			all := repos.repos()
			if ci := repos.index(composerRepoKey); ci >= 0 && rec.owns(composerOwnedRepo, all[ci].URL) {
				repos.del(composerRepoKey)
				removed = true
				if pi := repos.index("packagist.org"); pi >= 0 && rec.Flags[composerFlagPackagis] && repos.repos()[pi].Disabled {
					repos.del("packagist.org")
				}
				if len(repos.entries) == 0 {
					cfg.del("repositories")
				} else {
					cfg.set("repositories", repos.raw())
				}
			}
		}
	}

	auth, authData, aerr := readJSONObjectFile(authPath)
	authRec := readOwned(authPath)
	authChanged := false
	if aerr == nil {
		if raw, ok := auth.get("http-basic"); ok {
			if basic, perr := parseJSONObject(raw); perr == nil {
				for k := range authRec.Entries {
					host := strings.TrimPrefix(k, "http-basic.")
					if v, ok := basic.get(host); ok && authRec.owns(k, canonicalJSON(v)) {
						basic.del(host)
						authChanged = true
					}
				}
				if len(basic) == 0 {
					auth.del("http-basic")
				} else {
					auth.set("http-basic", basic.raw())
				}
			}
		}
	}
	if !removed && !authChanged {
		return ErrNotWired
	}
	if removed {
		out, err := cfg.document()
		if err != nil {
			return err
		}
		if len(cfgData) > 0 {
			if _, err := backup(cfgPath); err != nil {
				return fmt.Errorf("backup: %w", err)
			}
		}
		if err := writeAtomic(cfgPath, out); err != nil {
			return err
		}
		if err := removeOwned(cfgPath); err != nil {
			return err
		}
	}
	if authChanged {
		out, err := auth.document()
		if err != nil {
			return err
		}
		if len(authData) > 0 {
			if _, err := backup(authPath); err != nil {
				return fmt.Errorf("backup: %w", err)
			}
		}
		if err := writeAtomic(authPath, out); err != nil {
			return err
		}
		if err := removeOwned(authPath); err != nil {
			return err
		}
	}
	return nil
}

func (m composerManager) Status() (Status, error) {
	path, err := m.ConfigPath()
	if err != nil {
		return Status{}, err
	}
	st := Status{ConfigPath: path, Installed: m.IsInstalled()}
	cfg, _, err := readJSONObjectFile(path)
	if err != nil {
		return st, nil
	}
	rec := readOwned(path)
	raw, ok := cfg.get("repositories")
	if !ok {
		return st, nil
	}
	repos, _, err := ComposerRepos(raw)
	if err != nil {
		return st, nil
	}
	// Wired only while all three hold: our repository, Packagist off, and no
	// other repository serving the Packagist catalogue. Either form counts:
	// Composer 2.10 rewrites our keyed object as a list on the user's next
	// `composer config -g repositories.x`, prepending x.
	ours, packagistOff := false, false
	for _, r := range repos {
		switch {
		case r.Name == composerRepoKey:
			ours = ours || rec.owns(composerOwnedRepo, r.URL)
		case r.Name == "packagist.org" || r.Name == "packagist":
			packagistOff = packagistOff || r.Disabled
		}
		if why := composerRepoBypass(r, !ours); why != "" && st.Bypassed == "" {
			st.Bypassed = why
		}
	}
	st.Wired = ours && packagistOff && st.Bypassed == ""
	if !ours {
		st.Bypassed = ""
	}
	return st, nil
}
