package hook

import (
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/chain305/chainsaw-core/redact"
)

// uvManager edits uv's own uv.toml.
//
// uv does NOT read pip.conf, PIP_INDEX_URL or PIP_CONFIG_FILE, so a machine
// where `install-hook pip` succeeded still sends every `uv add`, `uv sync` and
// `uv pip install` straight to pypi.org. This manager closes that gap by
// writing a default [[index]] into the file uv itself reads:
//
//	https://docs.astral.sh/uv/concepts/configuration-files/
//	https://docs.astral.sh/uv/concepts/indexes/
type uvManager struct{}

func (uvManager) Name() string { return "uv" }

func (uvManager) IsInstalled() bool {
	_, err := exec.LookPath("uv")
	return err == nil
}

func (m uvManager) ConfigPath() (string, error) {
	return m.ConfigPathForScope(ScopeUser)
}

// ConfigPathForScope follows uv's discovery rules:
//
//   - user: $UV_CONFIG_FILE when set (uv then reads that file INSTEAD of
//     discovering any other), else %APPDATA%\uv\uv.toml on Windows, else
//     $XDG_CONFIG_HOME/uv/uv.toml or ~/.config/uv/uv.toml — on macOS too; uv
//     does not use ~/Library/Application Support.
//   - project: ./uv.toml (uv walks up from cwd to the nearest uv.toml or
//     pyproject.toml).
//   - system: /etc/uv/uv.toml, or %ProgramData%\uv\uv.toml on Windows.
func (uvManager) ConfigPathForScope(scope Scope) (string, error) {
	switch scope {
	case ScopeProject:
		cwd, err := os.Getwd()
		if err != nil || cwd == "" {
			return "", fmt.Errorf("resolve working dir: %w", err)
		}
		return filepath.Join(cwd, "uv.toml"), nil
	case ScopeSystem:
		if runtime.GOOS == "windows" {
			pd := os.Getenv("ProgramData")
			if pd == "" {
				return "", fmt.Errorf("ProgramData not set")
			}
			return filepath.Join(pd, "uv", "uv.toml"), nil
		}
		return "/etc/uv/uv.toml", nil
	}
	if p := strings.TrimSpace(os.Getenv("UV_CONFIG_FILE")); p != "" {
		return p, nil
	}
	if runtime.GOOS == "windows" {
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			return "", fmt.Errorf("APPDATA not set")
		}
		return filepath.Join(appdata, "uv", "uv.toml"), nil
	}
	if xdg := strings.TrimSpace(os.Getenv("XDG_CONFIG_HOME")); xdg != "" {
		return filepath.Join(xdg, "uv", "uv.toml"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return "", fmt.Errorf("resolve home dir: %w", err)
	}
	return filepath.Join(home, ".config", "uv", "uv.toml"), nil
}

func (m uvManager) Wire(opts WireOpts) error {
	path, err := m.ConfigPathForScope(opts.Scope)
	if err != nil {
		return err
	}
	body, err := uvBlockBody(opts)
	if err != nil {
		return err
	}
	data, err := readOrEmpty(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	if err := checkSentinelIntegrity("uv", path, data, hashMarker); err != nil {
		return err
	}
	if opts.Scope == ScopeProject && len(data) == 0 {
		if err := uvRefuseShadowedPyproject(filepath.Dir(path)); err != nil {
			return err
		}
	}
	stripped, _ := removeSentinel(data)
	if err := uvForeignIndexConflict(path, stripped, registryMatcher(uvTargetURL(opts))); err != nil {
		return err
	}
	out := replaceOrAppend(data, buildBlock(body))
	// Belt and braces: never write a uv.toml uv cannot load. TOML forbids
	// mixing an inline `index = [...]` with our [[index]] table, among
	// other things the line checks above do not model.
	var probe map[string]any
	if _, err := toml.Decode(string(out), &probe); err != nil {
		return fmt.Errorf("%s: adding chainsaw's [[index]] would leave a file uv cannot parse (%v); chainsaw did not write it", path, err)
	}
	if len(data) > 0 {
		if err := backupAndNotify(path, opts); err != nil {
			return err
		}
	}
	if err := writeConfigFile(path, out, opts); err != nil {
		return err
	}
	opts.notify("uv: a project's own [[tool.uv.index]] with default = true (or a project uv.toml) overrides %s, and uv.lock records the index URL it resolved from", path)
	return nil
}

// uvRefuseShadowedPyproject stops a project-scope wire from creating
// ./uv.toml next to a pyproject.toml that carries [tool.uv]. uv reads uv.toml
// INSTEAD of [tool.uv] when both exist in a directory, so creating the file
// would silently switch off every project setting the user already has.
func uvRefuseShadowedPyproject(dir string) error {
	py := filepath.Join(dir, "pyproject.toml")
	data, err := readOrEmpty(py)
	if err != nil || len(data) == 0 {
		return nil
	}
	var doc map[string]any
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return nil
	}
	tool, _ := doc["tool"].(map[string]any)
	if _, ok := tool["uv"]; !ok {
		return nil
	}
	return fmt.Errorf(`%s has a [tool.uv] table. uv ignores [tool.uv] whenever a uv.toml
exists in the same directory, so creating %s would switch off every
project setting you already have. Add the index to pyproject.toml instead:

  [[tool.uv.index]]
  name = "chainsaw"
  url = "<chainsaw>/repository/@<org>/pypi/simple/"
  default = true`, py, filepath.Join(dir, "uv.toml"))
}

// UVForeignIndexSettings lists every setting in a parsed uv config table (a
// uv.toml document, or pyproject.toml's [tool.uv]) that sends resolution
// somewhere other than chainsaw's default index. ours reports a URL that IS
// chainsaw; nil treats every URL as foreign.
//
// uv queries every non-default index, extra-index-url and find-links location
// BEFORE the default index, and no-index drops the default altogether
// (probed with uv 0.9: a no-index + find-links config fetched only from the
// find-links host). An [[index]] with explicit = true is used only for
// packages pinned to it in [tool.uv.sources], so it is not a conflict. The
// same keys under [pip] apply to every `uv pip` command.
func UVForeignIndexSettings(doc map[string]any, ours func(string) bool) []string {
	isOurs := func(v any) bool {
		s, _ := v.(string)
		return ours != nil && s != "" && ours(s)
	}
	var found []string
	urlKeys := func(t map[string]any, where string) {
		for _, k := range []string{"index-url", "extra-index-url", "find-links"} {
			v, ok := t[k]
			if !ok {
				continue
			}
			vals, isList := v.([]any)
			if !isList {
				vals = []any{v}
			}
			for _, u := range vals {
				if !isOurs(u) {
					found = append(found, fmt.Sprintf("%s%s = %v", where, k, u))
				}
			}
		}
		if b, _ := t["no-index"].(bool); b {
			found = append(found, where+"no-index = true (uv ignores the default index)")
		}
	}
	urlKeys(doc, "")
	if pip, ok := doc["pip"].(map[string]any); ok {
		urlKeys(pip, "[pip] ")
	}
	var idx []map[string]any
	switch v := doc["index"].(type) {
	case []map[string]any:
		idx = v
	case []any:
		for _, e := range v {
			if m, ok := e.(map[string]any); ok {
				idx = append(idx, m)
			}
		}
	}
	for _, e := range idx {
		if isOurs(e["url"]) {
			continue
		}
		if d, _ := e["default"].(bool); d {
			found = append(found, fmt.Sprintf("an [[index]] named %q with default = true", e["name"]))
		} else if x, _ := e["explicit"].(bool); !x {
			found = append(found, fmt.Sprintf("an [[index]] named %q (%v) without explicit = true, which uv queries before the default", e["name"], e["url"]))
		}
	}
	return found
}

// UVPinnedForeignIndexes lists the packages a [tool.uv] table pins, through
// [tool.uv.sources] (`pkg = { index = "name" }`, or a list of those), to an
// [[tool.uv.index]] that is not chainsaw's. UVForeignIndexSettings leaves an
// explicit = true index alone because uv asks it for nothing else, but every
// package pinned to it is fetched from it alone.
func UVPinnedForeignIndexes(table map[string]any, ours func(string) bool) []string {
	urls := map[string]string{}
	idx, _ := table["index"].([]map[string]any)
	if raw, ok := table["index"].([]any); ok {
		for _, e := range raw {
			if m, ok := e.(map[string]any); ok {
				idx = append(idx, m)
			}
		}
	}
	for _, e := range idx {
		name, _ := e["name"].(string)
		u, _ := e["url"].(string)
		if name != "" && !(ours != nil && ours(u)) {
			urls[name] = u
		}
	}
	sources, _ := table["sources"].(map[string]any)
	var out []string
	for pkg, v := range sources {
		entries, ok := v.([]any)
		if !ok {
			entries = []any{v}
		}
		if mm, ok := v.([]map[string]any); ok {
			for _, m := range mm {
				entries = append(entries, m)
			}
		}
		for _, e := range entries {
			m, _ := e.(map[string]any)
			name, _ := m["index"].(string)
			if u, foreign := urls[name]; foreign {
				out = append(out, fmt.Sprintf("package %q is pinned to uv index %q (%s), which is not Chainsaw", pkg, name, u))
			}
		}
	}
	sort.Strings(out)
	return out
}

// uvForeignIndexConflict refuses when the user's own content (the file minus
// our block) sends resolution anywhere but chainsaw's default index (see
// UVForeignIndexSettings). Same posture as cargo's H6: refuse rather than
// rewrite someone else's resolution chain. ours recognises this chainsaw's
// own index, which a user may already have set by hand (R2-S10).
func uvForeignIndexConflict(path string, userContent []byte, ours func(string) bool) error {
	if len(userContent) == 0 {
		return nil
	}
	var doc map[string]any
	if _, err := toml.Decode(string(userContent), &doc); err != nil {
		return fmt.Errorf("%s is not valid TOML (%v); chainsaw will not edit a file uv cannot load either", path, err)
	}
	found := UVForeignIndexSettings(doc, ours)
	if len(found) == 0 {
		return nil
	}
	return refuse(`%s already sets %s.

uv would query that before (or instead of) chainsaw's default index. Remove
it, or for a private index that serves only some packages, mark it
explicit = true and pin those packages to it in [tool.uv.sources]; then
re-run install-hook uv`, path, strings.Join(found, "; "))
}

func (m uvManager) Unwire(scope Scope) error {
	path, err := m.ConfigPathForScope(scope)
	if err != nil {
		return err
	}
	return unwireBlock(path)
}

// Status is wired only while our block is present AND nothing the user added
// beside it since, and nothing in the system-level uv.toml, sends uv
// elsewhere first.
func (m uvManager) Status() (Status, error) {
	st, err := statusForConfig(m.ConfigPath, m.IsInstalled)
	if err != nil || !st.Wired {
		return st, err
	}
	data, rerr := readOrEmpty(st.ConfigPath)
	if rerr != nil {
		st.Wired = false
		return st, nil
	}
	ours := registryMatcher(uvBlockIndexURL(data))
	stripped, _ := removeSentinel(data)
	if cerr := uvForeignIndexConflict(st.ConfigPath, stripped, ours); cerr != nil {
		st.Wired = false
		st.Bypassed, _, _ = strings.Cut(cerr.Error(), "\n")
		return st, nil
	}
	if why := UVSystemConfigOverride(ours); why != "" {
		st.Wired, st.Bypassed = false, why
	}
	return st, nil
}

// UVSystemConfigPath is the system-level uv.toml uv reads beside the user
// one, "" when there is none: the first $XDG_CONFIG_DIRS/uv/uv.toml that
// exists (default /etc/xdg), else /etc/uv/uv.toml; on Windows
// %SYSTEMDRIVE%\ProgramData\uv\uv.toml. uv merges it UNDER the user config,
// and arrays (index, extra-index-url, find-links) are concatenated, so its
// indexes are queried too. $UV_CONFIG_FILE makes uv read that one file only.
func UVSystemConfigPath() string {
	if strings.TrimSpace(os.Getenv("UV_CONFIG_FILE")) != "" {
		return ""
	}
	var candidates []string
	if runtime.GOOS == "windows" {
		drive := os.Getenv("SYSTEMDRIVE")
		if drive == "" {
			drive = "C:"
		}
		candidates = []string{filepath.Join(drive+`\`, "ProgramData", "uv", "uv.toml")}
	} else {
		dirs := strings.TrimSpace(os.Getenv("XDG_CONFIG_DIRS"))
		if dirs == "" {
			dirs = "/etc/xdg"
		}
		for _, d := range filepath.SplitList(dirs) {
			if d != "" {
				candidates = append(candidates, filepath.Join(d, "uv", "uv.toml"))
			}
		}
		candidates = append(candidates, uvEtcConfig)
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

// uvEtcConfig is uv's last-resort system config; a variable so tests can move it.
var uvEtcConfig = "/etc/uv/uv.toml"

// UVSystemConfigOverride says why the system-level uv.toml sends resolution
// around chainsaw, or "". ours recognises chainsaw's own index.
func UVSystemConfigOverride(ours func(string) bool) string {
	path := UVSystemConfigPath()
	if path == "" {
		return ""
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var doc map[string]any
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return "system uv config " + path + " is not valid TOML, so where uv resolves from cannot be judged"
	}
	if found := UVForeignIndexSettings(doc, ours); len(found) > 0 {
		return "system uv config " + path + " sets " + redact.Text(strings.Join(found, "; "))
	}
	return ""
}

// uvTargetURL is the index URL a wire with these options writes, without
// credentials; "" when there is no usable server.
func uvTargetURL(opts WireOpts) string {
	base, err := validateServerURL(strings.TrimSpace(opts.ServerURL))
	if err != nil || strings.TrimSpace(opts.ServerURL) == "" {
		return ""
	}
	p, err := orgScopedRepoPath(opts.OrgSlug, "pypi")
	if err != nil {
		return ""
	}
	return base + "/" + p + "/simple/"
}

// uvBlockIndexURL is the url of the [[index]] named "chainsaw" in a uv.toml.
func uvBlockIndexURL(data []byte) string {
	var doc struct {
		Index []struct{ Name, URL string } `toml:"index"`
	}
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return ""
	}
	for _, e := range doc.Index {
		if e.Name == "chainsaw" {
			return e.URL
		}
	}
	return ""
}

// registryMatcher reports whether a registry URL is want, ignoring credentials, case
// of scheme and host, and a trailing slash. nil when want is "".
func registryMatcher(want string) func(string) bool {
	norm := func(raw string) string {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Host == "" {
			return ""
		}
		u.User = nil
		return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + strings.TrimSuffix(u.EscapedPath(), "/")
	}
	w := norm(want)
	if w == "" {
		return nil
	}
	return func(raw string) bool { return norm(raw) == w }
}

func (uvManager) renderBody(o WireOpts) (string, error) { return uvBlockBody(o) }
func (uvManager) blockMarker() markerClassifier         { return hashMarker }

func (m uvManager) repairTargets(scope Scope) ([]string, markerClassifier, error) {
	p, err := m.ConfigPathForScope(scope)
	return []string{p}, hashMarker, err
}

// uvBlockBody renders the [[index]] table. It is a TOML array-of-tables entry,
// never a top-level `index-url = ...`: our block is appended at end of file,
// and a bare key there would land inside whatever table the user declared
// last (e.g. [pip]) instead of at the top level.
//
// Credentials follow pip's model: userinfo in the URL, in a file
// writeConfigFile restricts to the owner. uv strips userinfo before it writes
// uv.lock, so the secret does not reach the lockfile.
func uvBlockBody(opts WireOpts) (string, error) {
	server := strings.TrimSpace(opts.ServerURL)
	if server == "" {
		return `# Uncomment and re-run ` + "`chainsaw --server <url> install-hook uv`" + ` to
# populate real proxy URLs. The chainsaw proxy mounts PyPI at
# /repository/@<org>/pypi/simple/.
# [[index]]
# name = "chainsaw"
# url = "https://<chainsaw-server>/repository/@<org>/pypi/simple/"
# default = true`, nil
	}
	base, err := validateServerURL(server)
	if err != nil {
		return "", err
	}
	pypiPath, err := orgScopedRepoPath(opts.OrgSlug, "pypi")
	if err != nil {
		return "", err
	}
	const tail = `# A project's own [[tool.uv.index]] with default = true overrides this one;
# uv.lock records the index URL packages were resolved from.`
	if creds := strings.TrimSpace(opts.Credentials); creds != "" {
		user, pass, err := parseCreds(creds)
		if err != nil {
			return "", err
		}
		scheme, rest := splitScheme(base)
		u := fmt.Sprintf("%s%s:%s@%s/%s/simple/", scheme, url.PathEscape(user), url.PathEscape(pass), rest, pypiPath)
		return fmt.Sprintf(`%s[[index]]
name = "chainsaw"
url = %s
default = true
%s`, credentialHeaderNote("the [[index]] url below", opts), strconv.Quote(u), tail), nil
	}
	return fmt.Sprintf(`[[index]]
name = "chainsaw"
url = %s
default = true
# For proxies that require auth, export before running uv:
#   export UV_INDEX_CHAINSAW_USERNAME=<client_id>
#   export UV_INDEX_CHAINSAW_PASSWORD=<client_secret>
%s`, strconv.Quote(base+"/"+pypiPath+"/simple/"), tail), nil
}
