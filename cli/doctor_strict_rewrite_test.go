package cli

// `npm login` / `npm config set`, `pip config set` and `yarn config set`
// rewrite the user config without comments. The chainsaw-managed marker
// disappears while the registry still points at Chainsaw, and doctor
// --strict used to call that "drifted" — which the server turns into a
// compliant->drifted bypass alert. These pin that the SETTING decides.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"

	"github.com/chain305/chainsaw-core/cli/hook"
)

// fileHookManager is an installed manager whose Wired verdict comes from
// the marker in its config file, the way the real hook managers decide it.
type fileHookManager struct{ fakeHookManager }

func (f fileHookManager) Status() (hook.Status, error) {
	data, err := os.ReadFile(f.configPath)
	return hook.Status{ConfigPath: f.configPath, Wired: err == nil && hasChainsawSentinel(data), Installed: true}, nil
}

func (f fileHookManager) ConfigPathForScope(scope hook.Scope) (string, error) {
	if scope == hook.ScopeProject {
		return filepath.Join(filepath.Dir(f.configPath), "does-not-exist", "cfg"), nil
	}
	return f.configPath, nil
}

const rewriteTestServer = "https://chain305.example.com/chainproxy"

func TestEvaluateManager_RewrittenUserConfigJudgedBySetting(t *testing.T) {
	const (
		npmReg  = rewriteTestServer + "/repository/@acme/npmjs/"
		yarnReg = rewriteTestServer + "/repository/@acme/yarnpkg/"
		pipIdx  = "https://cli-1:s3cr3t@chain305.example.com/chainproxy/repository/@acme/pypi/simple/"
		marked  = "# >>> chainsaw-managed (do not edit) >>>\n"
		endMark = "# <<< chainsaw-managed <<<\n"
	)
	cases := []struct {
		name, manager, body, want string
	}{
		// npm (and bun, which writes the same ~/.npmrc shape)
		{"npm/marker present", "npm", marked + "registry=" + npmReg + "\n" + endMark, "compliant"},
		{"npm/marker stripped, chainsaw registry", "npm", "registry=" + npmReg + "\nignore-scripts=true\n", "compliant"},
		{"npm/npm login rewrote auth lines", "npm", "registry=" + npmReg + "\n//chain305.example.com/chainproxy/repository/@acme/npmjs/:_authToken=npm_abc123\nalways-auth=true\nignore-scripts=true\n", "compliant"},
		{"npm/marker stripped, public registry", "npm", "registry=https://registry.npmjs.org/\n", "drifted"},
		{"npm/lookalike host, same path", "npm", "registry=https://chain305.example.com.evil.net/chainproxy/repository/@acme/npmjs/\n", "drifted"},
		{"npm/right host, wrong repo path", "npm", "registry=https://chain305.example.com/chainproxy/npmjs/\n", "drifted"},
		{"npm/registry unset", "npm", "//chain305.example.com/chainproxy/repository/@acme/npmjs/:_authToken=npm_abc123\n", "drifted"},
		{"npm/later registry line wins", "npm", "registry=" + npmReg + "\nregistry=https://registry.npmjs.org/\n", "drifted"},
		{"npm/scoped registry elsewhere", "npm", "registry=" + npmReg + "\n@corp:registry=https://registry.npmjs.org/\n", "drifted"},
		{"bun/marker stripped, chainsaw registry", "bun", "registry=" + npmReg + "\n//chain305.example.com/chainproxy/repository/@acme/npmjs/:_auth=Y2xpOnM=\n", "compliant"},
		{"bun/marker stripped, public registry", "bun", "registry=https://registry.npmjs.org/\n", "drifted"},
		// yarn berry (.yarnrc.yml)
		{"yarn/marker present", "yarn", marked + "npmRegistryServer: \"" + yarnReg + "\"\n" + endMark, "compliant"},
		{"yarn/marker stripped, chainsaw registry", "yarn", "npmAuthToken: cli-1:s3cr3t\nnpmRegistryServer: \"" + yarnReg + "\"\n", "compliant"},
		{"yarn/marker stripped, public registry", "yarn", "npmRegistryServer: \"https://registry.yarnpkg.com\"\n", "drifted"},
		{"yarn/lookalike host, same path", "yarn", "npmRegistryServer: \"https://evil.example.net/chainproxy/repository/@acme/yarnpkg/\"\n", "drifted"},
		{"yarn/scope elsewhere", "yarn", "npmRegistryServer: \"" + yarnReg + "\"\nnpmScopes:\n  corp:\n    npmRegistryServer: \"https://registry.npmjs.org\"\n", "drifted"},
		// pip
		{"pip/marker present", "pip", marked + "[global]\nindex-url = " + pipIdx + "\n" + endMark, "compliant"},
		{"pip/pip config set rewrote file", "pip", "[global]\nindex-url = " + pipIdx + "\ntimeout = 60\n", "compliant"},
		{"pip/marker stripped, public index", "pip", "[global]\nindex-url = https://pypi.org/simple\n", "drifted"},
		{"pip/lookalike host, same path", "pip", "[global]\nindex-url = https://chain305.example.org/chainproxy/repository/@acme/pypi/simple/\n", "drifted"},
		{"pip/extra index public", "pip", "[global]\nindex-url = " + pipIdx + "\nextra-index-url = https://pypi.org/simple\n", "drifted"},
		{"pip/multi-line extra index public", "pip", "[global]\nindex-url = " + pipIdx + "\nextra_index_url =\n    https://pypi.org/simple\n", "drifted"},
		{"pip/install section overrides", "pip", "[global]\nindex-url = " + pipIdx + "\n[install]\nindex-url = https://pypi.org/simple\n", "drifted"},
		{"pip/index unset", "pip", "[global]\ntimeout = 60\n", "drifted"},
		// a manager the fallback does not cover keeps the marker-only verdict
		{"cargo/not covered", "cargo", "[source.crates-io]\nreplace-with = \"chainsaw\"\n", "drifted"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			clearWatchedEnv(t)
			t.Setenv("CHAINSAW_SERVER", "")
			viper.Set("server_url", rewriteTestServer)
			t.Cleanup(func() { viper.Set("server_url", "") })

			path := filepath.Join(t.TempDir(), "cfg")
			if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			m := fileHookManager{fakeHookManager{name: c.manager, configPath: path}}
			state := evaluateManager(m, map[string]string{}, map[string]string{})
			if state.Status != c.want {
				t.Fatalf("got %q (reason %q), want %q", state.Status, state.Reason, c.want)
			}
		})
	}
}

// With no Chainsaw server configured there is nothing to compare against,
// so a marker-less config keeps today's verdict even if it looks right.
func TestEvaluateManager_RewrittenUserConfigNeedsKnownServer(t *testing.T) {
	clearWatchedEnv(t)
	t.Setenv("CHAINSAW_SERVER", "")
	viper.Set("server_url", "")

	path := filepath.Join(t.TempDir(), ".npmrc")
	if err := os.WriteFile(path, []byte("registry="+rewriteTestServer+"/repository/@acme/npmjs/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := evaluateManager(fileHookManager{fakeHookManager{name: "npm", configPath: path}}, map[string]string{}, map[string]string{})
	if state.Status != "drifted" {
		t.Fatalf("got %q, want drifted with no server configured", state.Status)
	}
}

// A rewritten-but-Chainsaw user config must not mask a real bypass layered
// on top: an env override or a project-scope file still drifts.
func TestEvaluateManager_RewrittenUserConfigKeepsOtherBypasses(t *testing.T) {
	clearWatchedEnv(t)
	t.Setenv("CHAINSAW_SERVER", rewriteTestServer)
	viper.Set("server_url", "")

	dir := t.TempDir()
	path := filepath.Join(dir, ".npmrc")
	if err := os.WriteFile(path, []byte("registry="+rewriteTestServer+"/repository/@acme/npmjs/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := fileHookManager{fakeHookManager{name: "npm", configPath: path}}
	if st := evaluateManager(m, map[string]string{}, map[string]string{}); st.Status != "compliant" {
		t.Fatalf("baseline: got %q (%q), want compliant via CHAINSAW_SERVER", st.Status, st.Reason)
	}

	t.Setenv("NPM_CONFIG_REGISTRY", "https://registry.npmjs.org/")
	if st := evaluateManager(m, map[string]string{}, map[string]string{}); st.Status != "drifted" {
		t.Fatalf("env override: got %q, want drifted", st.Status)
	}
	clearWatchedEnv(t)

	proj := projectFileManager{fileHookManager: m, project: filepath.Join(dir, "proj.npmrc")}
	if err := os.WriteFile(proj.project, []byte("registry=https://registry.npmjs.org/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := evaluateManager(proj, map[string]string{}, map[string]string{}); st.Status != "drifted" {
		t.Fatalf("project override: got %q, want drifted", st.Status)
	}
}

type projectFileManager struct {
	fileHookManager
	project string
}

func (p projectFileManager) ConfigPathForScope(scope hook.Scope) (string, error) {
	if scope == hook.ScopeProject {
		return p.project, nil
	}
	return p.configPath, nil
}

// TestEvaluateManager_RealHookOutputSurvivesCommentStrip wires each covered
// manager with the real install-hook renderer, then drops every comment
// line — what `npm config set` / `pip config set` / `yarn config set` do to
// the file — and requires the result to stay compliant. This ties the
// fallback to the URL shape install-hook actually writes.
func TestEvaluateManager_RealHookOutputSurvivesCommentStrip(t *testing.T) {
	for _, name := range []string{"npm", "bun", "yarn", "pip"} {
		t.Run(name, func(t *testing.T) {
			clearWatchedEnv(t)
			home := t.TempDir()
			t.Setenv("HOME", home)
			t.Setenv("USERPROFILE", home)
			t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
			t.Setenv("APPDATA", filepath.Join(home, "AppData"))
			t.Setenv("CHAINSAW_SERVER", "")
			viper.Set("server_url", rewriteTestServer)
			t.Cleanup(func() { viper.Set("server_url", "") })

			var real hook.Manager
			for _, m := range hook.All() {
				if m.Name() == name {
					real = m
				}
			}
			if err := real.Wire(hook.WireOpts{ServerURL: rewriteTestServer, OrgSlug: "acme", Credentials: "cli-1:s3cr3t", Scope: hook.ScopeUser}); err != nil {
				t.Fatal(err)
			}
			path, err := real.ConfigPath()
			if err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var kept []string
			for _, ln := range strings.Split(string(data), "\n") {
				if !strings.HasPrefix(strings.TrimSpace(ln), "#") {
					kept = append(kept, ln)
				}
			}
			if err := os.WriteFile(path, []byte(strings.Join(kept, "\n")), 0o600); err != nil {
				t.Fatal(err)
			}

			m := fileHookManager{fakeHookManager{name: name, configPath: path}}
			if st := evaluateManager(m, map[string]string{}, map[string]string{}); st.Status != "compliant" {
				t.Fatalf("comment-stripped %s config: got %q (%q), want compliant\n%s", path, st.Status, st.Reason, strings.Join(kept, "\n"))
			}
		})
	}
}
