package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// agentHookTestEnv isolates the guard (embedded floor only, empty allowlist,
// no server preflight, nothing on PATH) and returns an empty project dir.
func agentHookTestEnv(t *testing.T) string {
	t.Helper()
	withGuardAllowlistStore(t)
	t.Setenv(guardSkipEnv, "")
	t.Setenv("CHAINSAW_OFFLINE", "1")
	prevPre, prevLook := runServerInstallPreflight, agentHookLookPath
	runServerInstallPreflight = func(context.Context, []packageSpec) ([]guardVerdict, bool, string) { return nil, false, "" }
	agentHookLookPath = func(string) (string, error) { return "", errors.New("not on PATH") }
	t.Cleanup(func() { runServerInstallPreflight, agentHookLookPath = prevPre, prevLook })
	return t.TempDir()
}

func words(cmd []shellWord) []string {
	out := make([]string, len(cmd))
	for i, w := range cmd {
		out[i] = w.text
		if w.dynamic {
			out[i] += "*"
		}
	}
	return out
}

func TestShellCommandsSplitsLikeAShell(t *testing.T) {
	cases := []struct {
		line string
		want [][]string
	}{
		{`npm i lodash`, [][]string{{"npm", "i", "lodash"}}},
		{`cd web && npm i a || yarn add b; pip install c | tee x`, [][]string{
			{"cd", "web"}, {"npm", "i", "a"}, {"yarn", "add", "b"}, {"pip", "install", "c"}, {"tee", "x"}}},
		// Quoted text is one word: this is a git command, not an install.
		{`git commit -m "npm install lodahs"`, [][]string{{"git", "commit", "-m", "npm install lodahs"}}},
		{`echo 'a;b|c' "d && e"`, [][]string{{"echo", "a;b|c", "d && e"}}},
		// A redirection target is not an argument; an fd number is not a word.
		{`npm i lodash > log.txt 2>&1`, [][]string{{"npm", "i", "lodash"}}},
		{`npm i lodash 2> err.txt >> out.txt < in.txt`, [][]string{{"npm", "i", "lodash"}}},
		// Comments and heredoc bodies are not commands.
		{"npm i a # npm i lodahs", [][]string{{"npm", "i", "a"}}},
		{"cat > README.md <<'EOF'\nnpm install lodahs\nEOF\nnpm i b", [][]string{
			{"cat"}, {"npm", "i", "b"}}},
		{"cat <<-EOF\n\tpip install reqeusts\n\tEOF\nls", [][]string{{"cat"}, {"ls"}}},
		// Run-time values are marked; substitutions become commands of their own.
		{`npm i "$PKG"`, [][]string{{"npm", "i", "$PKG*"}}},
		{`npm i $(cat pkgs)`, [][]string{{"npm", "i", "$*"}, {"cat", "pkgs"}}},
		{"echo `npm i evil`", [][]string{{"echo", "`*"}, {"npm", "i", "evil"}, {"`*"}}},
		{"npm i \\\n  lodash", [][]string{{"npm", "i", "lodash"}}},
		{`(cd app; npm ci)`, [][]string{{"cd", "app"}, {"npm", "ci"}}},
	}
	for _, c := range cases {
		var got [][]string
		for _, cmd := range shellCommands(c.line) {
			got = append(got, words(cmd))
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("shellCommands(%q)\n got  %q\n want %q", c.line, got, c.want)
		}
	}
}

// planSpecs resolves every check in a command line to "eco:name[@ver]" strings.
func planSpecs(t *testing.T, command, cwd string) []string {
	t.Helper()
	var out []string
	for _, c := range agentHookPlan(command, cwd, 0) {
		for _, s := range agentHookSpecs(c) {
			out = append(out, strings.ReplaceAll(s.String(), agentHookDynamicArg, "<dyn>"))
		}
	}
	return out
}

func TestAgentHookPlanFindsInstalls(t *testing.T) {
	dir := agentHookTestEnv(t)
	cases := []struct {
		command string
		want    []string
	}{
		{`npm install lodash`, []string{"npm:lodash"}},
		{`/opt/homebrew/bin/npm i lodash`, []string{"npm:lodash"}},
		{`command npm i lodash`, []string{"npm:lodash"}},
		{`sudo -E -u me npm i -g lodash`, []string{"npm:lodash"}},
		{`CI=1 FOO=bar npm i lodash`, []string{"npm:lodash"}},
		{`rtk pip install requests`, []string{"pip:requests"}},
		{`rtk proxy npm i lodash`, []string{"npm:lodash"}},
		{`python3 -m pip install requests==2.31.0`, []string{"pip:requests@2.31.0"}},
		{`pip3.12 install requests`, []string{"pip:requests"}},
		{`yarn add left-pad`, []string{"npm:left-pad"}},
		{`bash -lc "pnpm add left-pad"`, []string{"npm:left-pad"}},
		{`eval "npm i lodash"`, []string{"npm:lodash"}},
		// Run-a-package verbs the shell guard does not see.
		{`npx create-react-app my-app`, []string{"npm:create-react-app"}},
		{`npx -y @modelcontextprotocol/server-filesystem@latest /tmp`, []string{"npm:@modelcontextprotocol/server-filesystem@latest"}},
		{`npx -p typescript -p ts-node ts-node x.ts`, []string{"npm:typescript", "npm:ts-node"}},
		{`npm exec --yes -- cowsay hi`, []string{"npm:cowsay"}},
		{`npm create vite@latest my-app -- --template react`, []string{"npm:create-vite@latest"}},
		{`npm init @vitejs/app`, []string{"npm:@vitejs/create-app"}},
		{`pnpm dlx degit user/repo`, []string{"npm:degit"}},
		{`yarn create next-app`, []string{"npm:create-next-app"}},
		{`bunx cowsay`, []string{"npm:cowsay"}},
		{`uvx ruff@0.5.0 check .`, []string{"pip:ruff@0.5.0"}},
		{`uvx --from httpie http GET x`, []string{"pip:httpie"}},
		{`uv tool run --with rich black .`, []string{"pip:black", "pip:rich"}},
		{`pipx run pycowsay moo`, []string{"pip:pycowsay"}},
		// Unknown at run time: kept, marked.
		{`npm i "$PKG"`, []string{"npm:<dyn>"}},
		{`cat pkgs | xargs npm install`, []string{"npm:<dyn>"}},
		// Not installs.
		{`git commit -m "npm install lodahs"`, nil},
		{`echo npm install lodahs`, nil},
		{`command -v npm`, nil},
		{`npm run build`, nil},
		{`npm init -y`, nil},
		{`npm test && go test ./...`, nil},
		{`$NPM install lodahs`, nil}, // command name unknown: not classifiable
	}
	for _, c := range cases {
		got := planSpecs(t, c.command, dir)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s\n got  %q\n want %q", c.command, got, c.want)
		}
	}
}

// npx runs a local or PATH binary without fetching anything, so `npx tsc` in
// a project with typescript installed must not be checked as the unrelated
// npm package called "tsc".
func TestAgentHookNpxLocalBinIsNotAnInstall(t *testing.T) {
	dir := agentHookTestEnv(t)
	sub := filepath.Join(dir, "packages", "app")
	if err := os.MkdirAll(filepath.Join(dir, "node_modules", ".bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node_modules", ".bin", "tsc"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := planSpecs(t, `npx tsc --noEmit`, sub); got != nil {
		t.Errorf("npx tsc with a local bin up the tree: got %q, want nothing", got)
	}
	if got := planSpecs(t, `pnpm dlx tsc`, sub); !reflect.DeepEqual(got, []string{"npm:tsc"}) {
		t.Errorf("pnpm dlx always fetches: got %q, want [npm:tsc]", got)
	}
	agentHookLookPath = func(string) (string, error) { return "/usr/local/bin/eslint", nil }
	if got := planSpecs(t, `npx eslint .`, dir); got != nil {
		t.Errorf("npx eslint with eslint on PATH: got %q, want nothing", got)
	}
}

func TestAgentHookCdChangesTheLockfileDir(t *testing.T) {
	dir := agentHookTestEnv(t)
	web := filepath.Join(dir, "web")
	if err := os.MkdirAll(web, 0o755); err != nil {
		t.Fatal(err)
	}
	lock := `{"name":"w","lockfileVersion":3,"packages":{"":{"name":"w"},"node_modules/lodahs":{"version":"1.0.0"}}}`
	if err := os.WriteFile(filepath.Join(web, "package-lock.json"), []byte(lock), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := planSpecs(t, `npm ci`, dir); got != nil {
		t.Fatalf("npm ci in a dir with no lockfile: got %q, want nothing", got)
	}
	got := planSpecs(t, `cd web && npm ci`, dir)
	if !reflect.DeepEqual(got, []string{"npm:lodahs@1.0.0"}) {
		t.Fatalf("cd web && npm ci must scan web/package-lock.json: got %q", got)
	}
}

func TestAgentHookDecide(t *testing.T) {
	dir := agentHookTestEnv(t)
	ctx := context.Background()
	noConfig := func() {}

	d := agentHookDecide(ctx, `cd /tmp && npm install lodahs`, dir, noConfig)
	if d.decision != "deny" || !strings.Contains(d.reason, "npm:lodahs") {
		t.Fatalf("typosquat install: got %+v, want a deny naming npm:lodahs", d)
	}
	// The agent must not be handed the waiver (it would run it), and the
	// guard's signup nudge is not a reason.
	for _, bad := range []string{"guard allow", "sign up", "signup"} {
		if strings.Contains(d.reason, bad) {
			t.Errorf("deny reason contains %q:\n%s", bad, d.reason)
		}
	}

	for _, cmd := range []string{
		`npm install lodash`,
		`git commit -m "npm install lodahs"`,
		`ls -la`,
	} {
		if d := agentHookDecide(ctx, cmd, dir, noConfig); d.decision != "" {
			t.Errorf("%s: got %+v, want no opinion", cmd, d)
		}
	}

	if d := agentHookDecide(ctx, `npm i "$PKG"`, dir, noConfig); d.decision != "ask" {
		t.Errorf("dynamic package name: got %+v, want ask", d)
	}
	if d := agentHookDecide(ctx, `npm i "$PKG" lodahs`, dir, noConfig); d.decision != "deny" {
		t.Errorf("a refusal outranks an unknown: got %+v, want deny", d)
	}
}

func TestAgentHookHonoursGuardSkip(t *testing.T) {
	dir := agentHookTestEnv(t)
	t.Setenv(guardSkipEnv, "npm")
	if d := agentHookDecide(context.Background(), `npm i lodahs`, dir, func() {}); d.decision != "" {
		t.Errorf("CHAINSAW_GUARD_SKIP=npm: got %+v, want no opinion", d)
	}
	if d := agentHookDecide(context.Background(), `yarn add lodahs`, dir, func() {}); d.decision != "deny" {
		t.Errorf("skipping npm must not skip yarn: got %+v", d)
	}
}

// Config (and the keychain behind it) loads only when there is an install to
// check: the hook runs before every Bash call.
func TestAgentHookLoadsConfigOnlyForInstalls(t *testing.T) {
	dir := agentHookTestEnv(t)
	calls := 0
	count := func() { calls++ }
	agentHookDecide(context.Background(), `ls && git status && npm run build`, dir, count)
	if calls != 0 {
		t.Fatalf("config loaded %d times for a command with no install", calls)
	}
	agentHookDecide(context.Background(), `npm i lodash && pip install requests`, dir, count)
	if calls != 1 {
		t.Fatalf("config loaded %d times for two installs, want 1", calls)
	}
}

func runHook(t *testing.T, payload string, initConfig func()) (code int, stdout, stderr string) {
	t.Helper()
	var out, errb bytes.Buffer
	code = runAgentHook(strings.NewReader(payload), &out, &errb, nil, initConfig)
	return code, out.String(), errb.String()
}

func TestRunAgentHookProtocol(t *testing.T) {
	dir := agentHookTestEnv(t)
	payload := func(tool, command string) string {
		b, _ := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": dir,
			"tool_input": map[string]any{"command": command},
		})
		return string(b)
	}

	code, out, _ := runHook(t, payload("Bash", "npm i lodahs"), func() {})
	if code != 0 {
		t.Fatalf("deny must exit 0 (exit 2 would be a harness block), got %d", code)
	}
	var got struct {
		HookSpecificOutput struct {
			HookEventName, PermissionDecision, PermissionDecisionReason string
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not one JSON object: %v\n%s", err, out)
	}
	h := got.HookSpecificOutput
	if h.HookEventName != "PreToolUse" || h.PermissionDecision != "deny" || h.PermissionDecisionReason == "" {
		t.Fatalf("unexpected hook output: %+v", h)
	}

	for _, p := range []string{payload("Bash", "npm i lodash"), payload("Write", "npm i lodahs"), payload("Bash", "")} {
		if code, out, _ := runHook(t, p, func() {}); code != 0 || out != "" {
			t.Errorf("no-opinion payload %s: code=%d stdout=%q, want 0 and nothing", p, code, out)
		}
	}

	if code, out, _ := runHook(t, "not json", func() {}); code != 1 || out != "" {
		t.Errorf("malformed payload: code=%d stdout=%q, want 1 (a visible, non-blocking hook error)", code, out)
	}
	var out2, err2 bytes.Buffer
	if code := runAgentHook(strings.NewReader(payload("Bash", "ls")), &out2, &err2, []string{"--format", "cursor"}, func() {}); code != 1 {
		t.Errorf("unsupported --format: code=%d, want 1", code)
	}
}

// A crash must let the command through, never block it: Claude Code reads exit
// 2 (what an unrecovered Go panic exits with) as "block this tool call".
func TestRunAgentHookRecoversToExitZero(t *testing.T) {
	dir := agentHookTestEnv(t)
	b, _ := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": dir, "tool_input": map[string]any{"command": "npm i lodahs"}})
	code, out, stderr := runHook(t, string(b), func() { panic("boom") })
	if code != 0 || out != "" {
		t.Fatalf("panic: code=%d stdout=%q, want 0 and no decision", code, out)
	}
	if !strings.Contains(stderr, "not checked") {
		t.Errorf("panic must be reported on stderr, got %q", stderr)
	}
}

// The hook narrows; it never answers "allow", which would skip the user's own
// permission rules.
func TestAgentHookNeverAllows(t *testing.T) {
	dir := agentHookTestEnv(t)
	for _, cmd := range []string{`npm i lodash`, `npm i lodahs`, `npm i "$X"`, `ls`} {
		if d := agentHookDecide(context.Background(), cmd, dir, func() {}); d.decision != "" && d.decision != "deny" && d.decision != "ask" {
			t.Errorf("%s: decision %q", cmd, d.decision)
		}
	}
}

// Every manager the shell guard wraps is checked by the hook too.
func TestAgentHookCoversShimTools(t *testing.T) {
	for _, g := range guardedTools {
		if _, ok := agentHookTools[g.fn]; !ok && !agentHookPipRe.MatchString(g.fn) {
			t.Errorf("shell guard wraps %q but agentHookTools does not know it", g.fn)
		}
	}
}

func TestAgentHookFastPath(t *testing.T) {
	cases := map[string]bool{
		"chainsaw guard agent-hook":                 true,
		"chainsaw guard agent-hook --format claude": true,
		"chainsaw guard agent-hook --help":          false,
		"chainsaw guard status":                     false,
		"chainsaw --quiet guard agent-hook":         false,
		"chainsaw":                                  false,
	}
	for argv, want := range cases {
		if got := agentHookFastPath(strings.Fields(argv)); got != want {
			t.Errorf("agentHookFastPath(%q) = %v, want %v", argv, got, want)
		}
	}
}

func TestNpmInitializerPackage(t *testing.T) {
	cases := map[string]string{
		"vite":          "create-vite",
		"vite@latest":   "create-vite@latest",
		"@scope":        "@scope/create",
		"@scope@1.0.0":  "@scope/create@1.0.0",
		"@vitejs/app":   "@vitejs/create-app",
		"@vitejs/app@2": "@vitejs/create-app@2",
		"./local":       "",
		"":              "",
	}
	for in, want := range cases {
		if got := npmInitializerPackage(in); got != want {
			t.Errorf("npmInitializerPackage(%q) = %q, want %q", in, got, want)
		}
	}
}

// guardEvaluate is the one lane list the shell guard and the hook share. Its
// caller (runGuardedPassthrough) execs the real tool, so it is pinned here:
// the server lane gets the specs and its verdicts are merged; a notice
// instead of verdicts is reported, not merged; notices keep lane order.
func TestGuardEvaluateLanes(t *testing.T) {
	agentHookTestEnv(t)
	ctx := context.Background()
	specs := []packageSpec{{Ecosystem: "npm", Name: "lodash", Version: "4.17.21"}}

	var got []packageSpec
	runServerInstallPreflight = func(_ context.Context, s []packageSpec) ([]guardVerdict, bool, string) {
		got = s
		return []guardVerdict{{Spec: s[0], Block: true, Severity: serverSeverityPrefix + "critical", Reason: "server says no"}}, true, ""
	}
	verdicts, blocked, _ := guardEvaluate(ctx, newLocalGuard(), "npm", specs)
	if !reflect.DeepEqual(got, specs) {
		t.Fatalf("server lane got %+v, want the specs %+v", got, specs)
	}
	if !blocked || len(verdicts) == 0 || verdicts[len(verdicts)-1].Reason != "server says no" {
		t.Fatalf("server verdict not merged: blocked=%v verdicts=%+v", blocked, verdicts)
	}

	runServerInstallPreflight = func(context.Context, []packageSpec) ([]guardVerdict, bool, string) {
		return []guardVerdict{{Block: true}}, true, "server unavailable"
	}
	verdicts, blocked, notices := guardEvaluate(ctx, newLocalGuard(), "brew", []packageSpec{{Ecosystem: "homebrew", Name: "wget"}})
	if blocked {
		t.Fatalf("a server notice must not merge its verdicts: %+v", verdicts)
	}
	if len(notices) < 2 || !strings.Contains(notices[0], "Homebrew metadata not checked") || notices[len(notices)-1] != "server unavailable" {
		t.Fatalf("notices out of lane order (brew first, server last): %q", notices)
	}
}
