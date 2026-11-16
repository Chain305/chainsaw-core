package cli

// `chainsaw guard agent-hook` — the install guard as a coding-agent hook.
//
// Claude Code runs this before every Bash tool call (a PreToolUse hook). It
// reads the hook payload on stdin, finds the package installs in the command
// line, runs them through the SAME verdict lanes as the shell guard
// (guardEvaluate), and answers with a deny the agent can read. When nothing
// is refused it prints nothing and exits 0, and the command runs as normal.
//
// WHY A HOOK WHEN THE SHELL GUARD EXISTS. The shell guard is a set of shell
// functions. It reaches an agent only when the agent's shell loads the rc
// file, and only for the spelling `npm …`: `command npm`, `/opt/homebrew/bin/npm`,
// a wrapper that execs the real binary (rtk rewrites `pip install` to
// `rtk pip install`), npx and `npm create` all go around it. The hook sees
// the command text before any of that.
//
// WHAT IT IS NOT. It reads text, so a script file, `node -e`, or a Makefile
// still go around it. It is defence in depth beside the shell guard, exactly
// as guard_coverage.go says of the guard itself; the provable chokepoints are
// the proxy, CI, publish and admission. Never describe it as enforcement.
//
// CONTRACT WITH THE AGENT HARNESS — each rule is load-bearing:
//
//   - Exit 0 always, except a setup error (bad flag, unreadable payload),
//     which exits 1. Claude Code reads exit 2 as "block this tool call", and
//     both a Go panic and this CLI's generic error path exit 2 — so the
//     command never returns through cobra's error path (main fast path in
//     Execute, os.Exit here), and a panic is recovered to exit 0.
//   - Never answer "allow". An allow skips the user's own permission rules;
//     the hook only ever narrows. Silence means "no opinion".
//   - No session telemetry and no config load for commands that install
//     nothing: the hook runs on EVERY Bash call, and with telemetry consent a
//     chainsaw start used to cost ~1s and a session event pair.
//   - No new posture. Fail-closed applies only when the operator set
//     CHAINSAW_COVERAGE_MODE, exactly as for the shell guard
//     (docs/PLANS_PRODUCT.md#plan-optional-fail-closed, D3 and D5). An
//     internal error lets the command through, with a note on stderr.
//   - No stats, nudges or prompts (processGuardOutcome is not called): when
//     the shell guard is also loaded it runs on the same install, and
//     counting twice would double `guard status`.
//
// The deny reason does not offer `chainsaw guard allow`: the agent would run
// it. A waiver is the user's decision; they see the hint when they run the
// install themselves.

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

var guardAgentHookCmd = &cobra.Command{
	Use:   "agent-hook [--format claude]",
	Short: "Check package installs in a coding agent's shell commands (Claude Code PreToolUse hook)",
	Long: `Check the package installs in a coding agent's shell command before it runs.

Claude Code calls this as a PreToolUse hook on the Bash tool. It reads the hook
payload on stdin and, when an install would be refused, answers with a deny and
the reason; otherwise it prints nothing and the command runs. The checks are the
install guard's own (offline by default), applied to npm, pnpm, yarn, pip, uv,
poetry, pipx, go, cargo, gem and brew installs, and also to npx, npm exec,
npm/pnpm/yarn create, pnpm/yarn dlx, bunx, uvx, uv tool run and pipx run.

Install the Claude Code plugin, which also warns at session start when this
CLI is missing or too old:

  claude plugin marketplace add Chain305/chainsaw-core
  claude plugin install chainsaw-guard@chainsaw

Or add the hook to ~/.claude/settings.json yourself:

  {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command",
    "command": "chainsaw guard agent-hook; s=$?; [ \"$s\" -eq 2 ] && exit 1; exit \"$s\""}]}]}}

The exit-status line matters: Claude Code treats exit status 2 as "block this
command", so it is turned into 1, an error Claude Code shows without blocking.
This command never exits 2 itself; the line guards against a crash.

This is a second check beside the shell guard, not enforcement: a command the
hook cannot read (a script file, node -e) is not checked.`,
	DisableFlagParsing: true,
	SilenceUsage:       true,
	SilenceErrors:      true,
	Args:               cobra.ArbitraryArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		for _, a := range args {
			if a == "-h" || a == "--help" {
				return cmd.Help()
			}
		}
		// Normally unreachable: Execute runs plain `chainsaw guard agent-hook`
		// on its fast path. This path serves spellings the fast path does not
		// match (`chainsaw --quiet guard agent-hook`). Never a plain error:
		// Execute maps one to exit 2, which the harness reads as "block". A
		// message-less ExitCodeError exits silently with exactly its code,
		// and runAgentHook only returns 0 or 1.
		if code := runAgentHook(cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr(), args, func() {}); code != 0 {
			return &ExitCodeError{Code: code}
		}
		return nil
	},
}

func init() { guardCmd.AddCommand(guardAgentHookCmd) }

// agentHookFastPath reports whether argv is a plain `chainsaw guard
// agent-hook …` call that Execute should run before cobra, telemetry and
// config load. --help goes through cobra.
func agentHookFastPath(argv []string) bool {
	if len(argv) < 3 || argv[1] != "guard" || argv[2] != "agent-hook" {
		return false
	}
	for _, a := range argv[3:] {
		if a == "-h" || a == "--help" {
			return false
		}
	}
	return true
}

// agentHookMaxInput bounds the payload read. A Bash command is small; the
// bound only stops a runaway writer from holding memory.
const agentHookMaxInput = 8 << 20

// runAgentHook is the whole hook. initConfig loads chainsaw's config the
// first time a check needs it (the server preflight reads the URL and
// token); a command that installs nothing never pays for it.
func runAgentHook(stdin io.Reader, stdout, stderr io.Writer, args []string, initConfig func()) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(stderr, "chainsaw guard agent-hook: internal error, this command was not checked: %v\n", r)
			code = 0
		}
	}()

	format := "claude"
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--format" && i+1 < len(args):
			format = args[i+1]
			i++
		case strings.HasPrefix(a, "--format="):
			format = strings.TrimPrefix(a, "--format=")
		default:
			fmt.Fprintf(stderr, "chainsaw guard agent-hook: unknown argument %q (usage: chainsaw guard agent-hook [--format claude])\n", a)
			return 1
		}
	}
	if format != "claude" {
		fmt.Fprintf(stderr, "chainsaw guard agent-hook: unsupported --format %q (supported: claude)\n", format)
		return 1
	}

	data, err := io.ReadAll(io.LimitReader(stdin, agentHookMaxInput+1))
	if err != nil || len(data) > agentHookMaxInput {
		fmt.Fprintln(stderr, "chainsaw guard agent-hook: could not read the hook payload on stdin")
		return 1
	}
	var in struct {
		ToolName  string `json:"tool_name"`
		Cwd       string `json:"cwd"`
		ToolInput struct {
			Command string `json:"command"`
		} `json:"tool_input"`
	}
	if err := json.Unmarshal(data, &in); err != nil {
		fmt.Fprintf(stderr, "chainsaw guard agent-hook: the hook payload is not JSON: %v\n", err)
		return 1
	}
	if in.ToolName != "Bash" || strings.TrimSpace(in.ToolInput.Command) == "" {
		return 0
	}
	cwd := in.Cwd
	if cwd == "" {
		cwd, _ = os.Getwd()
	}

	d := agentHookDecide(context.Background(), in.ToolInput.Command, cwd, initConfig)
	if d.decision == "" {
		return 0
	}
	out, _ := json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       d.decision,
			"permissionDecisionReason": d.reason,
		},
	})
	fmt.Fprintln(stdout, string(out))
	return 0
}

type agentHookDecision struct {
	decision string // "deny", "ask", or "" (no opinion)
	reason   string
}

// agentHookCheck is one install found in the command line, in the shape the
// shell guard resolves: guardSpecsForBin(bin, args, parse) in dir.
type agentHookCheck struct {
	bin   string
	args  []string
	parse specParser
	dir   string
	skip  string // the CHAINSAW_GUARD_SKIP name that turns this check off ("" = none)
	text  string // the command as the agent wrote it, for the reason
}

// agentHookDynamicArg stands in for a word whose value is only known at run
// time. A resolved spec carrying it means the package name itself is unknown.
const agentHookDynamicArg = "\x00chainsaw-dynamic"

func agentHookDecide(ctx context.Context, command, cwd string, initConfig func()) agentHookDecision {
	checks := agentHookPlan(command, cwd, 0)
	if len(checks) == 0 {
		return agentHookDecision{}
	}
	skip, _, _ := parseGuardSkip([]string{os.Getenv(guardSkipEnv)})

	var (
		guard   *localGuard
		blocks  []guardVerdict
		unknown []string
	)
	for _, c := range checks {
		if c.skip != "" && skip[c.skip] {
			continue
		}
		specs, dynamic := agentHookSplitDynamic(agentHookSpecs(c))
		if dynamic {
			unknown = append(unknown, c.text)
		}
		if len(specs) == 0 {
			continue
		}
		if guard == nil {
			initConfig()
			guard = newLocalGuard()
		}
		verdicts, _, _ := guardEvaluate(ctx, guard, c.bin, specs)
		for _, v := range verdicts {
			if v.Block {
				blocks = append(blocks, v)
			}
		}
	}

	switch {
	case len(blocks) > 0:
		var b strings.Builder
		b.WriteString("Chainsaw refused this install; nothing was run.\n")
		for _, v := range blocks {
			fmt.Fprintf(&b, "- %s: %s\n", agentHookOneLine(fmt.Sprint(v.Spec)), agentHookOneLine(v.Reason))
		}
		b.WriteString("Do not retry it another way (another package manager, a direct path, npx, or a script). " +
			"Check that the package name is the one intended. If this exact package is needed, stop and ask the user to review it.")
		return agentHookDecision{"deny", b.String()}
	case len(unknown) > 0:
		return agentHookDecision{"ask", "Chainsaw cannot check this install: the package name is only known when the command runs " +
			"($VAR, $(...) or backticks) in: " + agentHookOneLine(strings.Join(unknown, "; ")) +
			". Write the package name out literally so it can be checked, or have the user approve it."}
	}
	return agentHookDecision{}
}

// agentHookSpecs resolves one check exactly as the shell guard would, in the
// directory the command runs in (a bare `npm ci` reads that directory's
// lockfile).
func agentHookSpecs(c agentHookCheck) []packageSpec {
	if c.dir != "" {
		if wd, err := os.Getwd(); err == nil && os.Chdir(c.dir) == nil {
			defer os.Chdir(wd) //nolint:errcheck // best effort; wd existed a moment ago
		}
	}
	specs, recognized, _ := guardSpecsForBin(c.bin, c.args, c.parse)
	if !recognized {
		return nil
	}
	return specs
}

// agentHookSplitDynamic drops the specs whose name, version or source is only
// known at run time, reporting whether there were any. The rest are still
// checked: `npm i "$X" lodahs` is refused for lodahs.
func agentHookSplitDynamic(specs []packageSpec) (known []packageSpec, dynamic bool) {
	for _, s := range specs {
		if strings.Contains(s.Name, agentHookDynamicArg) || strings.Contains(s.Version, agentHookDynamicArg) ||
			strings.Contains(s.Origin, agentHookDynamicArg) {
			dynamic = true
			continue
		}
		known = append(known, s)
	}
	return known, dynamic
}

// agentHookOneLine flattens untrusted text (a crafted package name, a reason
// quoting one) to a single line, so it cannot fake extra lines of the reason.
func agentHookOneLine(s string) string {
	return strings.Join(strings.Fields(sanitizeForTerminal(strings.ReplaceAll(s, agentHookDynamicArg, "<dynamic>"))), " ")
}

// agentHookMaxDepth bounds `bash -c "…"` / `eval` recursion.
const agentHookMaxDepth = 4

// agentHookPlan finds every install in a command line, in order, tracking
// `cd` so each one resolves in the directory it runs in.
func agentHookPlan(command, cwd string, depth int) []agentHookCheck {
	if depth > agentHookMaxDepth {
		return nil
	}
	var checks []agentHookCheck
	dir := cwd
	for _, words := range shellCommands(command) {
		words, fromStdin := agentHookStripPrefix(words)
		if len(words) == 0 || words[0].dynamic {
			continue // a command name only known at run time cannot be classified
		}
		name := agentHookToolName(words[0].text)
		rest := words[1:]
		switch name {
		case "cd", "pushd":
			if len(rest) > 0 && !rest[0].dynamic && rest[0].text != "-" {
				dir = agentHookJoinDir(dir, rest[0].text)
			}
			continue
		case "bash", "sh", "zsh", "dash", "ksh":
			if script, ok := agentHookShellScript(rest); ok {
				checks = append(checks, agentHookPlan(script, dir, depth+1)...)
			}
			continue
		case "eval":
			if len(rest) > 0 && !agentHookAnyDynamic(rest) {
				checks = append(checks, agentHookPlan(agentHookJoin(rest), dir, depth+1)...)
			}
			continue
		}
		argv := make([]string, len(rest))
		for i, w := range rest {
			argv[i] = w.text
			if w.dynamic {
				argv[i] = agentHookDynamicArg
			}
		}
		c, ok := agentHookClassify(name, argv, dir)
		if !ok {
			continue
		}
		if fromStdin {
			// `… | xargs npm install`: the packages arrive on stdin.
			c.args = append(c.args, agentHookDynamicArg)
		}
		c.dir = dir
		c.text = agentHookJoin(words)
		checks = append(checks, c)
	}
	return checks
}

// agentHookTools maps each manager the shell guard wraps to the bin and
// parser its `chainsaw <tool>` command uses (nil parse: a translated tool,
// see guardTranslators). TestAgentHookCoversShimTools pins it to
// guardedTools, so a manager added to the shell guard cannot be missed here.
var agentHookTools = map[string]struct {
	bin   string
	parse specParser
}{
	"npm":    {"npm", parseNpmInstall},
	"pip":    {"pip", parsePipInstall},
	"pip3":   {"pip", parsePipInstall},
	"go":     {"go", parseGoGet},
	"cargo":  {"cargo", parseCargoInstall},
	"gem":    {"gem", parseGemInstall},
	"brew":   {"brew", parseBrewInstall},
	"yarn":   {"yarn", nil},
	"pnpm":   {"pnpm", nil},
	"uv":     {"uv", nil},
	"poetry": {"poetry", nil},
	"pipx":   {"pipx", nil},
}

var (
	agentHookPythonRe = regexp.MustCompile(`^(python[0-9.]*|py)$`)
	agentHookPipRe    = regexp.MustCompile(`^pip[0-9.]+$`)
)

// agentHookClassify returns the check for one simple command, ok=false when
// the command is not a package manager this hook knows.
func agentHookClassify(name string, argv []string, dir string) (agentHookCheck, bool) {
	switch {
	case name == "npx":
		return agentHookNpx("npm", argv, nil, dir, true)
	case name == "bunx":
		return agentHookNpx("", argv, nil, dir, true)
	case name == "bun" && len(argv) > 0 && argv[0] == "x":
		return agentHookNpx("", argv[1:], nil, dir, true)
	case name == "uvx":
		return agentHookUvx(argv, nil)
	case agentHookPythonRe.MatchString(name):
		for i := 0; i+1 < len(argv); i++ {
			if argv[i] == "-m" {
				if argv[i+1] == "pip" || agentHookPipRe.MatchString(argv[i+1]) {
					return agentHookCheck{bin: "pip", args: argv[i+2:], parse: parsePipInstall, skip: "pip"}, true
				}
				return agentHookCheck{}, false
			}
		}
		return agentHookCheck{}, false
	case agentHookPipRe.MatchString(name):
		// pip3, pip3.12: `--skip pip` covers them too (parseGuardSkip matches
		// on the tool), `--skip pip3` covers only them.
		return agentHookCheck{bin: "pip", args: argv, parse: parsePipInstall, skip: "pip3"}, true
	}
	t, ok := agentHookTools[name]
	if !ok {
		return agentHookCheck{}, false
	}
	if c, ok := agentHookRunVerb(name, argv, dir); ok {
		return c, true
	}
	return agentHookCheck{bin: t.bin, args: argv, parse: t.parse, skip: name}, true
}

// agentHookRunVerb handles the run-a-package verbs the shell guard passes
// through unchecked: npm exec/x/create/init, pnpm and yarn dlx/create,
// uv tool run and pipx run. Each becomes the equivalent npm or pip install
// argv, so registry flags and project config apply exactly as they do to an
// install (the guard_translate.go approach). Hook-only on purpose: changing
// the shell functions would change every guarded shell at its next start.
func agentHookRunVerb(tool string, argv []string, dir string) (agentHookCheck, bool) {
	switch tool {
	case "npm":
		cmd := toolCommand(argv, npmFlags)
		if len(cmd) == 0 {
			return agentHookCheck{}, false
		}
		_, global := splitFlags(argv[:len(argv)-len(cmd)], npmFlags)
		switch cmd[0] {
		case "exec", "x":
			return agentHookNpx("npm", cmd[1:], global, dir, true)
		case "create", "init", "innit":
			return agentHookCreate("npm", cmd[1:], npmFlags, global)
		}
	case "pnpm", "yarn":
		fs := pnpmFlags
		if tool == "yarn" {
			fs = yarnFlags
		}
		cmd := toolCommand(argv, fs)
		if len(cmd) == 0 {
			return agentHookCheck{}, false
		}
		_, global := splitFlags(argv[:len(argv)-len(cmd)], fs)
		switch cmd[0] {
		case "dlx":
			return agentHookNpx(tool, cmd[1:], global, dir, false)
		case "create":
			return agentHookCreate(tool, cmd[1:], fs, global)
		}
	case "uv":
		cmd := toolCommand(argv, uvFlags)
		if len(cmd) >= 2 && cmd[0] == "tool" && cmd[1] == "run" {
			_, global := splitFlags(argv[:len(argv)-len(cmd)], uvFlags)
			return agentHookUvx(cmd[2:], global)
		}
	case "pipx":
		cmd := toolCommand(argv, pipxFlags)
		if len(cmd) >= 1 && cmd[0] == "run" {
			flags, app := agentHookLeadingFlags(cmd[1:], pipxFlags)
			var specs []string
			if lastValue(flags, "--spec") == "" {
				if app == "" {
					return agentHookCheck{}, false
				}
				specs = []string{app}
			}
			out := pipFamilyArgs(specs, flags)
			for _, pa := range flagValues(flags, "--pip-args") {
				out = append(out, strings.Fields(pa)...)
			}
			return agentHookCheck{bin: "pip", args: out, parse: parsePipInstall, skip: "pipx"}, true
		}
	}
	return agentHookCheck{}, false
}

// npxFlags: the npx / npm exec / dlx options that take a value.
var npxFlags = newFlagSet("",
	"-p --package -c --call --registry --cache --userconfig --prefix -w --workspace --node-options --script-shell",
	nil)

// agentHookNpx handles npx, npm exec, pnpm/yarn dlx and bunx: every --package
// is installed; with none, the first positional is a package unless it names
// a binary that is already there (resolveLocal: npx and npm exec run a local
// or PATH binary without fetching anything; dlx always fetches).
func agentHookNpx(skip string, argv []string, global []argFlag, dir string, resolveLocal bool) (agentHookCheck, bool) {
	flags, command := agentHookLeadingFlags(argv, npxFlags)
	var pkgs []string
	var rest []argFlag
	for _, f := range flags {
		if f.name == "-p" || f.name == "--package" {
			pkgs = append(pkgs, f.value)
		} else {
			rest = append(rest, f)
		}
	}
	if len(pkgs) == 0 {
		if command == "" || (resolveLocal && agentHookBinResolves(dir, command)) {
			return agentHookCheck{}, false
		}
		pkgs = []string{command}
	}
	return agentHookCheck{bin: "npm", args: npmFamilyArgs(pkgs, concatFlags(global, rest)), parse: parseNpmInstall, skip: skip}, true
}

// agentHookCreate handles npm init / npm, pnpm and yarn create: the first
// positional is an initializer, installed as create-<name>.
func agentHookCreate(skip string, argv []string, fs *flagSet, global []argFlag) (agentHookCheck, bool) {
	pos, flags := splitFlags(argv, fs)
	if len(pos) == 0 {
		return agentHookCheck{}, false // `npm init -y` writes package.json and installs nothing
	}
	spec := npmInitializerPackage(pos[0])
	if spec == "" {
		return agentHookCheck{}, false
	}
	return agentHookCheck{bin: "npm", args: npmFamilyArgs([]string{spec}, concatFlags(global, flags)), parse: parseNpmInstall, skip: skip}, true
}

// npmInitializerPackage maps an initializer to the package npm installs for
// it: foo -> create-foo, @scope -> @scope/create, @scope/foo ->
// @scope/create-foo, keeping any @version. "" for a path, which is not an
// initializer.
func npmInitializerPackage(arg string) string {
	if arg == "" || strings.ContainsAny(arg[:1], "./~") {
		return ""
	}
	name, ver := arg, ""
	if at := strings.LastIndex(arg, "@"); at > 0 {
		name, ver = arg[:at], arg[at:]
	}
	if strings.HasPrefix(name, "@") {
		if slash := strings.Index(name, "/"); slash < 0 {
			name += "/create"
		} else {
			name = name[:slash+1] + "create-" + name[slash+1:]
		}
	} else {
		name = "create-" + name
	}
	return name + ver
}

// agentHookUvx handles uvx and uv tool run: --from names the package when
// given (the positional is then a command in it), --with adds packages.
func agentHookUvx(argv []string, global []argFlag) (agentHookCheck, bool) {
	flags, command := agentHookLeadingFlags(argv, uvFlags)
	for i, f := range flags {
		if f.name == "--from" || f.name == "--with" {
			flags[i].value = uvxSpec(f.value)
		}
	}
	var specs []string
	if lastValue(flags, "--from") == "" {
		if command == "" {
			return agentHookCheck{}, false
		}
		specs = []string{uvxSpec(command)}
	}
	all := concatFlags(global, flags, uvEnvIndexFlags())
	return agentHookCheck{bin: "pip", args: pipFamilyArgs(specs, all), parse: parsePipInstall, skip: "uv"}, true
}

// uvxSpec maps uvx's `name@version` to pip's `name==version` (`@latest` to
// the bare name). A URL (`name@git+https://…`) is left for pip's parser.
func uvxSpec(s string) string {
	at := strings.LastIndex(s, "@")
	if at <= 0 || strings.ContainsAny(s[at+1:], ":/") {
		return s
	}
	if v := s[at+1:]; v != "latest" {
		return s[:at] + "==" + v
	}
	return s[:at]
}

// agentHookLeadingFlags reads options up to the first positional (the
// package or command to run; what follows it is that command's own argv).
func agentHookLeadingFlags(argv []string, fs *flagSet) (flags []argFlag, positional string) {
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--" {
			if i+1 < len(argv) {
				positional = argv[i+1]
			}
			return flags, positional
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			return flags, a
		}
		name, val, hasEq := strings.Cut(a, "=")
		name = fs.canonical(name)
		if !hasEq && fs.isValue(name) && i+1 < len(argv) {
			i++
			val = argv[i]
		}
		flags = append(flags, argFlag{name, val})
	}
	return flags, ""
}

// agentHookBinResolves reports whether npx would run name without fetching
// it: a plain command name found in node_modules/.bin up the tree or on PATH,
// or a scoped package installed up the tree. A name with a version is
// fetched unless the installed copy matches, which is not worth guessing.
func agentHookBinResolves(dir, name string) bool {
	if name == agentHookDynamicArg || dir == "" {
		return false
	}
	scoped := strings.HasPrefix(name, "@")
	if strings.Contains(strings.TrimPrefix(name, "@"), "@") || (!scoped && strings.ContainsAny(name, `/\`)) {
		return false
	}
	for d := filepath.Clean(dir); ; {
		if scoped {
			if fileExists(filepath.Join(d, "node_modules", filepath.FromSlash(name), "package.json")) {
				return true
			}
		} else {
			bin := filepath.Join(d, "node_modules", ".bin", name)
			if fileExists(bin) || (runtime.GOOS == "windows" && fileExists(bin+".cmd")) {
				return true
			}
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		d = parent
	}
	if scoped {
		return false
	}
	_, err := agentHookLookPath(name)
	return err == nil
}

// agentHookLookPath is exec.LookPath; a var so tests do not depend on what
// this machine has on PATH.
var agentHookLookPath = exec.LookPath

// agentHookStripPrefix drops what can stand before the command name: variable
// assignments, wrappers that run their argument (sudo, env, time, command,
// rtk, corepack, …) and their own options. fromStdin reports an xargs, whose
// arguments arrive on stdin. `command -v` is a lookup, not a run.
func agentHookStripPrefix(w []shellWord) (rest []shellWord, fromStdin bool) {
	for len(w) > 0 && !w[0].dynamic {
		t := w[0].text
		switch {
		case agentHookKeywords[t] || agentHookAssignRe.MatchString(t):
			w = w[1:]
		case agentHookWrappers[t] != nil:
			if t == "command" && len(w) > 1 && (w[1].text == "-v" || w[1].text == "-V") {
				return nil, false
			}
			if t == "xargs" {
				fromStdin = true
			}
			valueOpts := agentHookWrappers[t]
			w = w[1:]
			for len(w) > 0 && strings.HasPrefix(w[0].text, "-") && w[0].text != "-" {
				opt := w[0].text
				w = w[1:]
				if valueOpts[opt] && len(w) > 0 {
					w = w[1:]
				}
			}
			switch {
			case t == "timeout" && len(w) > 0:
				w = w[1:] // the duration
			case t == "rtk" && len(w) > 0 && w[0].text == "proxy":
				w = w[1:]
			}
		default:
			return w, fromStdin
		}
	}
	return w, fromStdin
}

var agentHookAssignRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\+?=`)

var agentHookKeywords = map[string]bool{
	"{": true, "!": true, "if": true, "then": true, "else": true, "elif": true,
	"do": true, "while": true, "until": true,
}

// agentHookWrappers: commands that run the command after them, with the
// options of each that take a value.
var agentHookWrappers = map[string]map[string]bool{
	"sudo":     {"-u": true, "-g": true, "-C": true, "-D": true, "-h": true, "-p": true, "-U": true, "-r": true, "-t": true, "-T": true},
	"doas":     {"-u": true, "-C": true},
	"env":      {"-u": true, "-C": true, "-S": true},
	"nice":     {"-n": true},
	"nohup":    {},
	"time":     {},
	"command":  {},
	"builtin":  {},
	"exec":     {"-a": true},
	"noglob":   {},
	"rtk":      {},
	"corepack": {},
	"timeout":  {"-s": true, "-k": true},
	"stdbuf":   {"-i": true, "-o": true, "-e": true},
	"xargs":    {"-I": true, "-n": true, "-P": true, "-L": true, "-s": true, "-d": true, "-E": true, "-a": true},
}

// agentHookToolName is the command's base name, without a Windows executable
// extension: /opt/homebrew/bin/npm and npm.cmd are both npm.
func agentHookToolName(word string) string {
	base := filepath.Base(strings.ReplaceAll(word, `\`, "/"))
	for _, ext := range []string{".exe", ".cmd", ".bat", ".ps1"} {
		if strings.HasSuffix(strings.ToLower(base), ext) {
			return base[:len(base)-len(ext)]
		}
	}
	return base
}

// agentHookShellScript returns the script of `bash -c '<script>'` (any option
// cluster containing c: -c, -lc, -ec).
func agentHookShellScript(args []shellWord) (string, bool) {
	for i := 0; i < len(args); i++ {
		a := args[i].text
		if !strings.HasPrefix(a, "-") || strings.HasPrefix(a, "--") {
			return "", false // a script file, or a long option this does not model
		}
		if strings.Contains(a, "c") {
			if i+1 < len(args) && !args[i+1].dynamic {
				return args[i+1].text, true
			}
			return "", false
		}
	}
	return "", false
}

func agentHookJoinDir(dir, target string) string {
	if strings.HasPrefix(target, "~") {
		if home, err := os.UserHomeDir(); err == nil {
			target = home + target[1:]
		}
	}
	if filepath.IsAbs(target) || dir == "" {
		return filepath.Clean(target)
	}
	return filepath.Join(dir, target)
}

func agentHookAnyDynamic(ws []shellWord) bool {
	for _, w := range ws {
		if w.dynamic {
			return true
		}
	}
	return false
}

func agentHookJoin(ws []shellWord) string {
	parts := make([]string, len(ws))
	for i, w := range ws {
		parts[i] = w.text
	}
	return strings.Join(parts, " ")
}
