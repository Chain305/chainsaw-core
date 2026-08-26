package cli

// output_flags_contract_test.go — R4/X10, R5, R6, R7, A6.
//
// These pin the global output/behaviour flags: what --format accepts, when
// --output is refusable, which commands are EXEMPT from both, and that a
// transient global can no longer be baked into config.yaml.

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/chain305/chainsaw-core/cli/platform"
)

// ── R4 / X10: --format and --output validation ────────────────────────────────

// shadowedFormatCommands is the EXACT set of commands that declare their own
// --format flag and are therefore exempt from the global table|json check.
// Their vocabularies span csv/ndjson/yaml/sarif/text/cyclonedx/spdx and the
// package ecosystems, so validating them against table|json would break every
// one. Adding a command here should be a deliberate act, not a side effect —
// hence the exact-set assertion below.
var shadowedFormatCommands = []string{
	"chainsaw audit export",
	"chainsaw policy export",
	"chainsaw policy lint",
	"chainsaw repo create",
	"chainsaw report exposure",
	"chainsaw report multiversion",
	"chainsaw report provenance",
	"chainsaw report sla",
	"chainsaw sbom diff",
	"chainsaw sbom export",
	// P8-27 — "chainsaw scan-actions" was REMOVED from this set. Its local
	// --format shadowed the root's with a different default ("text" vs
	// "table") and, per the exemption above, opted the command out of --format
	// validation entirely. It now rides the global flag with its extra
	// vocabulary declared in extraCommandFormats, which keeps it inside BOTH
	// checks. Do not re-add a local --format here to "fix" a rejected value.
}

func TestFormatValidation_ExemptSetIsExactlyTheShadowingCommands(t *testing.T) {
	var got []string
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		if c.Parent() == nil {
			return // the root OWNS the flag; it is not a shadow
		}
		if c.Flags().Lookup("format") != nil && !ownsGlobalFlag(c, "format") {
			got = append(got, c.CommandPath())
		}
	}
	walk(rootCmd)
	sort.Strings(got)

	want := append([]string(nil), shadowedFormatCommands...)
	sort.Strings(want)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("the set of commands shadowing --format changed.\n got: %v\nwant: %v\n\n"+
			"A NEW shadowing command silently opts itself out of --format validation and of the "+
			"--output refusal. Confirm that is intended, then update shadowedFormatCommands.", got, want)
	}
}

func TestValidateOutputFlags_RejectsUnknownGlobalFormat(t *testing.T) {
	for _, bad := range []string{"jsonl", "yaml", "JSON5", "bogus"} {
		t.Run(bad, func(t *testing.T) {
			cmd := newGlobalFlagTestCmd(t)
			if err := cmd.Flags().Set("format", bad); err != nil {
				t.Fatalf("set format: %v", err)
			}
			err := validateOutputFlags(cmd)
			if err == nil {
				t.Fatalf("--format=%s was accepted; it silently rendered a table at rc=0", bad)
			}
			var coded *ExitCodeError
			if !errors.As(err, &coded) || coded.Code != ExitUsage {
				t.Errorf("--format=%s error = %v, want ExitCodeError{Code: ExitUsage}", bad, err)
			}
		})
	}
}

func TestValidateOutputFlags_AcceptsGlobalFormatVocabulary(t *testing.T) {
	// Case-insensitivity is existing, documented behaviour (resolveFormat
	// folds JSON/Json to json) and must survive the new validation.
	for _, ok := range []string{"table", "json", "JSON", "Json", "TABLE", ""} {
		cmd := newGlobalFlagTestCmd(t)
		if err := cmd.Flags().Set("format", ok); err != nil {
			t.Fatalf("set format=%q: %v", ok, err)
		}
		if err := validateOutputFlags(cmd); err != nil {
			t.Errorf("--format=%q rejected: %v", ok, err)
		}
	}
}

func TestValidateOutputFlags_RejectsOutputWithHumanFormat(t *testing.T) {
	cmd := newGlobalFlagTestCmd(t)
	if err := cmd.Flags().Set("output", filepath.Join(t.TempDir(), "o.txt")); err != nil {
		t.Fatalf("set output: %v", err)
	}
	err := validateOutputFlags(cmd)
	if err == nil {
		t.Fatal("`-o file` with the default table format was accepted; the file is never created and the result still goes to stdout")
	}
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != ExitUsage {
		t.Errorf("error = %v, want ExitCodeError{Code: ExitUsage}", err)
	}
}

func TestValidateOutputFlags_AllowsOutputWithJSON(t *testing.T) {
	for _, set := range []func(*cobra.Command) error{
		func(c *cobra.Command) error { return c.Flags().Set("json", "true") },
		func(c *cobra.Command) error { return c.Flags().Set("format", "json") },
	} {
		cmd := newGlobalFlagTestCmd(t)
		if err := cmd.Flags().Set("output", filepath.Join(t.TempDir(), "o.json")); err != nil {
			t.Fatalf("set output: %v", err)
		}
		if err := set(cmd); err != nil {
			t.Fatalf("set json: %v", err)
		}
		if err := validateOutputFlags(cmd); err != nil {
			t.Errorf("--output with a machine-readable format was rejected: %v", err)
		}
	}
}

func TestValidateOutputFlags_SkipsDisableFlagParsingCommands(t *testing.T) {
	// The guard wrappers and cargo-credentials forward argv untouched to the
	// wrapped tool. A --format meant for npm must never be rejected by
	// chainsaw. Verify the exemption is DELIBERATE (the explicit guard),
	// not merely a consequence of cobra not parsing.
	var disabled []string
	var walk func(*cobra.Command)
	walk = func(c *cobra.Command) {
		for _, sub := range c.Commands() {
			walk(sub)
		}
		if c.DisableFlagParsing {
			disabled = append(disabled, c.CommandPath())
			if err := validateOutputFlags(c); err != nil {
				t.Errorf("%s (DisableFlagParsing) was rejected by validateOutputFlags: %v", c.CommandPath(), err)
			}
		}
	}
	walk(rootCmd)
	if len(disabled) == 0 {
		t.Fatal("found no DisableFlagParsing commands; the guard wrappers should be here")
	}
	for _, want := range []string{"chainsaw npm", "chainsaw pip", "chainsaw go", "chainsaw cargo", "chainsaw gem", "chainsaw cargo-credentials"} {
		found := false
		for _, d := range disabled {
			if d == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is no longer DisableFlagParsing (found: %v)", want, disabled)
		}
	}
}

// newGlobalFlagTestCmd builds a leaf command under a root carrying the real
// global flag set, so ownsGlobalFlag's pointer-identity test is exercised for
// real rather than mocked.
func newGlobalFlagTestCmd(t *testing.T) *cobra.Command {
	t.Helper()
	root := &cobra.Command{Use: "chainsaw"}
	root.PersistentFlags().Bool("json", false, "")
	root.PersistentFlags().String("format", "table", "")
	root.PersistentFlags().StringP("output", "o", "", "")
	leaf := &cobra.Command{Use: "leaf", RunE: func(*cobra.Command, []string) error { return nil }}
	root.AddCommand(leaf)
	// InheritedFlags() is what triggers cobra's mergePersistentFlags; without
	// it leaf.Flags() is still empty and Set() reports "no such flag".
	_ = leaf.InheritedFlags()
	return leaf
}

// ── R5: repo create --ecosystem ───────────────────────────────────────────────

func TestRepoCreate_FormatFlagIsDeprecatedAndEcosystemExists(t *testing.T) {
	eco := repoCreateCmd.Flags().Lookup("ecosystem")
	if eco == nil {
		t.Fatal("repo create has no --ecosystem flag")
	}
	f := repoCreateCmd.Flags().Lookup("format")
	if f == nil {
		t.Fatal("--format was removed outright; it must survive one release as a deprecated alias so no script breaks")
	}
	if f.Deprecated == "" {
		t.Error("--format is not marked deprecated; cobra will not warn the user to migrate")
	}
	// MarkFlagRequired("format") must be gone: with two spellings cobra
	// cannot express "one of these", and the requirement moved into RunE.
	if ann := f.Annotations[cobra.BashCompOneRequiredFlag]; len(ann) > 0 && ann[0] == "true" {
		t.Error("--format is still MarkFlagRequired; `repo create --ecosystem npm` would fail")
	}
}

// ── R6: --no-color reaches the guard's stderr path ────────────────────────────

func TestNoColorFlagInArgs(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		want bool
	}{
		{"chainsaw global before subcommand", []string{"chainsaw", "--no-color", "npm", "install", "x"}, true},
		{"explicit true form", []string{"chainsaw", "--no-color=true", "npm", "install", "x"}, true},
		{"absent", []string{"chainsaw", "npm", "install", "x"}, false},
		// Scoping: after the guard subcommand the flag belongs to the WRAPPED
		// tool, not to chainsaw. Claiming it would change npm's behaviour.
		{"npm's own flag is not chainsaw's", []string{"chainsaw", "npm", "install", "--no-color"}, false},
		{"stops at end-of-flags marker", []string{"chainsaw", "--", "--no-color"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := noColorFlagInArgs(tc.argv); got != tc.want {
				t.Errorf("noColorFlagInArgs(%v) = %v, want %v", tc.argv, got, tc.want)
			}
		})
	}
}

func TestNoColorEnv_StillBeatsExplicitFlagFalse(t *testing.T) {
	// The precedence that must NOT change: initConfig's viper.Set sits in the
	// override tier, above BindPFlag, so NO_COLOR wins over --no-color=false.
	// NO_COLOR is the ecosystem-wide standard; the flag binding added for R6
	// must not demote it.
	withStdoutTTY(t, true)
	resetViperColor(t)
	t.Setenv("NO_COLOR", "1")

	cmd := newTestCmd()
	if err := cmd.Flags().Set("no-color", "false"); err != nil {
		t.Fatalf("set --no-color=false: %v", err)
	}
	if !noColor(cmd) {
		t.Fatal("--no-color=false overrode NO_COLOR=1; NO_COLOR must win")
	}
}

// ── R7: --verbose actually reaches the support diagnostics ────────────────────

func TestVerboseEnabled_HonorsFlagAndRejectsFalsyEnv(t *testing.T) {
	cases := []struct {
		name  string
		env   string
		viper bool
		want  bool
	}{
		{"unset", "", false, false},
		{"flag/viper true", "", true, true},
		{"env 1", "1", false, true},
		{"env true", "true", false, true},
		// The R7 half nobody expects: a PRESENCE test made these ENABLE
		// verbose, which is the opposite of what the operator wrote.
		{"env 0 must NOT enable", "0", false, false},
		{"env false must NOT enable", "false", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			viper.Reset()
			t.Cleanup(viper.Reset)
			t.Setenv("CHAINSAW_VERBOSE", tc.env)
			if tc.viper {
				viper.Set("verbose", true)
			}
			if got := verboseEnabled(); got != tc.want {
				t.Errorf("verboseEnabled() with CHAINSAW_VERBOSE=%q viper=%v = %v, want %v",
					tc.env, tc.viper, got, tc.want)
			}
		})
	}
}

// ── A6: transient globals are never persisted, and are self-healed ────────────

func TestWriteConfigYAML_DropsTransientGlobalsKeepsUnknownKeys(t *testing.T) {
	dir := withIsolatedConfigHome(t)

	viper.Set("server_url", "https://example.test")
	viper.Set("org_id", "org-1")
	viper.Set("quiet", true)
	viper.Set("verbose", true)
	viper.Set("no_color", true)
	viper.Set("token", "secret-token")
	viper.Set("client_secret", "secret-client")
	// The key the seed's allowlist fix would have DELETED: hand-authored,
	// read by cargo_credentials.go, never written by the CLI.
	viper.Set("cargo_credentials", "cli-abc:s3cr3t")

	if err := writeConfigYAML(); err != nil {
		t.Fatalf("writeConfigYAML: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var got map[string]any
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal config: %v", err)
	}

	for _, gone := range []string{"quiet", "verbose", "no_color", "token", "client_secret"} {
		if _, ok := got[gone]; ok {
			t.Errorf("%q was persisted to config.yaml; one `chainsaw --quiet …` would make every later run quiet forever", gone)
		}
	}
	for _, kept := range []string{"server_url", "org_id", "cargo_credentials"} {
		if _, ok := got[kept]; !ok {
			t.Errorf("%q was dropped from config.yaml; the denylist must preserve every key it does not know about", kept)
		}
	}
}

func TestInitConfig_SelfHealsBakedTransientGlobals(t *testing.T) {
	dir := withIsolatedConfigHome(t)
	withFileCredStore(t)
	t.Setenv("CHAINSAW_QUIET", "")
	t.Setenv("CHAINSAW_VERBOSE", "")
	os.Unsetenv("NO_COLOR")

	cfg := filepath.Join(dir, "config.yaml")
	seed := "server_url: https://example.test\n" +
		"org_id: org-1\n" +
		"cargo_credentials: cli-abc:s3cr3t\n" +
		"quiet: true\n" +
		"verbose: true\n" +
		"no_color: true\n"
	if err := os.WriteFile(cfg, []byte(seed), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	initConfig()

	// Relief on THIS run, not the next one.
	for _, k := range transientGlobalKeys {
		if viper.GetBool(k) {
			t.Errorf("viper %q is still true after initConfig; the poisoned value must be neutralized immediately", k)
		}
	}
	// And the file is rewritten without them, keeping everything else.
	data, err := os.ReadFile(cfg)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	var got map[string]any
	if err := yaml.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range transientGlobalKeys {
		if _, ok := got[k]; ok {
			t.Errorf("%q survived the self-heal rewrite", k)
		}
	}
	if got["cargo_credentials"] != "cli-abc:s3cr3t" {
		t.Errorf("cargo_credentials = %v; the self-heal must not touch hand-authored keys", got["cargo_credentials"])
	}
	if got["server_url"] != "https://example.test" {
		t.Errorf("server_url = %v, want https://example.test", got["server_url"])
	}
}

func TestInitConfig_SelfHealDoesNotClobberFlagOrEnv(t *testing.T) {
	// InConfig is what makes the self-heal safe: a --quiet on THIS
	// invocation (BindPFlag) or CHAINSAW_QUIET (BindEnv) does not satisfy
	// it, so a deliberate request for silence survives.
	dir := withIsolatedConfigHome(t)
	withFileCredStore(t)
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"),
		[]byte("server_url: https://example.test\n"), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	t.Setenv("CHAINSAW_QUIET", "1")
	_ = viper.BindEnv("quiet", "CHAINSAW_QUIET")

	initConfig()

	if !viper.GetBool("quiet") {
		t.Error("CHAINSAW_QUIET=1 was cleared by the self-heal; only config-FILE values may be reset")
	}
}

var _ = platform.EnvConfigHome

// ── R14: --quiet actually silences chatter ────────────────────────────────────

func TestChatter_HonorsQuietButNeverTouchesResults(t *testing.T) {
	newCmd := func() (*cobra.Command, *strings.Builder) {
		c := &cobra.Command{Use: "x"}
		c.Flags().Bool("quiet", false, "")
		var errBuf strings.Builder
		c.SetErr(&errBuf)
		return c, &errBuf
	}

	viper.Reset()
	t.Cleanup(viper.Reset)
	t.Setenv("CHAINSAW_QUIET", "")

	cmd, errBuf := newCmd()
	chatter(cmd, "Fetching audit events…")
	if !strings.Contains(errBuf.String(), "Fetching audit events") {
		t.Fatalf("chatter wrote nothing without --quiet: %q", errBuf.String())
	}
	if !strings.HasSuffix(errBuf.String(), "\n") {
		t.Error("chatter did not terminate the line")
	}

	cmd, errBuf = newCmd()
	if err := cmd.Flags().Set("quiet", "true"); err != nil {
		t.Fatalf("set --quiet: %v", err)
	}
	chatter(cmd, "Fetching audit events…")
	if errBuf.String() != "" {
		t.Errorf("--quiet did not silence chatter: %q", errBuf.String())
	}

	cmd, errBuf = newCmd()
	t.Setenv("CHAINSAW_QUIET", "1")
	chatter(cmd, "Fetching audit events…")
	if errBuf.String() != "" {
		t.Errorf("CHAINSAW_QUIET=1 did not silence chatter: %q", errBuf.String())
	}
}

// ── B3: the argv gate, exercised through cobra's PersistentPreRunE ───────────
//
// Every pre-existing SARIF test calls runScan / runPRScan DIRECTLY, which is
// structurally incapable of catching a flag-validation regression: the
// validator lives in rootCmd.PersistentPreRunE and only runs when cobra
// dispatches. That blind spot is exactly how `--format sarif` — implemented,
// advertised in --help, and documented — became unreachable on `scan` and
// `pr-scan` for two releases (exit 4, `invalid --format "sarif"`). The tests
// below drive the REAL rootCmd through Execute so the gate is in the path.

// stubLeafRunE replaces the RunE of the command at the given path with a
// recorder and restores it afterwards, so these tests measure the ARGV GATE
// rather than whether a command can reach a server. Returns a pointer that is
// set to true when the RunE was reached (i.e. the gate let the invocation
// through).
func stubLeafRunE(t *testing.T, path ...string) *bool {
	t.Helper()
	c, _, err := rootCmd.Find(path)
	if err != nil || c == nil {
		t.Fatalf("command %v not found in the command tree: %v", path, err)
	}
	if c.CommandPath() != "chainsaw "+strings.Join(path, " ") {
		t.Fatalf("Find(%v) resolved to %q; the test would assert against the wrong command", path, c.CommandPath())
	}
	reached := false
	origRunE, origRun := c.RunE, c.Run
	c.RunE = func(*cobra.Command, []string) error { reached = true; return nil }
	c.Run = nil
	t.Cleanup(func() { c.RunE, c.Run = origRunE, origRun })
	return &reached
}

// executeRootArgs drives the real rootCmd exactly as a shell invocation would,
// then restores the process-global flag state cobra leaves behind.
func executeRootArgs(t *testing.T, argv ...string) error {
	t.Helper()
	withIsolatedConfigHome(t)
	withFileCredStore(t)

	pf := rootCmd.PersistentFlags()
	t.Cleanup(func() {
		for name, def := range map[string]string{"format": "table", "output": "", "json": "false"} {
			_ = pf.Set(name, def)
			if f := pf.Lookup(name); f != nil {
				f.Changed = false
			}
		}
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})

	rootCmd.SetArgs(argv)
	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
	return rootCmd.Execute()
}

func TestExecute_SARIFIsReachableOnScanAndPRScan(t *testing.T) {
	cases := []struct {
		name string
		path []string
		argv []string
	}{
		// The exact invocation `chainsaw scan --help` advertises.
		{"scan", []string{"scan"}, []string{"scan", "lodash@4.17.21", "--format", "sarif"}},
		{"scan with --output", []string{"scan"}, []string{"scan", "lodash@4.17.21", "--format", "sarif", "--output", "OUT"}},
		// pr-scan renders SARIF to its OWN --output-file; the gate must not
		// reject the format on the way in.
		{"pr-scan", []string{"pr-scan"}, []string{"pr-scan", "--base", "HEAD~1", "--format", "sarif", "--output-file", "OUT"}},
		// Branch 2: scan-actions SHADOWS --format, so the format check skips
		// it — but the --output refusal did not, and killed the invocation
		// published verbatim in the GitHub Actions how-to.
		{"scan-actions", []string{"scan-actions"}, []string{"scan-actions", ".", "--format", "sarif", "--output", "OUT"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached := stubLeafRunE(t, tc.path...)
			argv := append([]string(nil), tc.argv...)
			for i, a := range argv {
				if a == "OUT" {
					argv[i] = filepath.Join(t.TempDir(), "results.sarif")
				}
			}
			if err := executeRootArgs(t, argv...); err != nil {
				t.Fatalf("%v was rejected before the command ran: %v", argv, err)
			}
			if !*reached {
				t.Errorf("%v returned no error but never reached the command's RunE", argv)
			}
		})
	}
}

func TestExecute_UnknownFormatStillExits4OnScanAndPRScan(t *testing.T) {
	// The allowlist must WIDEN the vocabulary, not disable the check. A local
	// --format flag on these two commands would have opted them out of
	// validation entirely — the X10 defect.
	cases := []struct {
		name string
		path []string
		argv []string
	}{
		{"scan jsonl", []string{"scan"}, []string{"scan", "x@1", "--format", "jsonl"}},
		{"scan bogus", []string{"scan"}, []string{"scan", "x@1", "--format", "bogus"}},
		{"scan yaml", []string{"scan"}, []string{"scan", "x@1", "--format", "yaml"}},
		{"scan JSON5", []string{"scan"}, []string{"scan", "x@1", "--format", "JSON5"}},
		{"pr-scan bogus", []string{"pr-scan"}, []string{"pr-scan", "--base", "HEAD~1", "--format", "bogus"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached := stubLeafRunE(t, tc.path...)
			err := executeRootArgs(t, tc.argv...)
			if err == nil {
				t.Fatalf("%v was accepted; an unrecognized format silently renders a table at rc=0", tc.argv)
			}
			var coded *ExitCodeError
			if !errors.As(err, &coded) || coded.Code != ExitUsage {
				t.Errorf("%v error = %v, want ExitCodeError{Code: ExitUsage}", tc.argv, err)
			}
			if *reached {
				t.Errorf("%v reached the RunE; the gate must reject before the command runs", tc.argv)
			}
		})
	}
}

func TestExecute_ScanStillRefusesOutputWithTheHumanTable(t *testing.T) {
	// The widened vocabulary must not weaken the R4 refusal: `scan` on the
	// default table format still has no sink to redirect.
	reached := stubLeafRunE(t, "scan")
	out := filepath.Join(t.TempDir(), "o.txt")
	err := executeRootArgs(t, "scan", "x@1", "--output", out)
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != ExitUsage {
		t.Fatalf("`scan -o file` with the table format = %v, want ExitCodeError{ExitUsage}", err)
	}
	if *reached {
		t.Error("the refused invocation still ran the command")
	}
	if _, statErr := os.Stat(out); statErr == nil {
		t.Error("the refused invocation created the output file")
	}
}

func TestExtraCommandFormats_DeclaredOnRealNonShadowingCommands(t *testing.T) {
	// The allowlist only has meaning for a command that sees the ROOT
	// --format. If one of these ever grows a local --format flag it silently
	// becomes exempt from validation instead, and this map turns into a lie.
	for path, formats := range extraCommandFormats {
		c, _, err := rootCmd.Find(strings.Fields(strings.TrimPrefix(path, "chainsaw ")))
		if err != nil || c == nil || c.CommandPath() != path {
			t.Errorf("extraCommandFormats key %q does not resolve to a command (got %v, %v)", path, c, err)
			continue
		}
		if !ownsGlobalFlag(c, "format") {
			t.Errorf("%s now declares its OWN --format flag, so it is already exempt from validation; "+
				"remove it from extraCommandFormats (and from shadowedFormatCommands' inverse) rather than listing it twice", path)
		}
		for v := range formats {
			if v != strings.ToLower(strings.TrimSpace(v)) {
				t.Errorf("extraCommandFormats[%q] key %q is not lower-cased; lookups fold through strings.ToLower and would never match", path, v)
			}
			if globalResultFormats[v] {
				t.Errorf("extraCommandFormats[%q] redundantly lists the global format %q", path, v)
			}
		}
	}
}

func TestValidateOutputFlags_AllowsOutputForAShadowingCommandsOwnFormat(t *testing.T) {
	// Branch 2, at the validator level and independent of any one command's
	// file: a command with its OWN --format vocabulary must keep --output for
	// every value of it. `useJSON(cmd)` answered false for all of them.
	for _, format := range []string{"csv", "ndjson", "yaml", "cyclonedx", "spdx", "sarif", "text"} {
		cmd := newShadowedFormatTestCmd(t)
		if err := cmd.Flags().Set("format", format); err != nil {
			t.Fatalf("set format=%s: %v", format, err)
		}
		if err := cmd.Flags().Set("output", filepath.Join(t.TempDir(), "o.out")); err != nil {
			t.Fatalf("set output: %v", err)
		}
		if err := validateOutputFlags(cmd); err != nil {
			t.Errorf("--format=%s --output was refused: %v", format, err)
		}
	}
}

// newShadowedFormatTestCmd is newGlobalFlagTestCmd with a LOCAL --format flag,
// modelling the eleven commands that own their format vocabulary while still
// using the root's --output.
func newShadowedFormatTestCmd(t *testing.T) *cobra.Command {
	t.Helper()
	root := &cobra.Command{Use: "chainsaw"}
	root.PersistentFlags().Bool("json", false, "")
	root.PersistentFlags().String("format", "table", "")
	root.PersistentFlags().StringP("output", "o", "", "")
	leaf := &cobra.Command{Use: "leaf", RunE: func(*cobra.Command, []string) error { return nil }}
	leaf.Flags().String("format", "", "")
	root.AddCommand(leaf)
	_ = leaf.InheritedFlags()
	return leaf
}

// ── Y7: prose backticks must never reach a flag's usage string ───────────────

// TestFlagUsage_NoProseBackticksInPlaceholders pins the three flags in this
// agent's files against pflag's UnquoteUsage, which consumes the FIRST
// back-quoted span in a usage string as the flag's VALUE PLACEHOLDER. Prose
// backticks therefore render as a fake argument name:
//
//	--org    "`org delete` target"          -> "--org org delete"  (on all 143
//	                                            help screens; it is persistent)
//	--stdin  "same as the `-` arg"          -> "--stdin -"         (a BOOL flag
//	                                            must show NO placeholder)
//	--simulate-id "a fresh `risk-weights preview` run"
//	                                        -> "--simulate-id risk-weights preview"
//
// TRAP for anyone editing these strings: UnquoteUsage strips only the FIRST
// pair, so a real placeholder plus leftover prose backticks leaks literal
// backticks into the help body. Keep exactly one pair, or none.
func TestFlagUsage_NoProseBackticksInPlaceholders(t *testing.T) {
	cases := []struct {
		name string
		cmd  *cobra.Command
		flag string
		// want is the rendered "--flag <placeholder>" prefix; a bool flag
		// renders with no placeholder at all.
		want string
	}{
		// cmd.Flags() is the complete set (local + inherited persistent), so
		// this reads the same FlagSet the help screen renders from.
		{"--org", rootCmd, "org", "--org string"},
		{"--stdin", scanCmd, "stdin", "--stdin"},
		{"--simulate-id", riskWeightsApplyCmd, "simulate-id", "--simulate-id string"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.cmd.Flags().Lookup(tc.flag)
			if f == nil {
				t.Fatalf("flag %q not found", tc.flag)
			}
			if strings.Contains(f.Usage, "`") {
				t.Errorf("usage string for --%s contains a backtick; pflag turns the first "+
					"back-quoted span into the value placeholder. Use single quotes.\n  usage: %s", tc.flag, f.Usage)
			}
			// FlagUsages renders "  --flag <placeholder>   <usage>"; the
			// placeholder is followed by run of spaces before the text.
			re := regexp.MustCompile(regexp.QuoteMeta(tc.want) + `\s{2,}\S`)
			if got := tc.cmd.Flags().FlagUsages(); !re.MatchString(got) {
				t.Errorf("--%s does not render as %q in the help output:\n%s", tc.flag, tc.want, got)
			}
		})
	}
}
