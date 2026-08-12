package cli

// output_flags_contract_test.go — R4/X10, R5, R6, R7, A6.
//
// These pin the global output/behaviour flags: what --format accepts, when
// --output is refusable, which commands are EXEMPT from both, and that a
// transient global can no longer be baked into config.yaml.

import (
	"errors"
	"os"
	"path/filepath"
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
	"chainsaw scan-actions",
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
