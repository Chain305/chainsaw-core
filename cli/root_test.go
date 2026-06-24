package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/chain305/chainsaw-core/cli/credstore"
	"github.com/chain305/chainsaw-core/cli/platform"
)

// withFileCredStore swaps the package credStore for a file-backed store in a
// tempdir, restoring the original afterward. Tests that touch credentials
// should always use this to avoid mutating the real OS keyring.
func withFileCredStore(t *testing.T) credstore.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "creds.json")
	fs := credstore.ForceFileBackend(path)
	prev := credStore
	credStore = func() credstore.Store { return fs }
	t.Cleanup(func() { credStore = prev })
	return fs
}

// withIsolatedConfigHome pins CHAINSAW_CONFIG_HOME to a tempdir and resets
// viper so each test starts from a known state.
func withIsolatedConfigHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(platform.EnvConfigHome, dir)
	viper.Reset()
	t.Cleanup(viper.Reset)
	return dir
}

func TestMigrateTokenToKeychain_MovesTokenAndRewritesYAML(t *testing.T) {
	dir := withIsolatedConfigHome(t)
	store := withFileCredStore(t)

	// Seed a legacy config.yaml with a plaintext token.
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	yaml := "server_url: https://example.test\n" +
		"org_id: org-1\n" +
		"token: legacy-token\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}

	// Drive initConfig by pointing viper at the file and re-reading.
	viper.SetConfigFile(cfgPath)
	viper.SetConfigType("yaml")
	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("read config: %v", err)
	}
	if viper.GetString("token") != "legacy-token" {
		t.Fatalf("pre-migration token not seen by viper")
	}

	migrateTokenToKeychain()

	// Token should be in the store now, keyed by server URL.
	got, err := store.Get(credService, "https://example.test")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if got != "legacy-token" {
		t.Fatalf("store token = %q, want %q", got, "legacy-token")
	}

	// YAML on disk should no longer mention the token.
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read back config: %v", err)
	}
	if strings.Contains(string(raw), "legacy-token") {
		t.Fatalf("YAML still contains token: %s", raw)
	}

	// cfgToken() should now resolve from the store via server URL.
	if tok := cfgToken(); tok != "legacy-token" {
		t.Fatalf("cfgToken() = %q, want %q", tok, "legacy-token")
	}
}

func TestMigrateTokenToKeychain_PrefersExistingStoreValue(t *testing.T) {
	dir := withIsolatedConfigHome(t)
	store := withFileCredStore(t)

	// Pre-populate the credential store with the authoritative token.
	if err := store.Set(credService, "https://example.test", "store-token"); err != nil {
		t.Fatalf("seed store: %v", err)
	}

	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	yaml := "server_url: https://example.test\n" +
		"token: stale-yaml-token\n"
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	viper.SetConfigFile(cfgPath)
	viper.SetConfigType("yaml")
	if err := viper.ReadInConfig(); err != nil {
		t.Fatalf("read config: %v", err)
	}

	migrateTokenToKeychain()

	// Store value should win.
	got, _ := store.Get(credService, "https://example.test")
	if got != "store-token" {
		t.Fatalf("store token = %q, want %q", got, "store-token")
	}
	// YAML token must be stripped either way.
	raw, _ := os.ReadFile(cfgPath)
	if strings.Contains(string(raw), "stale-yaml-token") {
		t.Fatalf("YAML still contains stale token: %s", raw)
	}
}

func TestSaveConfig_RoutesTokenToCredStoreAndOmitsFromYAML(t *testing.T) {
	dir := withIsolatedConfigHome(t)
	store := withFileCredStore(t)

	if err := saveConfig("https://example.test", "fresh-token", "org-99"); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}

	cfgPath := filepath.Join(dir, "config.yaml")
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if strings.Contains(string(raw), "fresh-token") {
		t.Fatalf("YAML contains token: %s", raw)
	}
	if !strings.Contains(string(raw), "https://example.test") {
		t.Fatalf("YAML missing server_url: %s", raw)
	}
	if !strings.Contains(string(raw), "org-99") {
		t.Fatalf("YAML missing org_id: %s", raw)
	}

	got, err := store.Get(credService, "https://example.test")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if got != "fresh-token" {
		t.Fatalf("store token = %q, want %q", got, "fresh-token")
	}
}

// TestSaveConfig_RejectsTokenWithoutServer pins the D1a fix: a token paired
// with an empty server URL used to silently drop the token (the credstore
// branch was gated by serverURL != ""). The new behaviour is an actionable
// error mentioning `chainsaw auth login`.
func TestSaveConfig_RejectsTokenWithoutServer(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)

	err := saveConfig("", "secret-token", "org-1")
	if err == nil {
		t.Fatal("saveConfig with token + empty server should error, got nil")
	}
	if !strings.Contains(err.Error(), "server URL is required") {
		t.Fatalf("error message should mention required server URL, got: %v", err)
	}
}

// TestSaveConfig_ServerAndOrgOnlyWorksWithoutToken makes sure the guard is
// scoped tightly: an empty token alongside a server URL is still a legal
// write (e.g. reconfiguring the org without rotating the token).
func TestSaveConfig_ServerAndOrgOnlyWorksWithoutToken(t *testing.T) {
	dir := withIsolatedConfigHome(t)
	withFileCredStore(t)

	if err := saveConfig("https://example.test", "", "org-77"); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "config.yaml"))
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	if !strings.Contains(string(raw), "org-77") {
		t.Fatalf("YAML missing org_id, got: %s", raw)
	}
}

func TestClearConfig_RemovesCredentialAndYAML(t *testing.T) {
	dir := withIsolatedConfigHome(t)
	store := withFileCredStore(t)

	if err := saveConfig("https://example.test", "tok", "org"); err != nil {
		t.Fatalf("saveConfig: %v", err)
	}
	// Sanity: credential is there.
	if _, err := store.Get(credService, "https://example.test"); err != nil {
		t.Fatalf("precondition: %v", err)
	}

	if err := saveConfig("", "", ""); err != nil {
		t.Fatalf("clear: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "config.yaml")); !os.IsNotExist(err) {
		t.Fatalf("config.yaml should be gone, err = %v", err)
	}
	if _, err := store.Get(credService, "https://example.test"); err == nil {
		t.Fatalf("credential should be deleted")
	}
}

func TestPersistentServerFlagDefaultMatchesDefaultServer(t *testing.T) {
	got := rootCmd.PersistentFlags().Lookup("server").DefValue
	if got != DefaultServer {
		t.Fatalf("--server flag default = %q, want DefaultServer = %q", got, DefaultServer)
	}
}

// rebindRootFlagsAfterReset re-installs the pflag → viper bindings that
// viper.Reset() inside withIsolatedConfigHome wipes out. Tests that exercise
// the cfgToken / cfgServerURL precedence must call this to get the same
// behaviour the production CLI sees, where the bindings are installed once
// in init() and survive for the process lifetime.
func rebindRootFlagsAfterReset(t *testing.T) {
	t.Helper()
	if err := viper.BindPFlag("token", rootCmd.PersistentFlags().Lookup("token")); err != nil {
		t.Fatalf("rebind token: %v", err)
	}
	if err := viper.BindPFlag("server_url", rootCmd.PersistentFlags().Lookup("server")); err != nil {
		t.Fatalf("rebind server_url: %v", err)
	}
	// Also reset the persistent flag's "Changed" bit between tests so a flag
	// set by a previous test doesn't bleed into this one.
	_ = rootCmd.PersistentFlags().Set("token", "")
	rootCmd.PersistentFlags().Lookup("token").Changed = false
	_ = rootCmd.PersistentFlags().Set("server", "")
	rootCmd.PersistentFlags().Lookup("server").Changed = false
}

// TestCfgToken_FlagWinsOverKeychain is the **regression guard** for the
// `--token` precedence bug. Before the fix, migrateTokenToKeychain saw the
// flag's value via viper.GetString("token") (BindPFlag plumbs the flag value
// through that call), mistook it for a stale YAML token, wrote it into the
// keychain or skipped that branch entirely, and then called
// viper.Set("token", "") — which has higher precedence than BindPFlag and
// silently cleared the flag for the rest of the request. cfgToken() then
// fell through to the keychain. Repro from the bug report:
//
//	$ chainsaw --server X --token bogus policy list
//	→ HTTP 200 (uses keychain credentials, ignores --token)
//
// With the fix the flag wins.
func TestCfgToken_FlagWinsOverKeychain(t *testing.T) {
	withIsolatedConfigHome(t)
	store := withFileCredStore(t)
	rebindRootFlagsAfterReset(t)

	const server = "https://chain305.com/chainproxy"
	if err := store.Set(credService, server, "keychain-token-Y"); err != nil {
		t.Fatalf("seed keychain: %v", err)
	}

	// Simulate `chainsaw --server X --token Z policy list` by driving the
	// real rootCmd through Execute. A throwaway subcommand captures cfgToken()
	// after the OnInitialize chain (initConfig + migrateTokenToKeychain) runs.
	var captured string
	probe := &cobra.Command{
		Use: "__token_probe",
		RunE: func(cmd *cobra.Command, args []string) error {
			captured = cfgToken()
			return nil
		},
	}
	rootCmd.AddCommand(probe)
	t.Cleanup(func() { rootCmd.RemoveCommand(probe) })

	rootCmd.SetArgs([]string{
		"--server", server,
		"--token", "flag-token-X",
		"__token_probe",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if captured != "flag-token-X" {
		t.Fatalf("cfgToken() = %q, want %q (the --token flag must beat the keychain)",
			captured, "flag-token-X")
	}

	// Belt-and-braces: the keychain entry must still be intact afterward.
	// A previous regression had migrateTokenToKeychain overwriting the
	// keychain with the flag value when the keychain was empty.
	got, err := store.Get(credService, server)
	if err != nil {
		t.Fatalf("keychain.Get after run: %v", err)
	}
	if got != "keychain-token-Y" {
		t.Fatalf("keychain was mutated by --token flow: got %q, want %q", got, "keychain-token-Y")
	}
}

// TestCfgToken_FlagWinsWithEmptyKeychain covers the case where --token is
// passed and the keychain has nothing — the flag value still flows through.
func TestCfgToken_FlagWinsWithEmptyKeychain(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	rebindRootFlagsAfterReset(t)

	const server = "https://chain305.com/chainproxy"

	var captured string
	probe := &cobra.Command{
		Use: "__token_probe2",
		RunE: func(cmd *cobra.Command, args []string) error {
			captured = cfgToken()
			return nil
		},
	}
	rootCmd.AddCommand(probe)
	t.Cleanup(func() { rootCmd.RemoveCommand(probe) })

	rootCmd.SetArgs([]string{
		"--server", server,
		"--token", "flag-only",
		"__token_probe2",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if captured != "flag-only" {
		t.Fatalf("cfgToken() = %q, want %q", captured, "flag-only")
	}
}

// TestCfgToken_KeychainWinsWhenNoFlag confirms that when neither --token nor
// CHAINSAW_TOKEN is set, the keychain value is what cfgToken returns.
func TestCfgToken_KeychainWinsWhenNoFlag(t *testing.T) {
	withIsolatedConfigHome(t)
	store := withFileCredStore(t)
	rebindRootFlagsAfterReset(t)

	const server = "https://chain305.com/chainproxy"
	if err := store.Set(credService, server, "from-keychain"); err != nil {
		t.Fatalf("seed keychain: %v", err)
	}

	var captured string
	probe := &cobra.Command{
		Use: "__token_probe3",
		RunE: func(cmd *cobra.Command, args []string) error {
			captured = cfgToken()
			return nil
		},
	}
	rootCmd.AddCommand(probe)
	t.Cleanup(func() { rootCmd.RemoveCommand(probe) })

	rootCmd.SetArgs([]string{"--server", server, "__token_probe3"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if captured != "from-keychain" {
		t.Fatalf("cfgToken() = %q, want %q (no flag → keychain wins)", captured, "from-keychain")
	}
}

// TestCfgToken_EmptyWhenUnconfigured covers the "fail closed" path — no flag,
// no env, no YAML token, no keychain entry → cfgToken returns "".
func TestCfgToken_EmptyWhenUnconfigured(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	rebindRootFlagsAfterReset(t)

	const server = "https://chain305.com/chainproxy"

	var captured string
	probe := &cobra.Command{
		Use: "__token_probe4",
		RunE: func(cmd *cobra.Command, args []string) error {
			captured = cfgToken()
			return nil
		},
	}
	rootCmd.AddCommand(probe)
	t.Cleanup(func() { rootCmd.RemoveCommand(probe) })

	rootCmd.SetArgs([]string{"--server", server, "__token_probe4"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if captured != "" {
		t.Fatalf("cfgToken() = %q, want empty string when nothing is configured", captured)
	}
}

// TestCfgToken_FlagBeatsYAMLAndKeychain covers the worst-case scenario: a
// legacy YAML config with a token AND a keychain entry AND a --token flag on
// this invocation. The flag must still win; the migration must not stomp it.
func TestCfgToken_FlagBeatsYAMLAndKeychain(t *testing.T) {
	dir := withIsolatedConfigHome(t)
	store := withFileCredStore(t)
	rebindRootFlagsAfterReset(t)

	const server = "https://chain305.com/chainproxy"

	// Seed a legacy YAML config with a token in it.
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	yamlBody := "server_url: " + server + "\n" +
		"token: legacy-yaml-token\n"
	if err := os.WriteFile(cfgPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatalf("seed config: %v", err)
	}
	if err := store.Set(credService, server, "keychain-token"); err != nil {
		t.Fatalf("seed keychain: %v", err)
	}

	var captured string
	probe := &cobra.Command{
		Use: "__token_probe5",
		RunE: func(cmd *cobra.Command, args []string) error {
			captured = cfgToken()
			return nil
		},
	}
	rootCmd.AddCommand(probe)
	t.Cleanup(func() { rootCmd.RemoveCommand(probe) })

	rootCmd.SetArgs([]string{
		"--server", server,
		"--token", "flag-token",
		"__token_probe5",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if captured != "flag-token" {
		t.Fatalf("cfgToken() = %q, want flag-token (YAML and keychain must not override the flag)", captured)
	}
}
