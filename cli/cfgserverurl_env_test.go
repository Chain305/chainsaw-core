package cli

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// TestCfgServerURL_EnvHonored is the regression guard for the Wave K side
// observation: `chainsaw auth client create` (and every other server-required
// subcommand) ignored CHAINSAW_SERVER even though --help and docs advertised
// it as a valid configuration source. Only the --server flag worked.
//
// Root cause: viper.AutomaticEnv with the "CHAINSAW" prefix auto-binds the
// `server_url` viper key to CHAINSAW_SERVER_URL, not the documented
// CHAINSAW_SERVER. The fix is an explicit viper.BindEnv("server_url",
// "CHAINSAW_SERVER") in initConfig, mirroring the implicit CHAINSAW_TOKEN →
// `token` binding that already worked because the key and env name aligned.
//
// This test asserts the env-only resolution path produces a non-empty
// cfgServerURL() — no --server flag, no YAML config, no keychain entry.
func TestCfgServerURL_EnvHonored(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	rebindRootFlagsAfterReset(t)

	const want = "https://env-only.example.test"
	t.Setenv("CHAINSAW_SERVER", want)

	// Drive the real initConfig chain so the BindEnv call under test actually
	// runs in the same shape it does for production invocations.
	initConfig()

	var captured string
	probe := &cobra.Command{
		Use: "__server_env_probe",
		RunE: func(cmd *cobra.Command, args []string) error {
			captured = cfgServerURL()
			return nil
		},
	}
	rootCmd.AddCommand(probe)
	t.Cleanup(func() { rootCmd.RemoveCommand(probe) })

	// No --server flag — the only configured source is CHAINSAW_SERVER.
	rootCmd.SetArgs([]string{"__server_env_probe"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if captured != want {
		t.Fatalf("cfgServerURL() = %q, want %q (env-only resolution)", captured, want)
	}
}

// TestCfgServerURL_FlagBeatsEnv documents the precedence contract: when both
// the --server flag and CHAINSAW_SERVER are set, the flag wins. Matches the
// behaviour --token has with respect to CHAINSAW_TOKEN.
func TestCfgServerURL_FlagBeatsEnv(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	rebindRootFlagsAfterReset(t)

	const envURL = "https://from-env.example.test"
	const flagURL = "https://from-flag.example.test"
	t.Setenv("CHAINSAW_SERVER", envURL)

	initConfig()

	var captured string
	probe := &cobra.Command{
		Use: "__server_flag_probe",
		RunE: func(cmd *cobra.Command, args []string) error {
			captured = cfgServerURL()
			return nil
		},
	}
	rootCmd.AddCommand(probe)
	t.Cleanup(func() { rootCmd.RemoveCommand(probe) })

	rootCmd.SetArgs([]string{"--server", flagURL, "__server_flag_probe"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if captured != flagURL {
		t.Fatalf("cfgServerURL() = %q, want %q (flag beats env)", captured, flagURL)
	}
}

// TestCfgServerURL_EmptyWhenUnconfigured pins the "fail closed" path: no
// flag, no env, no YAML config → cfgServerURL returns "". This guards against
// a future regression where a stale viper-level default could leak into the
// "nothing configured" state and mask the helpful errServerNotConfigured.
func TestCfgServerURL_EmptyWhenUnconfigured(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	rebindRootFlagsAfterReset(t)

	// Make sure no env leaks in from the surrounding test process.
	t.Setenv("CHAINSAW_SERVER", "")
	t.Setenv("CHAINSAW_SERVER_URL", "")

	// Force the production initConfig chain to run with no inputs.
	viper.Reset()
	rebindRootFlagsAfterReset(t)
	initConfig()

	if got := cfgServerURL(); got != "" {
		t.Fatalf("cfgServerURL() = %q, want empty string when nothing is configured", got)
	}
}
