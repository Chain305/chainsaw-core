package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/chain305/chainsaw-core/cli/credstore"
	"github.com/chain305/chainsaw-core/cli/platform"
	"github.com/chain305/chainsaw-core/cli/secureio"
)

// credService is the keyring service name used for all chainsaw credentials.
// The account is the server URL so multiple profiles can coexist.
const credService = "chainsaw"

// credStore is indirected through a function so tests can swap in a file-
// backed store without touching the real OS keyring.
var credStore = func() credstore.Store { return credstore.Default() }

var rootCmd = &cobra.Command{
	Use:   "chainsaw",
	Short: "Chainsaw supply chain security CLI",
	Long: `Interact with your Chainsaw server: manage policies, audit events, and org
settings.

New here? Run ` + "`chainsaw introduce`" + ` first — it prints the five mental models,
two modes, vocabulary, and routing heuristics every Chainsaw surface (CLI,
MCP, docs, landing page) shares. That framing will make the rest of the
commands make sense.

Then: ` + "`chainsaw setup`" + ` for an interactive first-time wizard, or
` + "`chainsaw auth login --device`" + ` for the headless / CI / AI-agent path.`,
	Version:       fmt.Sprintf("%s (commit: %s, built: %s)", Version, Commit, BuildDate),
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		return rejectPostSubcommandServerFlag(cmd, os.Args)
	},
}

// rejectPostSubcommandServerFlag errors when --server appears positionally
// after the invoked subcommand name, unless that subcommand (or an ancestor
// below root) defines a local --server flag. The persistent root --server
// works from any position, but `chainsaw foo --server X` silently relied on
// that propagation before — the audit wants the canonical `chainsaw --server
// X foo` form surfaced to users who reach for the other placement.
func rejectPostSubcommandServerFlag(cmd *cobra.Command, argv []string) error {
	for c := cmd; c != nil && c.Parent() != nil; c = c.Parent() {
		if f := c.LocalFlags().Lookup("server"); f != nil {
			return nil
		}
	}
	var names []string
	for c := cmd; c != nil && c.Parent() != nil; c = c.Parent() {
		names = append([]string{c.Name()}, names...)
	}
	if len(names) == 0 || len(argv) == 0 {
		return nil
	}
	cutoff := -1
	searchFrom := 1
	for _, n := range names {
		for i := searchFrom; i < len(argv); i++ {
			if argv[i] == n {
				cutoff = i
				searchFrom = i + 1
				break
			}
		}
	}
	if cutoff < 0 {
		return nil
	}
	path := cmd.CommandPath()
	sub := strings.TrimPrefix(path, cmd.Root().Name()+" ")
	for i := cutoff + 1; i < len(argv); i++ {
		tok := argv[i]
		if tok == "--" {
			return nil
		}
		if tok == "--server" || strings.HasPrefix(tok, "--server=") {
			return fmt.Errorf("--server is not a flag of `%s`. The server URL is set with the root flag:\n  chainsaw --server <url> %s\nOr via CHAINSAW_SERVER env var, or via `chainsaw auth login`.", path, sub)
		}
	}
	return nil
}

// Execute is the CLI entrypoint called from main. Wraps the Cobra
// rootCmd.Execute so every invocation emits a cli.session.started on
// entry and cli.session.completed on exit, regardless of whether the
// command returned an error. Deferred Flush ensures a short-lived CLI
// doesn't lose its tail telemetry.
func Execute() {
	// Fast-path: cargo's credential-provider protocol invokes the
	// binary with argv == ["--cargo-plugin"] (the array form of the
	// `credential-provider = [...]` config drops everything but the
	// executable path, then appends --cargo-plugin). Detect that here
	// and route straight to the protocol loop before cobra parses
	// flags — otherwise cobra rejects --cargo-plugin as an unknown
	// flag and cargo sees "failed to deserialize hello: EOF" because
	// the helper never emitted anything.
	//
	// Wave Q P2-DRIFT-CARGO-CREDS — see internal/cli/cargo_credentials.go
	// for the wider protocol implementation. We only handle the entry
	// here; the actual JSON loop lives in runCargoCredsProtocol so
	// tests can drive it without spawning a real process.
	if len(os.Args) >= 2 && os.Args[1] == "--cargo-plugin" {
		// Wave S follow-up: the fast-path skips cobra's argv-parse phase,
		// which means cobra.OnInitialize(initConfig) never fires and
		// viper.ReadInConfig() never runs. Without that, the YAML
		// fallback branch in lookupCargoCredentials sees an empty viper
		// store and the provider reports "no client_credential
		// available" even when ~/.chainsaw/config.yaml has the right
		// `cargo_credentials` key. Run initConfig manually here so the
		// env / keyring / YAML resolution all behave the same way in
		// fast-path mode as they do under normal cobra dispatch.
		initConfig()
		if err := runCargoCredsProtocol(rootCmd, os.Stdin, os.Stdout, os.Stderr); err != nil {
			fmt.Fprintln(os.Stderr, "chainsaw cargo-credentials:", err)
			os.Exit(1)
		}
		return
	}

	// BUG-CLI-5: refresh the --version string from the resolved build
	// info (which falls back to runtime/debug.ReadBuildInfo() for ad-hoc
	// builds) before cobra renders --version.
	v := resolveVersion()
	suffix := ""
	if v.AdHoc {
		suffix = " (ad-hoc build)"
	}
	mod := ""
	if v.Modified {
		mod = " (modified)"
	}
	rootCmd.Version = fmt.Sprintf("%s%s (commit: %s%s, built: %s)", v.Version, suffix, v.Commit, mod, v.Built)

	cmdPath := "chainsaw"
	if cmd, _, err := rootCmd.Find(os.Args[1:]); err == nil && cmd != nil {
		cmdPath = cmd.CommandPath()
	}
	markSessionStart(cmdPath)
	defer flushTelemetry()

	assignCommandGroups()

	err := rootCmd.Execute()
	exitCode := ExitOK
	errClass := ""
	if err != nil {
		// A command may request a specific exit code via ExitCodeError
		// (e.g. `policy preflight` returns ExitBlocked when the printed
		// matrix has an unsupported cell, `admission soak clear` returns
		// ExitSoakNotCleared). That always wins.
		//
		// For a plain error we no longer blanket-map to 1. Instead we
		// classify it through the existing classifyCLIError buckets so an
		// operational failure (network/IO/internal) is distinguishable
		// from an enforcement block by exit code:
		//   auth/permission -> ExitConfigAuth(3)
		//   network/timeout -> ExitOpError(2)
		//   usage           -> ExitUsage(4)
		//   everything else -> ExitOpError(2)
		// Note: ExitBlocked(1) is reserved for the EXPECTED enforcement
		// outcome, which always arrives as an ExitCodeError{Code:1}; a
		// plain error never maps to 1 anymore.
		errClass = classifyCLIError(err)
		exitCode = exitCodeForClass(errClass)
		var coded *ExitCodeError
		if errors.As(err, &coded) && coded.Code != 0 {
			exitCode = coded.Code
		}
		renderError(err)
	}

	// P2.10 — emit at most a one-line "newer version available" hint to
	// stderr. Hard-gated and safe by default (no network on this path); see
	// update_notice.go. Called before the deferred flushTelemetry so the hint
	// never interleaves with session-completed bookkeeping.
	maybeNotifyUpdateAvailable()

	markSessionEnd(cmdPath, exitCode, errClass)

	if err != nil {
		os.Exit(exitCode)
	}
}

// exitCodeForClass maps a classifyCLIError bucket to the process exit code for
// a plain (non-ExitCodeError) error. See the exit-code contract in
// exitcodes.go. Operational failures land on ExitOpError(2) so they are never
// confused with an enforcement block (ExitBlocked(1)).
func exitCodeForClass(class string) int {
	switch class {
	case "auth", "permission":
		return ExitConfigAuth
	case "network", "timeout":
		return ExitOpError
	case "usage":
		return ExitUsage
	default:
		// "not_found", "other", and the empty bucket are all operational
		// from the process's point of view.
		return ExitOpError
	}
}

// renderError writes a user-facing error message to stderr. When the error
// is the structured CHW-NNNN envelope returned by the server (see
// internal/errcodes), it renders the code, message, reason, and docs URL
// on separate lines so the operator can find the catalog entry. For
// everything else it falls back to the plain Cobra-style "Error: ..." form.
//
// This replaces Cobra's default error print (suppressed via SilenceErrors
// on rootCmd) so we control formatting. The telemetry classifier in
// classifyCLIError continues to run alongside; it only consumes err.Error().
func renderError(err error) {
	if err == nil {
		return
	}
	// A message-less ExitCodeError (Code set, Err==nil) is the EXPECTED
	// enforcement-block signal: the user-facing reason (the findings table, the
	// "gate not cleared" line, etc.) was already printed by the command. Printing
	// "Error: exit 1" on top of that is a confusing artifact — stay silent and
	// let the exit code carry the outcome. (invariant B; keeps stdout/stderr
	// clean on the block path.)
	var coded *ExitCodeError
	if errors.As(err, &coded) && coded.Err == nil {
		return
	}
	var apiErr *apiError
	if errors.As(err, &apiErr) && strings.HasPrefix(apiErr.Code, "CHW-") {
		fmt.Fprintf(os.Stderr, "Error %s: %s\n", apiErr.Code, apiErr.Message)
		if apiErr.Reason != "" {
			fmt.Fprintf(os.Stderr, "  Reason: %s\n", apiErr.Reason)
		}
		if apiErr.Docs != "" {
			fmt.Fprintf(os.Stderr, "  Docs:   %s\n", apiErr.Docs)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "Error:", err)
	// Append a one-line remediation hint for the two buckets where a stock
	// next step is unambiguous. classifyCLIError is a pure function already
	// run for telemetry in Execute; calling it again here keeps renderError
	// self-contained (it consumes only err, per its godoc contract).
	switch classifyCLIError(err) {
	case "auth":
		fmt.Fprintln(os.Stderr, "  Hint: run `chainsaw auth login` to re-authenticate.")
	case "network":
		fmt.Fprintln(os.Stderr, "  Hint: check `chainsaw status` or your --server / CHAINSAW_SERVER setting.")
	}
}

// classifyCLIError returns a coarse error bucket so dashboards can group
// failures without leaking the actual message (which may carry paths,
// hostnames, or token fragments).
func classifyCLIError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "unauthorized") || strings.Contains(msg, "401"):
		return "auth"
	case strings.Contains(msg, "forbidden") || strings.Contains(msg, "403"):
		return "permission"
	case strings.Contains(msg, "not found") || strings.Contains(msg, "404"):
		return "not_found"
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline"):
		return "timeout"
	case strings.Contains(msg, "connection") || strings.Contains(msg, "refused"):
		return "network"
	case strings.Contains(msg, "unknown command") || strings.Contains(msg, "unknown flag"):
		return "usage"
	case strings.Contains(msg, "unknown shorthand flag") ||
		strings.Contains(msg, "arg(s)") || // cobra: "accepts N arg(s), received M"
		strings.Contains(msg, "requires at least") ||
		strings.Contains(msg, "requires exactly") ||
		strings.Contains(msg, "invalid argument") ||
		strings.Contains(msg, "flag needs an argument"):
		// Cobra's argument-count / flag-shape errors are usage errors, not
		// operational failures (invariant B: usage -> ExitUsage(4)).
		return "usage"
	}
	return "other"
}

func init() {
	cobra.OnInitialize(initConfig)

	// `chainsaw --version` prints a single line; the dedicated `version`
	// subcommand stays unchanged for richer output / JSON.
	rootCmd.SetVersionTemplate("chainsaw {{.Version}}\n")

	rootCmd.PersistentFlags().String("server", DefaultServer, "Server URL (overrides config; default baked at build via -X .../internal/cli.DefaultServer)")
	rootCmd.PersistentFlags().String("token", "", "Auth token (overrides config)")
	rootCmd.PersistentFlags().String("org", "", "Org ID (overrides config)")
	rootCmd.PersistentFlags().Bool("json", false, "Output JSON instead of human-readable text (alias for --format=json)")
	rootCmd.PersistentFlags().Bool("no-color", false, "Disable colored output")

	// P0.2 / P1.5 — output-control globals. --format selects the result
	// representation (table|json); --json stays as documented sugar for
	// --format=json (resolveFormat in output.go reconciles the two). --output
	// redirects the RESULT sink to a file while logs/progress stay on stderr.
	// --quiet/--verbose toggle chatter only — they MUST NEVER suppress a block
	// reason or change an exit code (see the guard invariant + its test).
	//
	// SECURITY (G1): every persistent flag added here MUST also be registered in
	// chainsawGlobalBoolFlags / chainsawGlobalValueFlags (guard_install.go) or a
	// guard subcommand (DisableFlagParsing) would leak it to the wrapped manager
	// / shift the install verb out of args[0] — a guard bypass. Part 1 already
	// listed --quiet/--verbose/--format/--output there; the regression test in
	// guard_globalflags_test.go enforces it.
	rootCmd.PersistentFlags().BoolP("quiet", "q", false, "Suppress progress/chatter (results and block reasons are still emitted)")
	rootCmd.PersistentFlags().BoolP("verbose", "v", false, "Emit extra diagnostic detail to stderr")
	rootCmd.PersistentFlags().String("format", "table", "Result format: table|json (--json is sugar for --format=json)")
	rootCmd.PersistentFlags().StringP("output", "o", "", "Write results to this file instead of stdout (logs/progress stay on stderr)")

	_ = viper.BindPFlag("server_url", rootCmd.PersistentFlags().Lookup("server"))
	_ = viper.BindPFlag("token", rootCmd.PersistentFlags().Lookup("token"))
	_ = viper.BindPFlag("org_id", rootCmd.PersistentFlags().Lookup("org"))

	// Back --quiet/--verbose with viper + env so precedence is flag > env. The
	// flag value flows through viper via BindPFlag; BindEnv supplies the env
	// fallback when the flag isn't set. CHAINSAW_VERBOSE already gates several
	// support logs directly via os.Getenv; binding it here is additive.
	_ = viper.BindPFlag("quiet", rootCmd.PersistentFlags().Lookup("quiet"))
	_ = viper.BindPFlag("verbose", rootCmd.PersistentFlags().Lookup("verbose"))
	_ = viper.BindEnv("quiet", "CHAINSAW_QUIET")
	_ = viper.BindEnv("verbose", "CHAINSAW_VERBOSE")
}

func initConfig() {
	migrateLegacyConfig()
	cfgFile := configFilePath()
	viper.SetConfigFile(cfgFile)
	viper.SetConfigType("yaml")
	viper.SetEnvPrefix("CHAINSAW")
	viper.AutomaticEnv()
	// AutomaticEnv with the "CHAINSAW" prefix auto-binds `server_url` to
	// `CHAINSAW_SERVER_URL`, but the help text, docs, and existing user
	// muscle memory all advertise `CHAINSAW_SERVER` (matches the `--server`
	// flag name). Bind it explicitly so env-driven configuration works
	// alongside --server / config / built-in default. Mirror of the implicit
	// CHAINSAW_TOKEN binding documented in cfgToken above.
	_ = viper.BindEnv("server_url", "CHAINSAW_SERVER")
	_ = viper.ReadInConfig()
	// no-color.org: NO_COLOR opts out when PRESENT, regardless of value (incl.
	// the empty string). Presence test, not a non-empty value test.
	if _, ok := os.LookupEnv("NO_COLOR"); ok {
		viper.Set("no_color", true)
	}
	migrateTokenToKeychain()
}

func configDir() string {
	return platform.ConfigHome()
}

func configFilePath() string {
	return filepath.Join(configDir(), "config.yaml")
}

func setupProgressPath() string {
	return filepath.Join(configDir(), ".setup_progress")
}

// cfgServerURL resolves the active server URL. Precedence (highest first):
//  1. --server flag (viper picks this up via BindPFlag)
//  2. CHAINSAW_SERVER env var (viper picks this up via the explicit
//     viper.BindEnv("server_url", "CHAINSAW_SERVER") in initConfig — the
//     AutomaticEnv prefix maps to CHAINSAW_SERVER_URL, not the documented
//     CHAINSAW_SERVER, so the explicit binding is what makes the env path work)
//  3. `server_url:` key in ~/.chainsaw/config.yaml
//  4. Built-in default baked at build time via -X .../internal/cli.DefaultServer
func cfgServerURL() string { return viper.GetString("server_url") }
func cfgOrgID() string     { return viper.GetString("org_id") }

// cfgToken resolves the active auth token. Precedence (highest first):
//  1. --token flag (viper picks this up via BindPFlag)
//  2. CHAINSAW_TOKEN env var (viper picks this up via AutomaticEnv)
//  3. `token:` key in ~/.chainsaw/config.yaml (legacy; new installs route through credstore)
//  4. OS keyring / file-store credential keyed by server URL
//
// The bug fix this docstring exists to pin: step 1 must win over step 4.
// A previous version of migrateTokenToKeychain treated the --token flag as a
// stale YAML token and clobbered it via viper.Set("token", ""), letting the
// keychain (step 4) silently override the explicit flag. See migrateTokenToKeychain
// for the InConfig-gated guard that keeps the flag honored.
func cfgToken() string {
	if tok := viper.GetString("token"); tok != "" {
		// Defensive support log: if the user explicitly passed --token (or
		// CHAINSAW_TOKEN) while a keychain entry exists for the same server,
		// note it so a support investigation can see the precedence at a glance.
		// Gated on CHAINSAW_VERBOSE to keep normal runs quiet — emitting on every
		// authenticated command would be noisy and could leak the existence of
		// stored credentials into shared terminals.
		if os.Getenv("CHAINSAW_VERBOSE") != "" {
			if server := cfgServerURL(); server != "" {
				if _, err := credStore().Get(credService, server); err == nil {
					fmt.Fprintf(os.Stderr,
						"chainsaw: --token / CHAINSAW_TOKEN set; ignoring keychain credential for %s\n",
						server)
				}
			}
		}
		return tok
	}
	server := cfgServerURL()
	if server == "" {
		return ""
	}
	tok, err := credStore().Get(credService, server)
	if err != nil {
		return ""
	}
	return tok
}

func newClient() *APIClient {
	return NewAPIClient(cfgServerURL(), cfgToken())
}

// saveConfig persists non-secret settings to YAML and routes the token to the
// credential store.
//
// This replaces all persisted state: pass empty strings to clear individual
// fields, and pass all-empty (serverURL, token, orgID all "") to log out
// entirely (clearConfig removes the YAML and any stored credential).
//
// A token can only be stored alongside a server URL (the credstore is keyed
// by server URL). Callers that try to store a token without a server receive
// an actionable error rather than having the token silently dropped.
func saveConfig(serverURL, token, orgID string) error {
	if serverURL == "" && token == "" && orgID == "" {
		return clearConfig()
	}
	if token != "" && serverURL == "" {
		return errors.New("chainsaw: a server URL is required to store an auth token; pass --server or run `chainsaw auth login` first")
	}
	if err := os.MkdirAll(configDir(), 0o700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	viper.Set("server_url", serverURL)
	viper.Set("org_id", orgID)
	// The token is never written to YAML; keep viper's in-memory view in sync
	// with the credential store so the current process sees the new value.
	viper.Set("token", "")

	if err := writeConfigYAML(); err != nil {
		return err
	}
	if token != "" && serverURL != "" {
		if err := credStore().Set(credService, serverURL, token); err != nil {
			return fmt.Errorf("store credential: %w", err)
		}
	}
	return nil
}

// clearConfig removes the credential and blanks viper so subsequent cfg* calls
// return empty. The YAML file itself is removed; if it does not exist we
// treat that as success.
func clearConfig() error {
	server := cfgServerURL()
	if server != "" {
		if err := credStore().Delete(credService, server); err != nil && !errors.Is(err, credstore.ErrNotFound) {
			return fmt.Errorf("delete credential: %w", err)
		}
	}
	viper.Set("token", "")
	viper.Set("server_url", "")
	viper.Set("org_id", "")
	if err := os.Remove(configFilePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove config: %w", err)
	}
	return nil
}

// writeConfigYAML marshals the non-secret subset of viper settings to the
// config file via secureio. We build the map explicitly (rather than using
// viper.AllSettings) to guarantee no secret key slips in.
func writeConfigYAML() error {
	settings := viper.AllSettings()
	delete(settings, "token")
	// client_secret is secret by intent; keep it out of YAML even though it's
	// not yet routed through credstore. Non-secret client_id stays.
	delete(settings, "client_secret")

	data, err := yaml.Marshal(settings)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := secureio.WriteFile(configFilePath(), data); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

// migrateTokenToKeychain runs on every initConfig. If YAML still carries a
// token (either from a pre-keychain install or from a hand-edited file), move
// it to the credential store and rewrite the YAML without the token key. If
// the credential store already holds a token, it wins — we still strip the
// YAML copy. Failures here never abort the CLI; we leave state untouched so
// the user isn't locked out.
//
// Precedence bug fix: this used to call viper.GetString("token") to detect a
// stale YAML token. But viper's BindPFlag means GetString returns the --token
// flag's value too, so passing `chainsaw --token X policy list` looked like a
// migration trigger — we'd write X into the keychain (or skip when one already
// existed) and then call viper.Set("token", "") at the bottom, which CLEARED
// the flag's value in viper. The result: --token was silently ignored and the
// keychain credential won. Gate the migration on viper.InConfig instead so we
// only fire when the token actually sits in the YAML config source.
func migrateTokenToKeychain() {
	// InConfig returns true only when the key is present in the parsed config
	// file. Flag values (via BindPFlag) and env values (via AutomaticEnv) do
	// not satisfy this check, which is exactly what we want — they must not
	// trigger a YAML-to-keychain migration.
	if !viper.InConfig("token") {
		return
	}
	tokenInYAML := viper.GetString("token")
	if tokenInYAML == "" {
		return
	}
	server := viper.GetString("server_url")
	if server == "" {
		return
	}
	store := credStore()
	existing, err := store.Get(credService, server)
	if err != nil && !errors.Is(err, credstore.ErrNotFound) {
		if os.Getenv("CHAINSAW_VERBOSE") != "" {
			fmt.Fprintf(os.Stderr, "chainsaw: keychain read failed during migration: %v\n", err)
		}
		return
	}
	if existing == "" {
		if err := store.Set(credService, server, tokenInYAML); err != nil {
			if os.Getenv("CHAINSAW_VERBOSE") != "" {
				fmt.Fprintf(os.Stderr, "chainsaw: keychain write failed during migration: %v\n", err)
			}
			return
		}
	}
	// Don't viper.Set("token", "") here: that has higher precedence than
	// BindPFlag and would clobber a --token flag passed on this same
	// invocation. writeConfigYAML already strips the token key from the YAML
	// it writes (see the delete(settings, "token") in that function), so the
	// migration goal — "remove the token from the YAML file" — is satisfied
	// without touching the in-memory viper state that the rest of the request
	// depends on.
	if err := writeConfigYAML(); err != nil {
		if os.Getenv("CHAINSAW_VERBOSE") != "" {
			fmt.Fprintf(os.Stderr, "chainsaw: rewriting config without token failed: %v\n", err)
		}
	}
}

// migrateLegacyConfig moves ~/.chainsaw/{config.yaml,.setup_progress} to the new
// platform location on first access. Silent by design: never fails the CLI and
// only reports diagnostics when CHAINSAW_VERBOSE is set. If the new path already
// holds a file, the legacy file is left untouched.
func migrateLegacyConfig() {
	legacy := platform.LegacyConfigHome()
	current := platform.ConfigHome()
	if legacy == "" || current == "" || legacy == current {
		return
	}
	for _, name := range []string{"config.yaml", ".setup_progress"} {
		src := filepath.Join(legacy, name)
		dst := filepath.Join(current, name)
		if err := moveIfAbsent(src, dst); err != nil {
			if os.Getenv("CHAINSAW_VERBOSE") != "" {
				fmt.Fprintf(os.Stderr, "chainsaw: config migration skipped for %s: %v\n", name, err)
			}
		}
	}
}

func moveIfAbsent(src, dst string) error {
	srcInfo, err := os.Stat(src)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if srcInfo.IsDir() {
		return nil
	}
	if _, err := os.Stat(dst); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := os.Rename(src, dst); err != nil {
		return err
	}
	return nil
}
