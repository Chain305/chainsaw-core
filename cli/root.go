package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
	Long: `Blocks typosquatted and known-malicious packages at install time — offline,
on this machine, with no account and no server.

Start here (nothing to sign up for):
  ` + "`chainsaw guard init --install`" + `   route npm/pip/go/cargo/gem through the guard
  ` + "`chainsaw npm install <pkg>`" + `     check one install by hand
  ` + "`chainsaw why npm <pkg>`" + `         explain any verdict
  ` + "`chainsaw doctor`" + `                read-only: what's wired, what isn't

Everything under GUARD, plus doctor / why / pr-scan / scan-repo / scan-actions,
runs entirely locally. The other groups are clients for a Chainsaw control plane
— policies, audit events, org settings, org-wide intelligence — and each says so
when none is configured. Connect one with ` + "`chainsaw setup`" + `, or
` + "`chainsaw auth login --device`" + ` for the headless / CI / AI-agent path.

New here? ` + "`chainsaw introduce`" + ` prints the mental models, modes and
vocabulary every Chainsaw surface (CLI, MCP, docs, landing page) shares.`,
	Version:       fmt.Sprintf("%s (commit: %s, built: %s)", Version, Commit, BuildDate),
	SilenceUsage:  true,
	SilenceErrors: true,
	PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
		if err := rejectPostSubcommandServerFlag(cmd, os.Args); err != nil {
			return err
		}
		return validateOutputFlags(cmd)
	},
}

// globalResultFormats is the vocabulary of the ROOT --format flag, exactly
// as its help text advertises ("Result format: table|json"). Matching is
// case-insensitive; resolveFormat already folds JSON/Json to "json".
var globalResultFormats = map[string]bool{"table": true, "json": true}

// extraCommandFormats lists the formats a command accepts ON TOP of the
// global table|json vocabulary, for commands that EXTEND the root --format
// inside their RunE instead of shadowing it with a local flag.
//
// B3 — `scan` and `pr-scan` both advertise sarif in --help and both
// implement it (writeScanSARIF / writePRScanSARIF), but neither declares a
// local --format, so ownsGlobalFlag reports them as owning the root's flag
// and the table|json check above rejected the very value the help text
// promises. `chainsaw scan lodash@4.17.21 --format sarif` exited 4 with
// "invalid --format" from v0.20.0 onward — a regression against v0.19.9,
// where the emitter was reachable.
//
// The fix is deliberately an ALLOWLIST rather than a local --format flag on
// those two commands: a local flag makes ownsGlobalFlag false, which opts
// the command out of ALL validation here, so `chainsaw scan --format bogus`
// would silently render a table at rc=0 again — the exact X10 defect this
// validator exists to close. Keys are cmd.CommandPath(); values are folded
// through strings.ToLower like the global set.
var extraCommandFormats = map[string]map[string]bool{
	"chainsaw scan":    {"sarif": true}, // emitted by writeScanSARIF, core/cli/scan.go
	"chainsaw pr-scan": {"sarif": true}, // emitted by writePRScanSARIF, core/cli/pr_scan.go
}

// supportedFormatsFor renders the accepted --format vocabulary for a command
// (the global set plus any per-command extras) for use in the error message,
// so a user who mistypes `--format sarf` on `scan` is told sarif is legal.
func supportedFormatsFor(cmd *cobra.Command) string {
	// Stable, human order: the two globals first, then the extras sorted.
	out := []string{"table", "json"}
	var extra []string
	for v := range extraCommandFormats[cmd.CommandPath()] {
		extra = append(extra, v)
	}
	sort.Strings(extra)
	return strings.Join(append(out, extra...), ", ")
}

// formatIsMachineReadable reports whether the RESOLVED --format for this
// command yields a machine-readable document that --output can meaningfully
// redirect to a file.
//
// B3 (second branch) — this used to be `useJSON(cmd)`, i.e. "json or
// nothing". That silently killed --output for EVERY other machine format,
// including on the eleven commands that shadow --format with vocabularies of
// their own. Verbatim-published invocations that stopped working:
//
//	chainsaw scan-actions . --format sarif --output chainsaw.sarif
//	chainsaw sbom export --format cyclonedx --output sbom.json
//	chainsaw audit export --format csv --output audit.csv
//	chainsaw policy export --format yaml --output policy.yaml
//
// A command that shadows --format owns a vocabulary this file cannot
// validate, and every one of those commands writes its result through a sink
// that honours --output (outWriter / outWriterOr), so the refusal is skipped
// for them wholesale — including their human-ish `text` format, which
// `report {exposure,multiversion,provenance,sla} --format text --output X`
// documents. What stays refused is the case the refusal was written for: a
// command on the GLOBAL vocabulary rendering the human table, whose
// renderers write to os.Stdout directly and take no sink.
func formatIsMachineReadable(cmd *cobra.Command) bool {
	if useJSON(cmd) {
		return true
	}
	if !ownsGlobalFlag(cmd, "format") {
		return true
	}
	f, _ := cmd.Flags().GetString("format")
	return extraCommandFormats[cmd.CommandPath()][strings.ToLower(strings.TrimSpace(f))]
}

// validateOutputFlags enforces the two contracts the global output flags
// advertise but never checked. Both failures are ExitUsage(4) — the user
// mistyped a flag, which is not an operational failure.
//
// 1. X10 — an unrecognized --format silently became `table`.
// `chainsaw --format=jsonl scan-repo .` and `--format=JSON5` both produced
// a human table at rc=0, so a pipeline piping that into jq got a parse
// error instead of a flag error.
//
// 2. R4 — --output/-o is a documented global ("Write results to this file
// instead of stdout") but the human/table renderers write to os.Stdout
// directly, so `chainsaw status -o out.txt` printed the full report to
// stdout and never created out.txt. The rejected alternative was threading
// a writer through the EXPORTED PrintTable: a breaking API change to a
// public open-core module across 22 call sites, to deliver table text to a
// file that nothing consumes. Refusing the combination tells the truth in
// ~15 lines; PrintTableTo can be added additively if a need ever appears.
//
// EXEMPTIONS — both checks are skipped for a command that declares its OWN
// --format flag (and the --output check is additionally skipped for a
// command declaring its own --output). Eleven commands shadow --format
// (audit export, policy export, policy lint, repo create, report ×4, sbom
// export, sbom diff, scan-actions) with vocabularies spanning csv/ndjson/
// yaml/sarif/text/cyclonedx/spdx; validating those against table|json would
// break every one of them, and their machine formats legitimately want the
// GLOBAL --output (scan-actions and the report family use it). Cobra's
// mergePersistentFlags keeps the LOCAL flag, so the identity test below (is
// this the root's own *pflag.Flag?) is exact.
//
// EXTENSIONS — a command may also accept extra formats without shadowing
// the flag at all (scan/pr-scan and sarif). Those are declared in
// extraCommandFormats above, which keeps them inside BOTH checks rather
// than opting them out.
//
// Guard wrappers (npm/pip/go/cargo/gem) and cargo-credentials run with
// DisableFlagParsing, so cobra never parses argv for them and every flag
// here reads its default. They would be exempt by accident; the explicit
// check below makes it deliberate — those commands forward argv untouched
// to the wrapped tool, and a `--format` intended for npm must never be
// rejected by chainsaw.
func validateOutputFlags(cmd *cobra.Command) error {
	if cmd == nil || cmd.DisableFlagParsing {
		return nil
	}
	if ownsGlobalFlag(cmd, "format") {
		f, _ := cmd.Flags().GetString("format")
		v := strings.ToLower(strings.TrimSpace(f))
		if f != "" && !globalResultFormats[v] && !extraCommandFormats[cmd.CommandPath()][v] {
			return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf(
				"invalid --format %q: supported values are %s (--json is sugar for --format=json)", f, supportedFormatsFor(cmd))}
		}
	}
	if !ownsGlobalFlag(cmd, "output") {
		return nil
	}
	path, _ := cmd.Flags().GetString("output")
	if path == "" {
		return nil
	}
	// --output only has a defined meaning for a machine-readable result;
	// the human table's renderers write to os.Stdout directly and take no
	// sink. See formatIsMachineReadable for what counts.
	if !formatIsMachineReadable(cmd) {
		// Name every machine format THIS command has, not just json — on
		// `scan` the honest answer includes sarif.
		alt := "--format=json"
		if extra := extraCommandFormats[cmd.CommandPath()]; len(extra) > 0 {
			names := []string{"json"}
			for v := range extra {
				names = append(names, v)
			}
			sort.Strings(names)
			alt = "--format=" + strings.Join(names, "|")
		}
		return &ExitCodeError{Code: ExitUsage, Err: fmt.Errorf(
			"--output is only supported with a machine-readable format; add --json (or %s), or redirect stdout with `> %s`", alt, path)}
	}
	return nil
}

// ownsGlobalFlag reports whether cmd sees the ROOT's persistent flag of
// this name rather than a local flag of its own that shadows it. Compares
// *pflag.Flag identity, which is what cobra's mergePersistentFlags
// preserves: an inherited flag is the very same pointer the root
// registered, a shadowing local flag is a different one.
//
// Resolved via cmd.Root() rather than the package-level rootCmd so this
// stays usable from a synthetic command tree in tests — and so root.go's
// var block doesn't form an initialization cycle through its own
// PersistentPreRunE.
func ownsGlobalFlag(cmd *cobra.Command, name string) bool {
	root := cmd.Root()
	if root == nil {
		return false
	}
	rf := root.PersistentFlags().Lookup(name)
	if rf == nil {
		return false
	}
	return cmd.Flags().Lookup(name) == rf
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
			// The two halves of the contract must agree. classifyCLIError
			// reads the error STRING, so a command that states its outcome
			// structurally — `return &ExitCodeError{Code: ExitUsage}` — lands
			// in the "other" bucket and reports error_class="other" alongside
			// exit_code=4. That is the same "reported two different ways"
			// split the X3/X4 note in classifyCLIError describes. When the
			// classifier has no opinion, take the class from the code the
			// command actually chose.
			if errClass == "" || errClass == "other" {
				if c := classForExitCode(coded.Code); c != "" {
					errClass = c
				}
			}
		}
		renderError(err)
	}

	// P2.10 — emit at most a one-line "newer version available" hint to
	// stderr. Hard-gated and safe by default (no network on this path); see
	// update_notice.go. Called before the deferred flushTelemetry so the hint
	// never interleaves with session-completed bookkeeping.
	maybeNotifyUpdateAvailable()

	markSessionEnd(cmdPath, exitCode, errClass)

	// R3: os.Exit below does NOT run deferred functions, so the deferred
	// flushTelemetry above never fired for a failing command — every
	// non-zero-exit invocation dropped its entire batch, including the
	// cli.session.completed carrying exit_code and error_class. Flush
	// explicitly here, after markSessionEnd has queued that event and
	// before the process leaves. flushTelemetry is safe to call twice (the
	// teardown half is sync.Once-guarded), so the defer stays as the
	// panic-path backstop.
	flushTelemetry()

	if err != nil {
		os.Exit(exitCode)
	}
}

// exitCodeForClass maps a classifyCLIError bucket to the process exit code for
// a plain (non-ExitCodeError) error. See the exit-code contract in
// exitcodes.go. Operational failures land on ExitOpError(2) so they are never
// confused with an enforcement block (ExitBlocked(1)).
// classForExitCode is the inverse of exitCodeForClass, used only to fill in a
// telemetry error_class that classifyCLIError could not infer from the message.
// It deliberately covers ONLY the cross-cutting 0–4 buckets: a command-specific
// code (>=10) means the command had its own outcome to report, and inventing a
// generic class for it would be less informative than leaving the classifier's
// answer alone. Returns "" when it has nothing to add.
func classForExitCode(code int) string {
	switch code {
	case ExitConfigAuth:
		return "auth"
	case ExitUsage:
		return "usage"
	case ExitOpError:
		return "other"
	default:
		return ""
	}
}

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
	// A mistyped or guessed verb (`chainsaw init`, `chainsaw login`,
	// `chainsaw get-started`, …) reaches cobra as an "unknown command" error.
	// Cobra's bare message (plus its sometimes-misleading "Did you mean")
	// leaves a brand-new user with no route forward, so append the canonical
	// start-here line. This is the "never leave them hanging" backstop for
	// every verb we don't (and can't) alias.
	if strings.Contains(err.Error(), "unknown command") {
		fmt.Fprintln(os.Stderr, "  New here? Run `chainsaw setup` (guided first-time setup) or")
		fmt.Fprintln(os.Stderr, "  `chainsaw introduce` (the concepts). `chainsaw --help` lists every command.")
		return
	}
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

// exactArgsWithUsage is cobra.ExactArgs(n) with a teaching error: on a count
// mismatch it prints the command's usage shape and a concrete example instead
// of cobra's bare "accepts N arg(s), received M", so a user who calls a command
// with the wrong number of positional args is never left guessing the shape.
// The "arg(s), received" fragment is preserved so classifyCLIError still buckets
// this as a usage error (ExitUsage=4).
func exactArgsWithUsage(n int, usage, example string) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) == n {
			return nil
		}
		return fmt.Errorf("accepts %d arg(s), received %d\n  usage:   %s\n  example: %s", n, len(args), usage, example)
	}
}

// classifyCLIError returns a coarse error bucket so dashboards can group
// failures without leaking the actual message (which may carry paths,
// hostnames, or token fragments).
func classifyCLIError(err error) string {
	if err == nil {
		return ""
	}
	// A1′: when the error carries the server's envelope, the HTTP status is
	// authoritative and substring matching is actively harmful. Before the
	// nested envelope was parsed, the raw JSON body landed in Message and
	// this function matched INSIDE it — measured: a 500 carrying CHW-5401
	// classified as "auth" and exited 3, so an internal server error
	// masqueraded as an auth failure and told the user to re-login.
	// Substring matching now applies ONLY to errors that are not *apiError.
	var ae *apiError
	if errors.As(err, &ae) && ae.Status != 0 {
		switch {
		case ae.Status == 401:
			return "auth"
		case ae.Status == 403:
			return "permission"
		case ae.Status == 404:
			return "not_found"
		}
		// Everything else (5xx, 409, 429, 4xx we don't bucket) is
		// operational from the process's point of view.
		return "other"
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "unauthorized") || strings.Contains(msg, "401"):
		return "auth"
	// X3/X4: the two locally-produced configuration failures. Without these
	// the exit code says ExitConfigAuth(3) while telemetry's errClass says
	// "other" — the same failure reported two different ways.
	case strings.Contains(msg, "server url not configured") ||
		strings.Contains(msg, "not authenticated"):
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
		// cobra: `required flag(s) "bundle", "input" not set` — the most
		// common argument-shape error in this CLI (14 commands declare a
		// required flag) and the one this switch was missing. Without it
		// `chainsaw policy gate pr` with no --bundle exited 2, telling CI
		// "infrastructure failure" for an incomplete invocation, while
		// `--nonexistent-flag` on the same command correctly exited 4.
		strings.Contains(msg, "not set") && strings.Contains(msg, "required flag") ||
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

	// The ldflags path in this help text is published verbatim on
	// docs.chain305.com/cli-reference/ by gen-cli-docs, so it has to name the
	// symbol that actually exists. It read `.../internal/cli.DefaultServer`
	// until the open-core split moved this package to core/ — a path no build
	// has been able to set since.
	rootCmd.PersistentFlags().String("server", DefaultServer, "Server URL (overrides config; default baked at build via -X github.com/chain305/chainsaw-core/cli.DefaultServer)")
	rootCmd.PersistentFlags().String("token", "", "Auth token (overrides config)")
	// A9: this used to read "Org ID (overrides config)", which every reader
	// took to mean "run this command against another org". It does NOT: no
	// request the CLI makes carries an org header or parameter, and that is
	// BY DESIGN — the server resolves the org from the token's identity and
	// 403s cross-org access for non-admins. Sending an org override would
	// 403 exactly the users who are confused today, and it touches the
	// tenancy boundary, so the FLAG is not the thing to change. The three
	// real consumers are all local: `status` display, the `org delete`
	// target, and a VEX document field in `sbom`.
	// Y7: the value placeholder here is pflag's, not prose. pflag's
	// UnquoteUsage consumes the FIRST back-quoted span in a usage string as
	// the flag's ARGUMENT NAME, so the old "`org delete` target" rendered
	// this persistent flag as `--org org delete` on all 143 help screens.
	// Single quotes keep the prose and let pflag fall back to the type name
	// ("--org string"). Never reintroduce backticks here.
	rootCmd.PersistentFlags().String("org", "", "Org ID used for LOCAL purposes only (status display, 'org delete' target, SBOM/VEX metadata). It is NOT sent to the server — your org is resolved from your token's identity.")
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

	// R6: --no-color was NOT bound, despite guardColorEnabled's comment
	// claiming it read the flag "surfaced via viper". Only the NO_COLOR env
	// var and a config-file key ever reached viper, so `chainsaw --no-color
	// npm install <pkg>` still emitted ANSI to stderr on a TTY — including
	// the block line, the single most important line the product prints —
	// while --no-color DID work on the stdout paths. Binding it here makes
	// the two streams agree. NO_COLOR keeps beating --no-color=false because
	// initConfig's viper.Set sits in the override tier above BindPFlag.
	_ = viper.BindPFlag("no_color", rootCmd.PersistentFlags().Lookup("no-color"))
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

	// A6 self-heal: strip any transient global that a PREVIOUS release baked
	// into config.yaml. Without this an operator who once ran `chainsaw
	// --quiet setup` stays quiet forever and has no obvious way back.
	//
	// viper.InConfig is what makes this safe: it is true ONLY when the key is
	// present in the parsed CONFIG FILE. A --quiet flag on this invocation
	// (BindPFlag) and CHAINSAW_QUIET (BindEnv) do not satisfy it, so this
	// cannot clobber a deliberate flag or env value. viper.Set neutralizes the
	// poisoned value for THIS run too (override tier beats the config tier),
	// which gives relief immediately rather than at the next login. Must run
	// BEFORE the NO_COLOR block below, so an actual NO_COLOR env var still
	// wins over a stale `no_color: true` we just cleared.
	stale := false
	for _, k := range transientGlobalKeys {
		if viper.InConfig(k) {
			viper.Set(k, false)
			stale = true
		}
	}
	if stale {
		// Best-effort: writeConfigYAML now drops these keys on the way out.
		// A failure here is not worth aborting the command over — the
		// in-memory Set above has already restored correct behavior.
		_ = writeConfigYAML()
	}

	// no-color.org: NO_COLOR opts out when PRESENT, regardless of value (incl.
	// the empty string). Presence test, not a non-empty value test.
	//
	// This viper.Set sits in the OVERRIDE tier, above BindPFlag — so NO_COLOR
	// deliberately still beats an explicit `--no-color=false`. That precedence
	// is correct (the env var is the ecosystem-wide opt-out) and is pinned by
	// test.
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
		// Gated on verbose (--verbose OR CHAINSAW_VERBOSE) to keep normal runs
		// quiet — emitting on every authenticated command would be noisy and
		// could leak the existence of stored credentials into shared terminals.
		// R7: this used to read os.Getenv directly, so the --verbose FLAG could
		// not reach it and CHAINSAW_VERBOSE=0 turned it ON.
		if verboseEnabled() {
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
	c := NewAPIClient(cfgServerURL(), cfgToken())
	// X4: every command that reaches for newClient() is an AUTHENTICATED
	// command. Opt this client into the token preflight so a missing token
	// fails fast at ExitConfigAuth(3) instead of going out unauthenticated
	// and coming back as a 401 the caller renders as an opaque failure.
	// NewAPIClient itself stays token-optional — see APIClient.requireToken.
	c.requireToken = true
	return c
}

// newClientWithTimeout is newClient with a caller-supplied overall HTTP
// timeout, for the few commands whose server call is legitimately long
// (scan can POST up to 10,000 packages and blocks while they are evaluated
// server-side, which the shared 30s default hard-caps with no override).
// NewAPIClient's 30s default is untouched for the ~40 other commands.
func newClientWithTimeout(timeout time.Duration) *APIClient {
	c := newAPIClientWithTimeout(cfgServerURL(), cfgToken(), timeout)
	c.requireToken = true
	return c
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

// transientGlobalKeys are the viper keys backed by per-invocation global
// FLAGS (or a per-invocation env signal). They describe how THIS run should
// behave, never durable configuration, so they must never be persisted.
//
// A6: writeConfigYAML snapshots viper.AllSettings(), which includes every
// pflag-bound key and every viper.Set override. One `chainsaw --quiet auth
// login` therefore baked `quiet: true` into config.yaml and made EVERY
// later invocation quiet forever, with no obvious undo (`--quiet=false`
// works; omitting --quiet does not). Same for --verbose and for NO_COLOR,
// which initConfig turns into viper.Set("no_color", true). The trigger is
// worse than "on login": migrateTokenToKeychain calls writeConfigYAML on
// the first run after ANY upgrade that still has a YAML token, so transient
// flags from that unrelated invocation get baked with no login involved.
//
// DENYLIST, not allowlist. The tempting fix — "build the map explicitly
// from server_url/org_id, as the comment already promises" — would DELETE a
// user's hand-authored `cargo_credentials:` key, which the CLI reads
// (cargo_credentials.go, lookupCargoCredentials) but never writes and
// documents as a supported hand-edited fallback.
var transientGlobalKeys = []string{"quiet", "verbose", "no_color"}

// writeConfigYAML marshals the non-secret, non-transient subset of viper
// settings to the config file via secureio.
func writeConfigYAML() error {
	settings := viper.AllSettings()
	delete(settings, "token")
	// client_secret is secret by intent; keep it out of YAML even though it's
	// not yet routed through credstore. Non-secret client_id stays.
	delete(settings, "client_secret")
	// A6 — see transientGlobalKeys. Unknown keys (e.g. a hand-authored
	// cargo_credentials) are deliberately preserved.
	for _, k := range transientGlobalKeys {
		delete(settings, k)
	}

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
		if verboseEnabled() {
			fmt.Fprintf(os.Stderr, "chainsaw: keychain read failed during migration: %v\n", err)
		}
		return
	}
	if existing == "" {
		if err := store.Set(credService, server, tokenInYAML); err != nil {
			if verboseEnabled() {
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
		if verboseEnabled() {
			fmt.Fprintf(os.Stderr, "chainsaw: rewriting config without token failed: %v\n", err)
		}
	}
}

// migrateLegacyConfig moves ~/.chainsaw/{config.yaml,.setup_progress} to the new
// platform location on first access. Silent by design: never fails the CLI and
// only reports diagnostics under --verbose / CHAINSAW_VERBOSE. If the new path already
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
			if verboseEnabled() {
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
