package cli

// cargo_credentials.go ships the `chainsaw cargo-credentials` subcommand,
// a Cargo credential-provider helper that lets `cargo fetch` /
// `cargo build` authenticate to a Chainsaw sparse-protocol crate
// proxy on cargo 1.74+ (verified against 1.78 and 1.88).
//
// Why this exists
// ───────────────
// The legacy "embed creds in the registry URL"
// (sparse+https://user:pass@host/...) form works for the index call
// but cargo STRIPS embedded credentials when downloading the .crate
// artifacts that the index points at — those go to a separate URL.
// The fix in cargo 1.74+ is to use the credential-provider protocol,
// which lets us inject an Authorization header on every request.
//
// What the customer pastes into ~/.cargo/config.toml
// ─────────────────────────────────────────────────────
//
//   [registry]
//   global-credential-providers = ["chainsaw-cargo", "cargo:token"]
//
//   [credential-alias]
//   chainsaw-cargo = ["chainsaw"]
//
//   [source.crates-io]
//   replace-with = "chainsaw"
//
//   [source.chainsaw]
//   registry = "sparse+https://chain305.com/chainproxy/repository/@your-org/crates-io/"
//
//   # The credential-provider must also be pinned on the replacement
//   # registry so cargo's index-URL → registry lookup finds it on
//   # the .crate download path too. The mismatch where it's only
//   # attached to [registries.crates-io] is the most common wiring
//   # mistake (the user explicitly flagged it as "the gotcha"):
//   # cargo's source-replacement resolver picks the REPLACEMENT name
//   # ("chainsaw" below), not the original "crates-io".
//   [registries.chainsaw]
//   credential-provider = ["chainsaw"]
//
// Critically: the array contains EXACTLY ONE element — the chainsaw
// executable path. cargo discards any further array elements (does
// NOT forward them as argv) and only appends `--cargo-plugin`. We
// detect that flag at the binary's main entry (internal/cli/root.go
// Execute) and dispatch to the protocol loop before cobra parses
// anything. Adding a "cargo-credentials" sub-arg in the config array
// would be silently dropped by cargo and break the wiring.
//
// Protocol
// ────────
// Cargo invokes the provider with `--cargo-plugin` and communicates
// over newline-delimited JSON on stdin/stdout. The provider:
//   1. Emits a hello: {"v":[1]}
//   2. Reads a request (one JSON object per line)
//   3. Emits a response wrapped in {"Ok":{...}} or {"Err":{...}}
//   4. Exits when stdin closes
//
// Supported request kinds:
//   - "get": return Basic <b64(client_id:client_secret)>. cargo sends
//     this verbatim as the Authorization header on both index and
//     .crate artifact downloads.
//   - "login" / "logout" / unknown: respond with
//     {"Err":{"kind":"operation-not-supported"}} so cargo can fall
//     through to another provider rather than treat it as a fatal error.
//
// Credential lookup precedence (highest first)
// ────────────────────────────────────────────
//  1. CHAINSAW_CARGO_CREDENTIALS env var (a "client_id:client_secret"
//     pair; cargo-specific so CI jobs can scope cargo separately from
//     pip/npm).
//  2. CHAINSAW_CLIENT_CREDENTIALS env var (the generic chainsaw
//     client_credential used by other ecosystems; reused so a single
//     CI secret covers every registry).
//  3. OS keyring under service "chainsaw", account
//     "cargo-credentials@<server>" — populated by
//     `chainsaw cargo-credentials store`.
//  4. ~/.chainsaw/config.yaml `cargo_credentials:` key (plaintext;
//     enforced 0600 file mode on read).
//
// Errors are sent to cargo as {"Err":{"kind":"other","message":"..."}}
// so cargo surfaces a real diagnostic instead of a generic "credential
// provider failed". This is the difference between "I can fix my
// config" and "rerun with -v to see what broke".

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/chain305/chainsaw-core/cli/credstore"
)

// cargoCredsKeyringAccount is the account string under credService
// ("chainsaw") that holds a cargo-specific client_credential. Distinct
// from the API-bearer-token account (the server URL) so the two never
// collide. The "@<server>" suffix keeps multi-profile users honest —
// you can have a cargo credential per Chainsaw instance.
func cargoCredsKeyringAccount(server string) string {
	if server == "" {
		return "cargo-credentials"
	}
	return "cargo-credentials@" + server
}

// cargoCredentialsCmd registers `chainsaw cargo-credentials`. We disable
// flag parsing because cargo invokes us with `--cargo-plugin`, which
// cobra would otherwise reject as an unknown flag. The protocol itself
// is positional/JSON-based, so we have nothing to gain from cobra's
// flag machinery on the hot path.
//
// The "store", "clear", and "status" sub-verbs DO use flag parsing —
// each one re-enables it on its own subcommand.
func cargoCredentialsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cargo-credentials",
		Short: "Cargo credential-provider helper (store / clear / status; cargo itself invokes the binary via --cargo-plugin)",
		Long: `Cargo credential-provider helper for the Chainsaw crate proxy.

Cargo 1.74+ uses the credential-provider protocol to inject auth on
every registry request — including .crate artifact downloads, which
strip URL-embedded credentials.

Wire the helper into ~/.cargo/config.toml:

  [registry]
  global-credential-providers = ["chainsaw-cargo", "cargo:token"]

  [credential-alias]
  chainsaw-cargo = ["chainsaw"]

  [source.crates-io]
  replace-with = "chainsaw"

  [source.chainsaw]
  registry = "sparse+https://<server>/chainproxy/repository/@<org>/crates-io/"

  [registries.chainsaw]
  credential-provider = ["chainsaw"]

The credential-provider array contains EXACTLY ONE element (the
chainsaw executable). Cargo discards any further elements and only
appends --cargo-plugin. We detect that flag at process start and
route directly to the protocol loop — running ` + "`chainsaw cargo-credentials`" + `
as a subcommand is a HUMAN-ONLY surface (store / clear / status),
not the path cargo uses.

The credential-provider attaches to [registries.chainsaw] (the
REPLACEMENT source's name), not [registries.crates-io] — cargo's
source-replacement resolver uses the replacement name for credential
lookup. Configuring it on [registries.crates-io] is the most common
wiring mistake and silently no-ops.

Sub-verbs:
  chainsaw cargo-credentials store    Save a client_id:client_secret in the keyring
  chainsaw cargo-credentials status   Show which source is providing credentials
  chainsaw cargo-credentials clear    Remove the stored credential

See docs/integrations/cargo.md for the full setup recipe.`,
		// DisableFlagParsing lets cargo pass --cargo-plugin without
		// cobra erroring. The sub-verbs below override this by being
		// real subcommands cargo never calls.
		DisableFlagParsing: true,
		SilenceUsage:       true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Route to a sub-verb when invoked by a human. Cargo only
			// ever passes --cargo-plugin or nothing, never one of our
			// verbs, so this branch is safe.
			for _, a := range args {
				switch a {
				case "store":
					return runCargoCredsStore(cmd, args)
				case "clear":
					return runCargoCredsClear(cmd, args)
				case "status":
					return runCargoCredsStatus(cmd, args)
				case "--help", "-h":
					return cmd.Help()
				}
			}
			return runCargoCredsProtocol(cmd, os.Stdin, cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	return cmd
}

func init() {
	rootCmd.AddCommand(cargoCredentialsCmd())
}

// ── Protocol loop ─────────────────────────────────────────────────────────────

// cargoHello is the version-handshake the provider emits first.
type cargoHello struct {
	V []int `json:"v"`
}

// cargoRequest captures the fields we care about across "get", "login",
// "logout" requests. Unknown fields are tolerated (json.Decoder is
// lenient by default) so future protocol additions don't break us.
type cargoRequest struct {
	V        int             `json:"v"`
	Kind     string          `json:"kind"`
	Op       string          `json:"operation,omitempty"`
	Registry json.RawMessage `json:"registry,omitempty"`
	Args     []string        `json:"args,omitempty"`
}

// cargoOkGet is the success payload for "get" requests. cache:"session"
// means cargo will keep the token for the lifetime of one cargo
// process — repeated `cargo build` calls re-invoke the helper once
// per process, not once per artifact, which matches the protocol's
// intent and keeps our helper cheap.
//
// operation_independent:true says "the same token works for read and
// publish" — true for us; publish goes through the same Basic auth.
type cargoOkGet struct {
	Kind                 string `json:"kind"`
	Token                string `json:"token"`
	Cache                string `json:"cache"`
	OperationIndependent bool   `json:"operation_independent"`
}

// cargoErr is the error envelope cargo recognises. "operation-not-supported"
// is the canonical kind for login/logout/etc when a provider is read-only;
// "other" carries a free-form message for actionable diagnostics.
type cargoErr struct {
	Kind    string `json:"kind"`
	Message string `json:"message,omitempty"`
}

// runCargoCredsProtocol implements the credential-provider loop. Split
// out of the cobra RunE so tests can drive it with synthetic stdin/stdout
// instead of process pipes.
func runCargoCredsProtocol(cmd *cobra.Command, in io.Reader, out io.Writer, errOut io.Writer) error {
	enc := json.NewEncoder(out)
	// Step 1: emit the hello so cargo learns we speak protocol v1.
	if err := enc.Encode(cargoHello{V: []int{1}}); err != nil {
		return fmt.Errorf("emit hello: %w", err)
	}

	scanner := bufio.NewScanner(in)
	// Default Scanner buffer is 64KB; that's plenty for cargo requests
	// but bump the cap to 1MB so a future protocol expansion (e.g. a
	// large headers array) can't cause silent truncation. Truncation is
	// the worst failure mode here because the helper would then emit a
	// successful response to a malformed request and the user would see
	// a 401 with no breadcrumb.
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := bytes_trim_space(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var req cargoRequest
		if err := json.Unmarshal(line, &req); err != nil {
			_ = enc.Encode(map[string]cargoErr{"Err": {Kind: "other", Message: "malformed request JSON: " + err.Error()}})
			continue
		}
		switch req.Kind {
		case "get":
			tok, err := resolveCargoCredentialToken()
			if err != nil {
				_ = enc.Encode(map[string]cargoErr{"Err": {Kind: "other", Message: err.Error()}})
				continue
			}
			_ = enc.Encode(map[string]cargoOkGet{"Ok": {
				Kind:                 "get",
				Token:                tok,
				Cache:                "session",
				OperationIndependent: true,
			}})
		case "login", "logout":
			// We don't mint or revoke creds via cargo — those flow
			// through `chainsaw auth client create` / `delete`.
			_ = enc.Encode(map[string]cargoErr{"Err": {Kind: "operation-not-supported"}})
		default:
			_ = enc.Encode(map[string]cargoErr{"Err": {Kind: "operation-not-supported", Message: "unsupported kind: " + req.Kind}})
		}
	}
	if err := scanner.Err(); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("read protocol: %w", err)
	}
	return nil
}

// bytes_trim_space mirrors strings.TrimSpace for a byte slice without
// pulling bytes.TrimSpace into the top imports. Kept inline because
// it's a one-liner and avoids inflating the import list.
func bytes_trim_space(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\t' || b[start] == '\n' || b[start] == '\r') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\n' || b[end-1] == '\r') {
		end--
	}
	return b[start:end]
}

// ── Credential resolution ─────────────────────────────────────────────────────

// resolveCargoCredentialToken walks the precedence chain and returns a
// fully-formed "Basic <b64>" token suitable for the Authorization
// header. The error path returns a defensive message that tells the
// user EXACTLY which sources were consulted — debugging this in the
// wild without that breadcrumb is awful.
func resolveCargoCredentialToken() (string, error) {
	creds, source := lookupCargoCredentials()
	if creds == "" {
		return "", errors.New(
			"no Chainsaw client_credential available. Tried (in order): " +
				"CHAINSAW_CARGO_CREDENTIALS env, CHAINSAW_CLIENT_CREDENTIALS env, " +
				"OS keyring (chainsaw/cargo-credentials@<server>), " +
				"~/.chainsaw/config.yaml cargo_credentials. " +
				"Fix: run `chainsaw cargo-credentials store --client-id ... --client-secret ...` " +
				"or set CHAINSAW_CARGO_CREDENTIALS=client_id:client_secret.")
	}
	id, secret, ok := splitCargoCreds(creds)
	if !ok {
		return "", fmt.Errorf(
			"credential from %s is not in the expected \"client_id:client_secret\" form", source)
	}
	enc := base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
	return "Basic " + enc, nil
}

// lookupCargoCredentials walks every source and returns the first hit.
// The second return value names the source — exposed so error messages
// can say "credential from <source> was malformed" instead of
// "credential was malformed".
func lookupCargoCredentials() (creds, source string) {
	if v := strings.TrimSpace(os.Getenv("CHAINSAW_CARGO_CREDENTIALS")); v != "" {
		return v, "CHAINSAW_CARGO_CREDENTIALS env"
	}
	if v := strings.TrimSpace(os.Getenv("CHAINSAW_CLIENT_CREDENTIALS")); v != "" {
		return v, "CHAINSAW_CLIENT_CREDENTIALS env"
	}
	// Keyring under chainsaw/cargo-credentials@<server>. Server may
	// be empty (legitimate when the user hasn't run `chainsaw auth
	// login` yet but did run `cargo-credentials store`) — the account
	// degrades to "cargo-credentials" cleanly.
	server := strings.TrimSpace(viper.GetString("server_url"))
	if v, err := credStore().Get(credService, cargoCredsKeyringAccount(server)); err == nil && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v), "OS keyring"
	}
	// YAML fallback — read directly from viper. If the value is set
	// in YAML the user has accepted plaintext-on-disk; we don't
	// double-check file perms here because the file is already
	// machine-readable to the user.
	if v := strings.TrimSpace(viper.GetString("cargo_credentials")); v != "" {
		return v, "~/.chainsaw/config.yaml cargo_credentials"
	}
	return "", ""
}

// splitCargoCreds parses "client_id:client_secret". A duplicate of
// hook.splitCreds because internal/cli/hook is a child package and
// importing it from internal/cli would invert the dependency direction
// (and pull in cobra-less hook code we don't need). The implementation
// is identical — keep it that way if you ever edit one.
func splitCargoCreds(raw string) (id, secret string, ok bool) {
	parts := strings.SplitN(strings.TrimSpace(raw), ":", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	id = strings.TrimSpace(parts[0])
	secret = strings.TrimSpace(parts[1])
	if id == "" || secret == "" {
		return "", "", false
	}
	return id, secret, true
}

// ── Sub-verbs: store / clear / status ─────────────────────────────────────────
//
// These are invoked by the human, not cargo. Each one re-enables flag
// parsing on its own subcommand by being a real cobra subcommand
// underneath the protocol-only parent. cobra dispatches on positional
// args during the parent's DisableFlagParsing path (see RunE above).

func runCargoCredsStore(cmd *cobra.Command, _ []string) error {
	// We do flag parsing manually here because the parent disabled it.
	// The supported invocations are:
	//   chainsaw cargo-credentials store --client-id X --client-secret Y
	//   chainsaw cargo-credentials store X:Y
	// The second form is convenient for shell history users; the first
	// avoids leaking the secret into argv on systems where /proc/*/cmdline
	// is world-readable.
	argv := cmd.Flags().Args()
	// cmd.Flags().Args() is empty when DisableFlagParsing is on; use
	// os.Args directly. The shape we expect: "chainsaw cargo-credentials store ..."
	// Find the "store" token and read everything after it.
	var rest []string
	saw := false
	for _, a := range os.Args[1:] {
		if !saw {
			if a == "store" {
				saw = true
			}
			continue
		}
		rest = append(rest, a)
	}
	_ = argv

	var clientID, clientSecret, pair string
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "--client-id":
			if i+1 < len(rest) {
				clientID = rest[i+1]
				i++
			}
		case "--client-secret":
			if i+1 < len(rest) {
				clientSecret = rest[i+1]
				i++
			}
		default:
			if pair == "" && strings.Contains(rest[i], ":") {
				pair = rest[i]
			}
		}
	}
	if pair == "" && clientID != "" && clientSecret != "" {
		pair = clientID + ":" + clientSecret
	}
	if pair == "" {
		return errors.New("usage: chainsaw cargo-credentials store --client-id <id> --client-secret <secret>")
	}
	if _, _, ok := splitCargoCreds(pair); !ok {
		return errors.New("credential must be \"client_id:client_secret\" with both halves non-empty")
	}
	server := strings.TrimSpace(viper.GetString("server_url"))
	if err := credStore().Set(credService, cargoCredsKeyringAccount(server), pair); err != nil {
		return fmt.Errorf("store credential: %w", err)
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Stored cargo credential for %s.\n", displayServer(server))
	fmt.Fprintln(cmd.ErrOrStderr(), "Cargo will pick it up automatically when `credential-provider = [\"chainsaw\", \"cargo-credentials\"]` is set under [registries.chainsaw].")
	return nil
}

func runCargoCredsClear(cmd *cobra.Command, _ []string) error {
	server := strings.TrimSpace(viper.GetString("server_url"))
	err := credStore().Delete(credService, cargoCredsKeyringAccount(server))
	if err != nil && !errors.Is(err, credstore.ErrNotFound) {
		return fmt.Errorf("delete credential: %w", err)
	}
	if errors.Is(err, credstore.ErrNotFound) {
		fmt.Fprintf(cmd.ErrOrStderr(), "No cargo credential stored for %s.\n", displayServer(server))
		return nil
	}
	fmt.Fprintf(cmd.ErrOrStderr(), "Cleared cargo credential for %s.\n", displayServer(server))
	return nil
}

func runCargoCredsStatus(cmd *cobra.Command, _ []string) error {
	creds, source := lookupCargoCredentials()
	if creds == "" {
		fmt.Fprintln(cmd.OutOrStdout(), "Status: NO credential available.")
		fmt.Fprintln(cmd.OutOrStdout(), "Cargo would receive an error response on the next `cargo fetch`.")
		fmt.Fprintln(cmd.OutOrStdout(), "Fix: chainsaw cargo-credentials store --client-id <id> --client-secret <secret>")
		return nil
	}
	id, _, ok := splitCargoCreds(creds)
	if !ok {
		fmt.Fprintf(cmd.OutOrStdout(), "Status: MALFORMED credential from %s (not client_id:client_secret).\n", source)
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Status: OK\n")
	fmt.Fprintf(cmd.OutOrStdout(), "Source: %s\n", source)
	fmt.Fprintf(cmd.OutOrStdout(), "Client: %s (secret hidden)\n", id)
	return nil
}

func displayServer(s string) string {
	if s == "" {
		return "<no server configured>"
	}
	return s
}
