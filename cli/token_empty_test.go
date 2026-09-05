package cli

// token_empty_test.go — Phase 9 fresh QA, A2.
//
// A present-but-EMPTY `--token ""` / `CHAINSAW_TOKEN=` used to be
// indistinguishable from "no override at all": viper folds both to "", and
// cfgToken then consulted the keyring. So an operator who exported an empty
// CHAINSAW_TOKEN to run anonymously (or a CI job whose secret was unset) was
// silently authenticated with whatever credential the machine had stored.
//
// The contract pinned here: present-but-empty means "no credential; do NOT
// consult the keyring". cfgToken returns "" (the anonymous signal its ~25
// callers already understand) and never errors, so anonymous-capable commands
// keep working; the AUTHENTICATED path (requireAuth / the APIClient.do
// preflight) exits ExitConfigAuth with a message that names the empty
// override instead of the generic "not authenticated".

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

const tokenEmptyMessage = "--token / CHAINSAW_TOKEN is set but empty; refusing to fall back to the stored credential (unset it, or pass a value)"

// seededServerForEmptyToken seeds the file credstore with a PAT for a live
// httptest server and returns the server URL plus a pointer to the number of
// requests it received. Any request at all means the stored credential was
// consulted — the thing this file forbids.
func seededServerForEmptyToken(t *testing.T) (string, *int) {
	t.Helper()
	withIsolatedConfigHome(t)
	store := withFileCredStore(t)
	rebindRootFlagsAfterReset(t)
	unsetEnv(t, "CHAINSAW_TOKEN")

	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"policies":[]}`))
	}))
	t.Cleanup(srv.Close)

	if err := store.Set(credService, srv.URL, "stored-pat-must-not-be-used"); err != nil {
		t.Fatalf("seed credstore: %v", err)
	}
	return srv.URL, &hits
}

func assertEmptyTokenRefused(t *testing.T, err error, hits int) {
	t.Helper()
	if err == nil {
		t.Fatal("an authenticated command ran with an empty --token / CHAINSAW_TOKEN; it must refuse")
	}
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != ExitConfigAuth {
		t.Fatalf("err = %v, want ExitCodeError{Code: ExitConfigAuth(3)}", err)
	}
	if !strings.Contains(err.Error(), tokenEmptyMessage) {
		t.Fatalf("err = %q, want the empty-override message %q", err.Error(), tokenEmptyMessage)
	}
	if hits != 0 {
		t.Fatalf("the server received %d request(s): the stored credential was used despite the empty override", hits)
	}
}

// TestEmptyTokenFlag_DoesNotFallBackToKeyring: `chainsaw --token "" policy list`
// with a stored PAT for that server must NOT use the PAT.
func TestEmptyTokenFlag_DoesNotFallBackToKeyring(t *testing.T) {
	server, hits := seededServerForEmptyToken(t)

	rootCmd.SetArgs([]string{"--server", server, "--token", "", "policy", "list"})
	var err error
	captureStdout(t, func() { err = rootCmd.Execute() })
	assertEmptyTokenRefused(t, err, *hits)
}

// TestEmptyTokenEnv_DoesNotFallBackToKeyring: same contract for
// `CHAINSAW_TOKEN= chainsaw policy list`.
func TestEmptyTokenEnv_DoesNotFallBackToKeyring(t *testing.T) {
	server, hits := seededServerForEmptyToken(t)
	t.Setenv("CHAINSAW_TOKEN", "")

	rootCmd.SetArgs([]string{"--server", server, "policy", "list"})
	var err error
	captureStdout(t, func() { err = rootCmd.Execute() })
	assertEmptyTokenRefused(t, err, *hits)
}

// TestEmptyTokenEnv_WhitespaceCountsAsEmpty: `CHAINSAW_TOKEN="  "` is the same
// mistake with a shell quoting accident on top; it must not reach the keyring.
func TestEmptyTokenEnv_WhitespaceCountsAsEmpty(t *testing.T) {
	server, hits := seededServerForEmptyToken(t)
	t.Setenv("CHAINSAW_TOKEN", "   ")

	rootCmd.SetArgs([]string{"--server", server, "policy", "list"})
	var err error
	captureStdout(t, func() { err = rootCmd.Execute() })
	assertEmptyTokenRefused(t, err, *hits)
}

// TestEmptyTokenEnv_RequireAuthNamesTheOverride: the early guard destructive
// verbs call (requireAuth) must say the same thing as the transport preflight,
// so the two remain indistinguishable to a caller.
func TestEmptyTokenEnv_RequireAuthNamesTheOverride(t *testing.T) {
	server, _ := seededServerForEmptyToken(t)
	t.Setenv("CHAINSAW_TOKEN", "")

	var got error
	probe := &cobra.Command{
		Use: "__empty_token_probe",
		RunE: func(cmd *cobra.Command, _ []string) error {
			got = requireAuth(cmd)
			return nil
		},
	}
	rootCmd.AddCommand(probe)
	t.Cleanup(func() { rootCmd.RemoveCommand(probe) })

	rootCmd.SetArgs([]string{"--server", server, "__empty_token_probe"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	assertEmptyTokenRefused(t, got, 0)

	c := newClient()
	c.baseURL = "http://127.0.0.1:1"
	transportErr := c.Get("/api/anything", nil)
	if transportErr == nil || transportErr.Error() != got.Error() {
		t.Fatalf("requireAuth says %q but the transport says %v; they must match", got, transportErr)
	}
}

// TestEmptyTokenEnv_AnonymousCommandStillRuns is the negative control that
// justified the design: cfgToken returns "" rather than erroring, so a
// command that is happy anonymous (`status`) still runs, reports "no token
// configured", exits 0 — and never touches the stored credential.
func TestEmptyTokenEnv_AnonymousCommandStillRuns(t *testing.T) {
	server, hits := seededServerForEmptyToken(t)
	t.Setenv("CHAINSAW_TOKEN", "")

	rootCmd.SetArgs([]string{"--server", server, "status"})
	var err error
	stdout := captureStdout(t, func() { err = rootCmd.Execute() })
	if err != nil {
		t.Fatalf("status must run anonymously with an empty CHAINSAW_TOKEN; err = %v", err)
	}
	if !strings.Contains(stdout, "no token configured") {
		t.Fatalf("stdout = %q, want the anonymous 'no token configured' line", stdout)
	}
	// /healthz is anonymous and expected; /api/auth/me would mean the stored
	// PAT was picked up.
	if *hits > 1 {
		t.Fatalf("server saw %d requests; the stored credential was consulted", *hits)
	}
}

// TestEmptyTokenEnv_DoctorStrictExitsOnItsOwnLadder: the plan's stated
// negative. `doctor --strict` with an empty CHAINSAW_TOKEN and no server must
// exit on the doctor ladder (0/1/10/30/40), never on ExitConfigAuth, and never
// with the empty-override message.
func TestEmptyTokenEnv_DoctorStrictExitsOnItsOwnLadder(t *testing.T) {
	withHookEnv(t)
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	rebindRootFlagsAfterReset(t)
	withStubbedEgress(t, "unknown")
	t.Setenv("CHAINSAW_TOKEN", "")

	rootCmd.SetArgs([]string{"doctor", "--strict", "--no-egress-probe"})
	var err error
	captureStdout(t, func() { err = rootCmd.Execute() })
	if err == nil {
		return // exit 0 on the ladder is fine
	}
	var coded *ExitCodeError
	if errors.As(err, &coded) && coded.Code == ExitConfigAuth {
		t.Fatalf("doctor --strict exited ExitConfigAuth with an empty CHAINSAW_TOKEN: %v", err)
	}
	if strings.Contains(err.Error(), "set but empty") {
		t.Fatalf("doctor --strict surfaced the empty-override message: %v", err)
	}
}

// TestTokenFlag_RealValueBeatsEmptyEnvAndKeyring: an explicit non-empty
// --token still wins over both a present-but-empty CHAINSAW_TOKEN and the
// keyring. The empty-override rule must not demote a real flag.
func TestTokenFlag_RealValueBeatsEmptyEnvAndKeyring(t *testing.T) {
	server, _ := seededServerForEmptyToken(t)
	t.Setenv("CHAINSAW_TOKEN", "")

	var captured string
	probe := &cobra.Command{
		Use: "__real_token_probe",
		RunE: func(cmd *cobra.Command, _ []string) error {
			captured = cfgToken()
			return nil
		},
	}
	rootCmd.AddCommand(probe)
	t.Cleanup(func() { rootCmd.RemoveCommand(probe) })

	rootCmd.SetArgs([]string{"--server", server, "--token", "flag-token-real", "__real_token_probe"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if captured != "flag-token-real" {
		t.Fatalf("cfgToken() = %q, want the explicit --token value", captured)
	}
}

// TestTokenExplicitlyEmpty_NotTrippedByAbsentOverride: with neither the flag
// nor the env var present, the predicate is false and the keyring is used —
// the pre-A2 behaviour every stored-credential user relies on.
func TestTokenExplicitlyEmpty_NotTrippedByAbsentOverride(t *testing.T) {
	server, _ := seededServerForEmptyToken(t)

	var captured string
	probe := &cobra.Command{
		Use: "__absent_override_probe",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if tokenExplicitlyEmpty(cmd) {
				t.Error("tokenExplicitlyEmpty is true with no --token and no CHAINSAW_TOKEN")
			}
			captured = cfgToken()
			return nil
		},
	}
	rootCmd.AddCommand(probe)
	t.Cleanup(func() { rootCmd.RemoveCommand(probe) })

	rootCmd.SetArgs([]string{"--server", server, "__absent_override_probe"})
	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	if captured != "stored-pat-must-not-be-used" {
		t.Fatalf("cfgToken() = %q, want the stored credential when nothing overrides it", captured)
	}
}
