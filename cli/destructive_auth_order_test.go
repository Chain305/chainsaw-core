package cli

// destructive_auth_order_test.go — Z2.
//
// There is no PersistentPreRunE and no auth middleware. The CLI's only
// authentication check lives inside the transport (APIClient.do in client.go:
// `requireToken && c.token == ""` → ExitConfigAuth), which means a command
// inherits an auth check ONLY if it happens to make a server call before it
// prompts. `policy delete` did, because it fetches a display name for the
// confirmation message. `token revoke` did not.
//
// The result: six destructive verbs asked an unauthenticated operator to
// confirm an irreversible action, waited for them to type y, and only then
// reported "not authenticated". The four that behaved did so by accident.
//
// requireAuth (root.go) makes the ordering a property of the command. These
// tests assert it for every gated verb, and — via the set check at the bottom —
// for any gated verb added later.

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// destructiveRunner names one gated command and the invocation that reaches its
// confirmation gate.
type destructiveRunner struct {
	// path matches the key in requiresYesGate (auth_destructive_guard_test.go)
	// so the two lists can be checked against each other.
	path string
	run  func(t *testing.T) error
}

func destructiveRunners() []destructiveRunner {
	return []destructiveRunner{
		{"chainsaw undo", func(t *testing.T) error {
			return runUndo(quietCmd(newUndoCmdForTest()), nil)
		}},
		{"chainsaw finding suppress", func(t *testing.T) error {
			c := newFindingSuppressCmdForTest()
			if err := c.Flags().Set("reason", "triaged elsewhere"); err != nil {
				t.Fatalf("set reason: %v", err)
			}
			return runFindingSuppress(quietCmd(c), []string{"f-1"})
		}},
		{"chainsaw exception delete", func(t *testing.T) error {
			return runExceptionDelete(quietCmd(newExceptionDeleteCmdForTest()), []string{"exc-1"})
		}},
		{"chainsaw token revoke", func(t *testing.T) error {
			c := &cobra.Command{Use: "revoke"}
			c.Flags().Bool("yes", false, "")
			c.Flags().Bool("dry-run", false, "")
			return runTokenRevoke(quietCmd(c), []string{"tok-1"})
		}},
		{"chainsaw token rotate", func(t *testing.T) error {
			c := &cobra.Command{Use: "rotate"}
			c.Flags().Bool("yes", false, "")
			c.Flags().Bool("json", false, "")
			return runTokenRotate(quietCmd(c), []string{"ak-1"})
		}},
		{"chainsaw auth client delete", func(t *testing.T) error {
			return runAuthClientDelete(quietCmd(authClientDeleteCmd()), []string{"cli-1"})
		}},
		{"chainsaw auth client rotate", func(t *testing.T) error {
			return runAuthClientRotate(quietCmd(authClientRotateCmd()), []string{"cli-1"})
		}},
		{"chainsaw policy delete", func(t *testing.T) error {
			return runPolicyDelete(quietCmd(newPolicyDeleteCmdForTest()), []string{"pol-1"})
		}},
		{"chainsaw policy flip-to-block", func(t *testing.T) error {
			return runPolicyFlipToBlock(quietCmd(newPolicyFlipToBlockCmdForTest()), []string{"pol-1"})
		}},
		{"chainsaw org delete", func(t *testing.T) error {
			c := &cobra.Command{Use: "delete"}
			c.Flags().Bool("dry-run", false, "")
			c.Flags().String("simulate-id", "", "")
			c.Flags().Bool("confirm", false, "")
			c.Flags().Bool("yes", false, "")
			c.Flags().String("slug", "", "")
			c.Flags().Bool("json", false, "")
			for k, v := range map[string]string{"simulate-id": "sim-1", "confirm": "true", "slug": "acme"} {
				if err := c.Flags().Set(k, v); err != nil {
					t.Fatalf("set %s: %v", k, err)
				}
			}
			return runOrgDelete(quietCmd(c), nil)
		}},
		{"chainsaw team remove", func(t *testing.T) error {
			c := &cobra.Command{Use: "remove"}
			c.Flags().Bool("yes", false, "")
			return runTeamRemove(quietCmd(c), []string{"acme/*"})
		}},
		{"chainsaw coverage expected remove", func(t *testing.T) error {
			c := &cobra.Command{Use: "remove"}
			c.Flags().Bool("yes", false, "")
			return runCoverageExpectedRemove(quietCmd(c), []string{"7"})
		}},
		{"chainsaw repo disable", func(t *testing.T) error {
			c := &cobra.Command{Use: "disable"}
			c.Flags().Bool("yes", false, "")
			c.Flags().Bool("json", false, "")
			return runRepoSetEnabled(false)(quietCmd(c), []string{"npm-proxy"})
		}},
	}
}

// quietCmd routes cobra's writers into discard buffers so a test failure shows
// the captured os.Stdout (where the prompts actually go) and nothing else.
func quietCmd(c *cobra.Command) *cobra.Command {
	c.SetOut(&bytes.Buffer{})
	c.SetErr(&bytes.Buffer{})
	c.SilenceUsage = true
	return c
}

// TestDestructiveVerbs_AuthCheckedBeforeAnyPrompt is Z2.
//
// The setup is deliberately hostile to the bug: stdin reports a TTY AND is
// primed with "y", and the server accepts everything. So a command that
// prompts before checking auth will confirm, will issue its mutation, and will
// be caught here — rather than being masked by a later 401.
func TestDestructiveVerbs_AuthCheckedBeforeAnyPrompt(t *testing.T) {
	for _, tc := range destructiveRunners() {
		t.Run(tc.path, func(t *testing.T) {
			withIsolatedConfigHome(t) // viper.Reset(): no token anywhere
			withFileCredStore(t)      // never touch the real OS keyring
			unsetEnv(t, "CHAINSAW_TOKEN")
			answerPromptYes(t)

			var requests int
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				t.Errorf("unauthenticated %s reached the server: %s %s", tc.path, r.Method, r.URL)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			t.Cleanup(srv.Close)
			viper.Set("server_url", srv.URL)

			var err error
			stdout := captureStdout(t, func() { err = tc.run(t) })

			if err == nil {
				t.Fatalf("%s succeeded with no credentials; stdout:\n%s", tc.path, stdout)
			}
			var coded *ExitCodeError
			if !errors.As(err, &coded) || coded.Code != ExitConfigAuth {
				t.Fatalf("%s error = %v, want ExitCodeError{Code: ExitConfigAuth(3)}", tc.path, err)
			}
			if !strings.Contains(err.Error(), "not authenticated") {
				t.Errorf("%s error = %q, want the transport's own wording", tc.path, err)
			}
			if strings.Contains(stdout, "[y/N]") || strings.Contains(stdout, "[Y/n]") {
				t.Errorf("%s prompted for confirmation before checking auth:\n%s", tc.path, stdout)
			}
			if requests != 0 {
				t.Errorf("%s issued %d requests without credentials", tc.path, requests)
			}
		})
	}
}

// TestDestructiveVerbs_AuthOrderCoversEveryGatedCommand keeps the table above
// honest. requiresYesGate (auth_destructive_guard_test.go) is the curated set
// of commands that destroy durable state; every one of them prompts, so every
// one of them must be exercised here. A twelfth gated verb added later fails
// this test rather than quietly shipping with the old ordering.
func TestDestructiveVerbs_AuthOrderCoversEveryGatedCommand(t *testing.T) {
	covered := map[string]bool{}
	for _, r := range destructiveRunners() {
		if covered[r.path] {
			t.Errorf("%q is listed twice in destructiveRunners", r.path)
		}
		covered[r.path] = true
	}
	for path := range requiresYesGate {
		if !covered[path] {
			t.Errorf("%q declares a --yes confirmation gate but is not exercised by "+
				"TestDestructiveVerbs_AuthCheckedBeforeAnyPrompt.\n"+
				"  Add it to destructiveRunners, and add `if err := requireAuth(cmd); err != nil { return err }`\n"+
				"  immediately after its errServerNotConfigured check.", path)
		}
	}
	for path := range covered {
		if _, ok := requiresYesGate[path]; !ok {
			t.Errorf("%q is exercised here but is not in requiresYesGate; the two lists must agree", path)
		}
	}
}

// TestRequireAuth_MatchesTheTransportContract: requireAuth moves the existing
// failure earlier, it must not invent a new one. Same code, same message as
// APIClient.do's preflight.
func TestRequireAuth_MatchesTheTransportContract(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	unsetEnv(t, "CHAINSAW_TOKEN")

	err := requireAuth(&cobra.Command{Use: "x"})
	if err == nil {
		t.Fatal("requireAuth returned nil with no credential configured")
	}
	var coded *ExitCodeError
	if !errors.As(err, &coded) || coded.Code != ExitConfigAuth {
		t.Fatalf("err = %v, want ExitCodeError{Code: ExitConfigAuth}", err)
	}

	// The transport's own preflight, for comparison.
	c := newClient()
	c.baseURL = "http://127.0.0.1:1"
	c.requireToken = true
	c.token = ""
	transportErr := c.Get("/api/anything", nil)
	if transportErr == nil {
		t.Fatal("transport preflight did not fire")
	}
	if err.Error() != transportErr.Error() {
		t.Errorf("requireAuth says %q but the transport says %q; the two must be indistinguishable "+
			"to a caller, or moving the check earlier is a contract change", err, transportErr)
	}
}

// TestRequireAuth_PassesWithACredential is the negative control: the guard must
// not fire for an authenticated operator.
func TestRequireAuth_PassesWithACredential(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	viper.Set("server_url", "https://example.test")
	viper.Set("token", "live-token")

	if err := requireAuth(&cobra.Command{Use: "x"}); err != nil {
		t.Fatalf("requireAuth blocked an authenticated caller: %v", err)
	}
}
