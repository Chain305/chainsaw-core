package cli

// confirm_target_test.go — L-30.
//
// The finding: five destructive verbs interpolated args[0] straight into the
// confirmation prompt and only discovered the target did not exist AFTER the
// operator typed y. These tests drive the real RunE functions against an
// httptest server and inject a prompt stub, so "the prompt was never reached"
// is asserted directly rather than inferred from output.

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// destructiveTarget is one verb, the id it is asked to destroy, and how to run
// it through its confirmation gate.
type destructiveTarget struct {
	name string
	id   string
	run  func(t *testing.T) error
	// probePaths are the request paths the pre-confirm probe is allowed to
	// hit. Used by the --yes test to prove no probe fires.
	probePaths []string
}

func destructiveTargets() []destructiveTarget {
	return []destructiveTarget{
		{
			name:       "token revoke",
			id:         "ak-missing",
			probePaths: []string{"/api/api-keys/ak-missing"},
			run: func(t *testing.T) error {
				c := &cobra.Command{Use: "revoke"}
				c.Flags().Bool("yes", false, "")
				c.Flags().Bool("dry-run", false, "")
				return runTokenRevoke(quietCmd(c), []string{"ak-missing"})
			},
		},
		{
			name:       "token rotate",
			id:         "ak-missing",
			probePaths: []string{"/api/api-keys/ak-missing"},
			run: func(t *testing.T) error {
				c := &cobra.Command{Use: "rotate"}
				c.Flags().Bool("yes", false, "")
				c.Flags().Bool("json", false, "")
				return runTokenRotate(quietCmd(c), []string{"ak-missing"})
			},
		},
		{
			name:       "auth client delete",
			id:         "cli-missing",
			probePaths: []string{"/api/clients"},
			run: func(t *testing.T) error {
				return runAuthClientDelete(quietCmd(authClientDeleteCmd()), []string{"cli-missing"})
			},
		},
		{
			name:       "exception delete",
			id:         "exc-missing",
			probePaths: []string{"/api/exceptions/exc-missing"},
			run: func(t *testing.T) error {
				return runExceptionDelete(quietCmd(newExceptionDeleteCmdForTest()), []string{"exc-missing"})
			},
		},
		{
			name:       "finding suppress",
			id:         "f-missing",
			probePaths: []string{"/api/findings/f-missing"},
			run: func(t *testing.T) error {
				c := newFindingSuppressCmdForTest()
				if err := c.Flags().Set("reason", "triaged elsewhere"); err != nil {
					t.Fatalf("set reason: %v", err)
				}
				return runFindingSuppress(quietCmd(c), []string{"f-missing"})
			},
		},
	}
}

// authedAgainst points the CLI at srv with a credential, on an isolated config
// home and a file-backed cred store (never the real OS keyring).
func authedAgainst(t *testing.T, srv *httptest.Server) {
	t.Helper()
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	t.Setenv("CHAINSAW_TOKEN", "test-token")
	viper.Set("server_url", srv.URL)
	viper.Set("token", "test-token")
	t.Cleanup(viper.Reset)
}

// forbidPrompt installs a prompt stub that fails the test if it is reached, and
// pretends stdin is a TTY so the TTY guard does not short-circuit first.
func forbidPrompt(t *testing.T) {
	t.Helper()
	prevTTY := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	prevPrompt := promptConfirmFn
	promptConfirmFn = func(label string) bool {
		t.Fatalf("the confirmation prompt was reached for a target that does not exist: %q", label)
		return false
	}
	t.Cleanup(func() {
		stdinIsTerminal = prevTTY
		promptConfirmFn = prevPrompt
	})
}

// recordPrompt captures the prompt text and answers no, so the test observes
// what the operator would have been asked without confirming anything.
func recordPrompt(t *testing.T) *string {
	t.Helper()
	var seen string
	prevTTY := stdinIsTerminal
	stdinIsTerminal = func() bool { return true }
	prevPrompt := promptConfirmFn
	promptConfirmFn = func(label string) bool {
		seen = label
		return false
	}
	t.Cleanup(func() {
		stdinIsTerminal = prevTTY
		promptConfirmFn = prevPrompt
	})
	return &seen
}

// statusServer answers every request with the given status and body.
func statusServer(t *testing.T, status int, body string, seen *[]string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = append(*seen, r.Method+" "+r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestDestructiveVerbsFailBeforeThePromptOnAMissingTarget is the L-30
// regression. The prompt stub t.Fatal's if reached, so this cannot pass by
// accident.
func TestDestructiveVerbsFailBeforeThePromptOnAMissingTarget(t *testing.T) {
	for _, tc := range destructiveTargets() {
		t.Run(tc.name, func(t *testing.T) {
			var seen []string
			srv := statusServer(t, http.StatusNotFound,
				`{"error":{"code":"CHW-1404","message":"not found"}}`, &seen)
			// auth client delete resolves by listing; an empty list is its
			// "not found", so serve one rather than a 404.
			if tc.name == "auth client delete" {
				srv = statusServer(t, http.StatusOK, `{"clients":[]}`, &seen)
			}
			authedAgainst(t, srv)
			forbidPrompt(t)

			err := tc.run(t)
			if err == nil {
				t.Fatalf("%s destroyed (or reported success for) a target that does not exist", tc.name)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "not found") {
				t.Errorf("%s error = %q, want it to name the missing target", tc.name, err)
			}
			// The mutation itself must never have been attempted.
			for _, req := range seen {
				if strings.HasPrefix(req, "POST ") || strings.HasPrefix(req, "PUT ") {
					t.Errorf("%s issued a mutation for a missing target: %s", tc.name, req)
				}
			}
		})
	}
}

// TestDestructiveVerbsDegradeGracefullyWhenTheProbeIs403 pins the deliberate
// non-404 behaviour: read and write permissions are separate grants, so an
// operator who may revoke a token but may not READ tokens must still be able
// to revoke it. A courtesy lookup must never become a new authorization gate.
func TestDestructiveVerbsDegradeGracefullyWhenTheProbeIs403(t *testing.T) {
	for _, tc := range destructiveTargets() {
		t.Run(tc.name, func(t *testing.T) {
			var seen []string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				seen = append(seen, r.Method+" "+r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				// Every read is refused; the mutation itself would succeed.
				if r.Method == http.MethodGet ||
					(r.Method == http.MethodDelete && r.Header.Get(DryRunHeader) != "") {
					w.WriteHeader(http.StatusForbidden)
					_, _ = w.Write([]byte(`{"error":{"code":"CHW-1403","message":"forbidden"}}`))
					return
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{}`))
			}))
			t.Cleanup(srv.Close)
			authedAgainst(t, srv)
			prompt := recordPrompt(t)

			// Answering "no" means the command aborts cleanly; what matters is
			// that the operator WAS asked despite the failed probe.
			_ = tc.run(t)

			if *prompt == "" {
				t.Fatalf("%s refused to prompt because it could not READ the target; "+
					"a read-permission gap must not block a mutation the caller is allowed to perform", tc.name)
			}
			if !strings.Contains(*prompt, tc.id) {
				t.Errorf("%s degraded prompt does not name the raw id: %q", tc.name, *prompt)
			}
		})
	}
}

// TestDestructiveVerbsStillRefuseWithoutYesOffATTY keeps the A5 guarantee that
// this refactor moved into confirmDestructive: off a terminal there is no
// prompt to show, so the command must fail loudly rather than print "Aborted."
// and exit 0 while the credential stays live.
func TestDestructiveVerbsStillRefuseWithoutYesOffATTY(t *testing.T) {
	for _, tc := range destructiveTargets() {
		t.Run(tc.name, func(t *testing.T) {
			var seen []string
			srv := statusServer(t, http.StatusOK, `{}`, &seen)
			authedAgainst(t, srv)

			prev := stdinIsTerminal
			stdinIsTerminal = func() bool { return false }
			t.Cleanup(func() { stdinIsTerminal = prev })
			prevPrompt := promptConfirmFn
			promptConfirmFn = func(label string) bool {
				t.Fatalf("prompted off a TTY: %q", label)
				return false
			}
			t.Cleanup(func() { promptConfirmFn = prevPrompt })

			err := tc.run(t)
			if err == nil {
				t.Fatalf("%s silently no-opped off a TTY without --yes", tc.name)
			}
			if !strings.Contains(err.Error(), "--yes") {
				t.Errorf("%s error = %q, want it to name --yes", tc.name, err)
			}
			// And no probe should have fired either — there was never going to
			// be a prompt for it to inform.
			for _, req := range seen {
				t.Errorf("%s issued %s before failing the TTY guard", tc.name, req)
			}
		})
	}
}

// TestDestructiveVerbsWithYesFireNoProbe: --yes callers are scripts that have
// already decided. They must not pay a round trip for a confirmation they will
// never see, and must not be exposed to a read-permission failure.
func TestDestructiveVerbsWithYesFireNoProbe(t *testing.T) {
	cases := []struct {
		name       string
		probePaths []string
		run        func(t *testing.T) error
	}{
		{"token revoke", []string{"/api/api-keys/ak-1"}, func(t *testing.T) error {
			c := &cobra.Command{Use: "revoke"}
			c.Flags().Bool("yes", false, "")
			c.Flags().Bool("dry-run", false, "")
			mustSetFlag(t, c, "yes", "true")
			return runTokenRevoke(quietCmd(c), []string{"ak-1"})
		}},
		{"exception delete", []string{"/api/exceptions/exc-1"}, func(t *testing.T) error {
			c := newExceptionDeleteCmdForTest()
			mustSetFlag(t, c, "yes", "true")
			return runExceptionDelete(quietCmd(c), []string{"exc-1"})
		}},
		{"auth client delete", []string{"/api/clients"}, func(t *testing.T) error {
			c := authClientDeleteCmd()
			mustSetFlag(t, c, "yes", "true")
			return runAuthClientDelete(quietCmd(c), []string{"cli-1"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var seen []string
			srv := statusServer(t, http.StatusOK, `{}`, &seen)
			authedAgainst(t, srv)
			prevPrompt := promptConfirmFn
			promptConfirmFn = func(label string) bool {
				t.Fatalf("--yes still prompted: %q", label)
				return false
			}
			t.Cleanup(func() { promptConfirmFn = prevPrompt })

			if err := tc.run(t); err != nil {
				t.Fatalf("--yes run failed: %v", err)
			}
			for _, req := range seen {
				if strings.HasPrefix(req, "GET ") {
					t.Errorf("--yes fired a pre-confirm probe: %s", req)
				}
				// A dry-run DELETE is the probe for revoke/exception delete.
				if strings.Contains(req, "DELETE ") && len(seen) > 1 {
					t.Errorf("--yes issued more than the mutation itself: %v", seen)
					break
				}
			}
		})
	}
}

// TestConfirmDestructive_NotFoundIsStrictly404 pins the distinction the whole
// degrade-vs-abort decision rests on.
func TestConfirmDestructive_NotFoundIsStrictly404(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"404 apiError", &apiError{Status: http.StatusNotFound}, true},
		{"wrapped 404", fmt.Errorf("fetch: %w", &apiError{Status: http.StatusNotFound}), true},
		{"client-side not found", notFoundError("nope"), true},
		{"403", &apiError{Status: http.StatusForbidden}, false},
		{"401", &apiError{Status: http.StatusUnauthorized}, false},
		{"500", &apiError{Status: http.StatusInternalServerError}, false},
		{"transport error", errors.New("connection refused"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isNotFoundError(tc.err); got != tc.want {
				t.Fatalf("isNotFoundError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
