package cli

// Regression tests for D5 and D6 — the two ways `doctor verify-hook`, the
// check whose entire job is detecting a bypass, could report success on a
// real bypass.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestVerifyHook_FilterIgnoringServerDoesNotCertifyBypass is the D5 guard.
//
// The condition was `if resp.Total > 0 || matchSentinelInEvents(...)`. Go
// short-circuits `||`, so the client-side check — added SPECIFICALLY to
// defend against a server that ignores the package_name filter — never ran
// when total was non-zero. But total is the server's UNFILTERED count in
// exactly that scenario.
//
// This fake deliberately does NOT echo the query parameter back (unlike
// TestVerifyHook_PassWhenSentinelInAuditLog, which cannot exercise this
// path): it returns a large total and a page of unrelated events, i.e. a
// version-skewed proxy or a gateway that strips the query string. Before
// the fix this returned PASS with "proxy received 4213 event(s) matching
// sentinel" while the client had in fact routed straight to upstream.
func TestVerifyHook_FilterIgnoringServerDoesNotCertifyBypass(t *testing.T) {
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total": 4213,
			"events": []map[string]any{
				{"requested_package": "express", "event_type": "install"},
				{"requested_package": "react", "event_type": "install"},
			},
		})
	})
	withConfiguredServer(t, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	res := pollAuditReceipt(ctx, "chainsaw-verify-deadbeef-1700000000")

	if res.outcome == verifyPass {
		t.Fatalf("a non-zero server total with NO matching event must not certify PASS (matchCount=%d) — that is the filter-ignoring-server case the client-side check exists for", res.matchCount)
	}
	if res.outcome != verifyFail {
		t.Fatalf("outcome = %s, want FAIL (the API stayed reachable and never showed the sentinel)", res.outcome)
	}
}

// TestVerifyHook_FilterIgnoringServerStillPassesOnGenuineMatch proves the
// fix NARROWS rather than removes PASS: if the sentinel IS among the
// unrelated events, the proxy did see the install and the verdict is PASS.
// The reported count then comes from the client-side tally, because a page
// carrying non-matching rows proves `total` is counting something else.
func TestVerifyHook_FilterIgnoringServerStillPassesOnGenuineMatch(t *testing.T) {
	const sentinel = "chainsaw-verify-cafebabe-1700000000"
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total": 4213,
			"events": []map[string]any{
				{"requested_package": "express", "event_type": "install"},
				{"requested_package": sentinel, "event_type": "install"},
				{"requested_package": "react", "event_type": "install"},
			},
		})
	})
	withConfiguredServer(t, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res := pollAuditReceipt(ctx, sentinel)

	if res.outcome != verifyPass {
		t.Fatalf("outcome = %s, want PASS (the sentinel is present in the page)", res.outcome)
	}
	if res.matchCount != 1 {
		t.Errorf("matchCount = %d, want 1 — the page carries unrelated rows, so the server total counts something else and must not be reported as the match count", res.matchCount)
	}
}

// TestVerifyHookCmd_JSONVerboseStillFailsCI is the D6 guard.
//
// The `--json --verbose` branch `return writeJSON(...)`-ed straight out of
// RunE, skipping both the telemetry emit and the exit switch. So an
// operator adding --verbose to a failing CI step to get more detail turned
// the step green — while the JSON payload still said "outcome":"FAIL".
func TestVerifyHookCmd_JSONVerboseStillFailsCI(t *testing.T) {
	// Reachable audit API that never shows the sentinel → genuine FAIL.
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"total": 0, "events": []map[string]any{}})
	})
	withConfiguredServer(t, srv.URL)

	for _, verbose := range []bool{false, true} {
		name := "json"
		if verbose {
			name = "json+verbose"
		}
		t.Run(name, func(t *testing.T) {
			var exitCode int
			prev := verifyExitOverride
			verifyExitOverride = func(c int) { exitCode = c }
			t.Cleanup(func() { verifyExitOverride = prev })

			// Stub the driver so this never shells out to the developer's REAL `pip`.
			// The assertions below are about output shape and exit code, not about
			// pip itself; without the stub this test reached the network and let the
			// machine's own chainsaw install-hook write to the real config home.
			withStubVerifyDriver(t, "pip")
			cmd := newDoctorVerifyHookCmd()
			cmd.Flags().Bool("json", true, "")
			args := []string{"pip", "--json", "--timeout", "1s"}
			if verbose {
				args = append(args, "--verbose")
			}
			cmd.SetArgs(args)
			var out, errb bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&errb)
			cmd.SetContext(context.Background())
			cmd.SilenceUsage = true
			if err := cmd.Execute(); err != nil {
				t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
			}

			if !strings.Contains(out.String(), string(verifyFail)) {
				t.Skipf("environment did not produce a FAIL verdict (stdout=%q); the exit assertion needs one", out.String())
			}
			if exitCode != 1 {
				t.Fatalf("exit code = %d, want 1 — choosing a richer rendering must never weaken a verdict", exitCode)
			}
		})
	}
}

// TestVerifyHookCmd_JSONVerbosePayloadKeepsBothShapes pins the payload: the
// verbose envelope still nests the result under "result" and carries the
// command output, and the plain one is still the bare result object. The
// fallthrough fix must not change either shape.
func TestVerifyHookCmd_JSONVerbosePayloadKeepsBothShapes(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)

	run := func(verbose bool) map[string]any {
		t.Helper()
		prev := verifyExitOverride
		verifyExitOverride = func(int) {}
		t.Cleanup(func() { verifyExitOverride = prev })

		// Stub the driver so this never shells out to the developer's REAL `pip`.
		// The assertions below are about output shape and exit code, not about
		// pip itself; without the stub this test reached the network and let the
		// machine's own chainsaw install-hook write to the real config home.
		withStubVerifyDriver(t, "pip")
		cmd := newDoctorVerifyHookCmd()
		cmd.Flags().Bool("json", true, "")
		args := []string{"pip", "--json"}
		if verbose {
			args = append(args, "--verbose")
		}
		cmd.SetArgs(args)
		var out, errb bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errb)
		cmd.SetContext(context.Background())
		cmd.SilenceUsage = true
		if err := cmd.Execute(); err != nil {
			t.Fatalf("execute: %v\nstderr: %s", err, errb.String())
		}
		var parsed map[string]any
		if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &parsed); err != nil {
			t.Fatalf("stdout is not parseable JSON: %v\n%s", err, out.String())
		}
		return parsed
	}

	plain := run(false)
	if _, ok := plain["outcome"]; !ok {
		t.Errorf("plain --json payload should be the bare result object: %v", plain)
	}
	// The verbose envelope only appears when the driver produced output; if
	// pip is absent the payload legitimately stays bare, so only assert the
	// nested shape when we got one.
	verbose := run(true)
	if inner, ok := verbose["result"]; ok {
		m, _ := inner.(map[string]any)
		if _, ok := m["outcome"]; !ok {
			t.Errorf("verbose envelope must nest the full result: %v", verbose)
		}
		if _, ok := verbose["command_output"]; !ok {
			t.Errorf("verbose envelope must carry command_output: %v", verbose)
		}
	} else if _, ok := verbose["outcome"]; !ok {
		t.Errorf("verbose payload is neither the nested envelope nor the bare result: %v", verbose)
	}
}
