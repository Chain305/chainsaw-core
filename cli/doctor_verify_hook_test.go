package cli

// doctor_verify_hook_test.go covers the verify-hook subcommand's
// audit-receipt logic (the part we can hermetically test without
// shelling out to bun / docker / npm in CI). The per-manager Drive
// methods are exercised via a thin unit test that asserts each driver
// at least returns a non-empty command and embeds the sentinel — the
// actual cmd execution is delegated to integration smoke tests.

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/cli/hook"
)

// TestVerifyHookKnowsAllInstallHookManagers is the registry tripwire:
// every manager registered in hook.All() must either have a
// verifyDriver OR be explicitly listed in the deferred set. Without
// this, adding a new manager (e.g. swift, gomod) silently leaves
// verify-hook with a "unknown package manager" failure mode.
func TestVerifyHookKnowsAllInstallHookManagers(t *testing.T) {
	// Managers we've deliberately not yet built a verify driver for.
	// Adding one here is a conscious decision — file a follow-up
	// before removing the entry.
	deferred := map[string]string{
		"swift":  "swiftpm reverse-lookup + git clone interaction needs a separate driver — Wave AG showed swift falls back to direct GitHub clone on 404",
		"yarn":   "yarn uses the same .npmrc as npm; verify via npm for now",
		"maven":  "maven settings.xml drive needs profile injection",
		"gradle": "gradle init-script driver pending",
		"sbt":    "sbt resolvers drive pending",
		"nuget":  "nuget.config drive pending",
		"go":     "GOPROXY drive pending — well-tested elsewhere",
	}

	drivers := verifyDrivers()
	for _, m := range hook.All() {
		name := m.Name()
		if _, ok := drivers[name]; ok {
			continue
		}
		if _, ok := deferred[name]; ok {
			continue
		}
		t.Errorf("manager %q is registered in hook.All() but has no verifyDriver and is not in the deferred allowlist — add one or document the deferral", name)
	}
}

// TestVerifyHook_PassWhenSentinelInAuditLog covers the happy path: the
// audit API returns a row matching the sentinel coordinate → PASS.
func TestVerifyHook_PassWhenSentinelInAuditLog(t *testing.T) {
	var gotPackageName string
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/events" {
			http.NotFound(w, r)
			return
		}
		gotPackageName = r.URL.Query().Get("package_name")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total": 1,
			"events": []map[string]any{
				{
					"requested_package": gotPackageName,
					"event_type":        "install",
				},
			},
		})
	})
	withConfiguredServer(t, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res := pollAuditReceipt(ctx, "chainsaw-verify-deadbeef-1700000000")

	if res.outcome != verifyPass {
		t.Fatalf("outcome = %s, want PASS (reason=%s)", res.outcome, res.degradedReason)
	}
	if res.matchCount != 1 {
		t.Errorf("matchCount = %d, want 1", res.matchCount)
	}
	if !strings.HasPrefix(gotPackageName, "chainsaw-verify-") {
		t.Errorf("server got package_name = %q, want chainsaw-verify- prefix", gotPackageName)
	}
}

// TestVerifyHook_FailWhenSentinelMissing exercises the bypass-detection
// path: audit API is reachable but never returns a match → FAIL after
// timeout.
func TestVerifyHook_FailWhenSentinelMissing(t *testing.T) {
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Always-empty response — proxy never saw the sentinel.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"total":  0,
			"events": []map[string]any{},
		})
	})
	withConfiguredServer(t, srv.URL)

	// Short timeout — we don't want CI hanging.
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	res := pollAuditReceipt(ctx, "chainsaw-verify-cafebabe-1700000000")

	if res.outcome != verifyFail {
		t.Fatalf("outcome = %s, want FAIL", res.outcome)
	}
}

// TestVerifyHook_DegradedWhenAuditAPIUnreachable confirms that an
// audit-API transport error degrades cleanly rather than reporting a
// false-positive bypass.
func TestVerifyHook_DegradedWhenAuditAPIUnreachable(t *testing.T) {
	// Point at a port nothing is listening on. 127.0.0.1:1 reliably
	// refuses connections in CI.
	withConfiguredServer(t, "http://127.0.0.1:1")

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res := pollAuditReceipt(ctx, "chainsaw-verify-feedface-1700000000")

	if res.outcome != verifyDegraded {
		t.Fatalf("outcome = %s, want DEGRADED", res.outcome)
	}
	if res.degradedReason == "" {
		t.Errorf("DEGRADED reason should not be empty")
	}
}

// TestVerifyHook_DegradedWhenNoServerConfigured covers the
// "scaffolded-but-not-authed" path: no server URL means we can't
// confirm receipt either way, so degrade with an actionable message.
func TestVerifyHook_DegradedWhenNoServerConfigured(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)
	// Deliberately no withConfiguredServer call.

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	res := pollAuditReceipt(ctx, "chainsaw-verify-baadf00d-1700000000")

	if res.outcome != verifyDegraded {
		t.Fatalf("outcome = %s, want DEGRADED", res.outcome)
	}
	if !strings.Contains(res.degradedReason, "no server") {
		t.Errorf("reason = %q, want mention of missing server", res.degradedReason)
	}
}

// TestVerifyHook_SentinelCoordIsUniqueAndRecognisable asserts the
// sentinel shape so log-grepping operators (and the JSON output) can
// always tell a verify event apart from a real install. Drift here
// will break the OBSERVABILITY runbook.
func TestVerifyHook_SentinelCoordIsUniqueAndRecognisable(t *testing.T) {
	seen := map[string]struct{}{}
	for i := 0; i < 32; i++ {
		s, err := newSentinelCoord()
		if err != nil {
			t.Fatalf("newSentinelCoord: %v", err)
		}
		if !strings.HasPrefix(s, "chainsaw-verify-") {
			t.Errorf("sentinel %q missing chainsaw-verify- prefix", s)
		}
		if _, dup := seen[s]; dup {
			t.Errorf("sentinel collision after %d iterations: %q", i, s)
		}
		seen[s] = struct{}{}
	}
}

// TestVerifyHookCmd_UnknownManagerSurfacesSupportedList asserts that
// asking for an unknown manager produces a useful list of supported
// managers (not a stack trace).
func TestVerifyHookCmd_UnknownManagerSurfacesSupportedList(t *testing.T) {
	cmd := newDoctorVerifyHookCmd()
	cmd.SetArgs([]string{"nonexistent-pm"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetContext(context.Background())
	cmd.SilenceUsage = true
	err := cmd.Execute()
	if err == nil {
		t.Fatalf("expected error for unknown manager, got nil")
	}
	if !strings.Contains(err.Error(), "nonexistent-pm") {
		t.Errorf("error %q does not mention bad manager name", err)
	}
	if !strings.Contains(err.Error(), "verify supports") {
		t.Errorf("error %q does not list supported managers", err)
	}
}

// TestVerifyHookCmd_DeferredManagerHasSpecificError ensures that
// "yarn" (or any other deferred manager) gets the deferred-coverage
// message, not the generic "unknown" one — distinguishing a typo from
// a known gap is part of the contract.
func TestVerifyHookCmd_DeferredManagerHasSpecificError(t *testing.T) {
	_, err := verifyDriverFor("yarn")
	if err == nil {
		t.Fatalf("expected error for deferred manager yarn, got nil")
	}
	if !strings.Contains(err.Error(), "verify not yet supported") {
		t.Errorf("yarn error = %q, want deferred-coverage message", err)
	}
}

// TestVerifyHook_JSONOutputShape locks the JSON envelope so dashboards
// and CI parsers can rely on the field names.
func TestVerifyHook_JSONOutputShape(t *testing.T) {
	res := verifyResult{
		Manager:   "npm",
		Sentinel:  "chainsaw-verify-deadbeef-1700000000",
		Outcome:   verifyPass,
		Reason:    "proxy received 1 event(s) matching sentinel",
		Duration:  "412ms",
		InstallOK: false,
	}
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, key := range []string{`"manager"`, `"sentinel"`, `"outcome"`, `"reason"`, `"duration"`, `"install_ok"`} {
		if !strings.Contains(string(b), key) {
			t.Errorf("JSON missing required key %s: %s", key, b)
		}
	}
}

// TestVerifyDrivers_BypassHintsArePopulated guards the operator-facing
// remediation text: every driver must surface a non-trivial hint, else
// the FAIL message degrades to "cause: bypass" with no fix line.
func TestVerifyDrivers_BypassHintsArePopulated(t *testing.T) {
	for name, d := range verifyDrivers() {
		hint := d.BypassHint()
		if len(hint) < 40 {
			t.Errorf("driver %q BypassHint too short (%d chars), want actionable remediation", name, len(hint))
		}
	}
}

// TestServerHostForDockerPull_StripsSchemeAndPath asserts the docker
// driver's URL-to-host normalisation. Drift here would point pulls at
// the wrong host and silently DEGRADE every docker verify.
func TestServerHostForDockerPull_StripsSchemeAndPath(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"https://chainsaw.example.com", "chainsaw.example.com"},
		{"https://chainsaw.example.com/", "chainsaw.example.com"},
		{"http://127.0.0.1:8443/chainproxy/", "127.0.0.1:8443"},
	}
	for _, tc := range tests {
		got, err := serverHostForDockerPull(tc.in)
		if err != nil {
			t.Errorf("serverHostForDockerPull(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("serverHostForDockerPull(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestGrepHintFor_EmbedsSentinel guarantees the DEGRADED-mode grep
// one-liner is copy-pasteable.
func TestGrepHintFor_EmbedsSentinel(t *testing.T) {
	hint := grepHintFor("chainsaw-verify-deadbeef-1700000000")
	if !strings.Contains(hint, "chainsaw-verify-deadbeef-1700000000") {
		t.Errorf("grep hint missing sentinel: %s", hint)
	}
	if !strings.Contains(hint, "grep") {
		t.Errorf("grep hint missing 'grep': %s", hint)
	}
}

// emptyEventsJSON is the on-the-wire shape for a reachable-but-no-match
// audit poll. Shared by the trailing-failure tests below.
func emptyEventsJSON(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"total":  0,
		"events": []map[string]any{},
	})
}

// TestVerifyHook_DegradedWhenPollsFailTransportAfterFirstSuccess is the
// core P0 regression guard: the FIRST audit call succeeds (establishing
// the API was reachable, returning zero matches) but EVERY subsequent
// poll hits a transport error until the context times out. The old code
// fell through to verifyFail — the alarming "client BYPASSED chainsaw"
// verdict — even though we never actually proved a bypass. The fix
// degrades instead, because a trailing run of transport failures means
// we can no longer confirm anything.
func TestVerifyHook_DegradedWhenPollsFailTransportAfterFirstSuccess(t *testing.T) {
	var calls int32
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 1 {
			// First call: reachable, zero matches.
			emptyEventsJSON(w)
			return
		}
		// Every subsequent poll: hijack and slam the connection so the
		// client sees a transport error (not an HTTP status).
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Errorf("test server does not support hijacking")
			emptyEventsJSON(w)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			t.Errorf("hijack: %v", err)
			return
		}
		_ = conn.Close()
	})
	withConfiguredServer(t, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	res := pollAuditReceipt(ctx, "chainsaw-verify-deadbeef-1700000000")

	if res.outcome != verifyDegraded {
		t.Fatalf("outcome = %s, want DEGRADED (trailing transport failures must not report a false bypass)", res.outcome)
	}
	if !strings.Contains(res.degradedReason, "unreachable while polling") {
		t.Errorf("degradedReason = %q, want mention of unreachable-while-polling transport error", res.degradedReason)
	}
	if atomic.LoadInt32(&calls) < 2 {
		t.Errorf("expected at least 2 calls (first success + at least one failing poll), got %d", calls)
	}
}

// TestVerifyHook_FailWhenPollsSucceedButNeverMatch proves the fix
// NARROWS rather than removes the FAIL verdict: the first call and every
// poll succeed-without-match until timeout, so the API stayed reachable
// and genuinely never showed the sentinel → the real bypass case is
// preserved as FAIL. (Complements TestVerifyHook_FailWhenSentinelMissing
// by exercising the post-first-call poll loop specifically.)
func TestVerifyHook_FailWhenPollsSucceedButNeverMatch(t *testing.T) {
	var calls int32
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		emptyEventsJSON(w)
	})
	withConfiguredServer(t, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	res := pollAuditReceipt(ctx, "chainsaw-verify-cafebabe-1700000000")

	if res.outcome != verifyFail {
		t.Fatalf("outcome = %s, want FAIL (reachable + never matched is a genuine bypass)", res.outcome)
	}
	if atomic.LoadInt32(&calls) < 2 {
		t.Errorf("expected at least 2 calls (first + polls), got %d", calls)
	}
}

// TestVerifyHook_FailWhenLastPollSucceedsAfterTransientErrors confirms
// consecutiveErr resets on success: polls fail transiently mid-run but
// the LAST poll before timeout succeeds-without-match, so the trailing
// failure run is empty → FAIL, not DEGRADED. This is the boundary that
// keeps the degrade scoped to *trailing* failures only.
func TestVerifyHook_FailWhenLastPollSucceedsAfterTransientErrors(t *testing.T) {
	// Pattern: call 1 succeeds (reachable). Calls 2-3 fail transport.
	// Calls 4+ succeed (empty). Because the run ends on a success
	// streak, consecutiveErr is 0 at timeout → FAIL.
	var calls int32
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		if n == 2 || n == 3 {
			hj, ok := w.(http.Hijacker)
			if !ok {
				emptyEventsJSON(w)
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				return
			}
			_ = conn.Close()
			return
		}
		emptyEventsJSON(w)
	})
	withConfiguredServer(t, srv.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
	defer cancel()
	res := pollAuditReceipt(ctx, "chainsaw-verify-feedface-1700000000")

	if res.outcome != verifyFail {
		t.Fatalf("outcome = %s, want FAIL (a trailing successful poll must reset the failure run)", res.outcome)
	}
	if atomic.LoadInt32(&calls) < 4 {
		t.Errorf("expected at least 4 calls to reach the post-error success streak, got %d", calls)
	}
}

// TestVerifyHookCmd_StatusLinesOnStderrInNonJSONMode covers Finding 2:
// the two progress status lines must go to stderr (never stdout) in the
// default human mode. We drive the real command with a stub manager that
// is unknown to the audit API; the verdict doesn't matter — we only
// assert the status lines appear before the (degraded) result.
func TestVerifyHookCmd_StatusLinesOnStderrInNonJSONMode(t *testing.T) {
	// No server configured → pollAuditReceipt degrades immediately, so
	// the command returns fast without a live network dependency. We use
	// pip because its Drive() has no server precondition and exits fast.
	withIsolatedConfigHome(t)
	withFileCredStore(t)

	cmd := newDoctorVerifyHookCmd()
	cmd.SetArgs([]string{"pip"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetContext(context.Background())
	cmd.SilenceUsage = true
	_ = cmd.Execute()

	stderr := errb.String()
	if !strings.Contains(stderr, "driving synthetic install") {
		t.Errorf("stderr missing 'driving synthetic install' status line:\n%s", stderr)
	}
	if !strings.Contains(stderr, "polling audit log") {
		t.Errorf("stderr missing 'polling audit log' status line:\n%s", stderr)
	}
	if strings.Contains(out.String(), "driving synthetic install") || strings.Contains(out.String(), "polling audit log") {
		t.Errorf("status lines leaked to stdout:\n%s", out.String())
	}
}

// TestVerifyHookCmd_NoStatusLinesInJSONMode is the JSON-contract guard
// for Finding 2: in --json mode neither status line may appear on
// stderr, and stdout must remain a single parseable JSON object with no
// leading non-JSON bytes.
func TestVerifyHookCmd_NoStatusLinesInJSONMode(t *testing.T) {
	withIsolatedConfigHome(t)
	withFileCredStore(t)

	cmd := newDoctorVerifyHookCmd()
	// --json is a persistent/global flag in this CLI; register it locally
	// so the standalone command instance honours it the way the real
	// root command would.
	cmd.Flags().Bool("json", true, "")
	cmd.SetArgs([]string{"pip", "--json"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetContext(context.Background())
	cmd.SilenceUsage = true
	_ = cmd.Execute()

	stderr := errb.String()
	if strings.Contains(stderr, "driving synthetic install") || strings.Contains(stderr, "polling audit log") {
		t.Errorf("status lines must be suppressed in JSON mode, got stderr:\n%s", stderr)
	}
	trimmed := strings.TrimSpace(out.String())
	if !strings.HasPrefix(trimmed, "{") {
		t.Fatalf("stdout is not a JSON object (has leading non-JSON bytes):\n%q", out.String())
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(trimmed), &parsed); err != nil {
		t.Fatalf("stdout is not parseable JSON: %v\n%s", err, out.String())
	}
	if _, ok := parsed["outcome"]; !ok {
		t.Errorf("JSON result missing 'outcome' key: %s", trimmed)
	}
}

// TestMatchSentinelInEvents_ClientSideFallback exercises the defensive
// client-side LIKE check that protects against an older server
// ignoring the package_name filter.
func TestMatchSentinelInEvents_ClientSideFallback(t *testing.T) {
	items := []eventsResponseItem{
		{RequestedPackage: "express"},
		{RequestedPackage: "chainsaw-verify-deadbeef-1700000000"},
		{RequestedPackage: "react"},
	}
	if !matchSentinelInEvents(items, "chainsaw-verify-deadbeef-1700000000") {
		t.Errorf("expected match for sentinel substring")
	}
	if matchSentinelInEvents(items, "chainsaw-verify-cafebabe-1700000000") {
		t.Errorf("did not expect match for absent sentinel")
	}
}
