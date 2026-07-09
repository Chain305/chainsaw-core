package cli

// onboard_test.go covers the CLI twin of the MCP chainsaw_onboard tool.
// The tests stand up a fake server that mimics POST /api/users/me/persona
// and GET /api/users/me, then assert that --persona sets, --skip
// silences, and bare invocation reads without writing.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestOnboard_SetsPersona(t *testing.T) {
	var (
		gotPost bool
		gotBody map[string]any
	)
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/users/me/persona":
			gotPost = true
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &gotBody)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		case r.Method == http.MethodGet && r.URL.Path == "/api/users/me":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "user-1",
				"email":   "alice@example.test",
				"persona": "appsec",
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	})
	withConfiguredServer(t, srv.URL)

	cmd := newOnboardCmd()
	cmd.SetArgs([]string{"--persona", "appsec"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("onboard: %v\nstderr: %s", err, errb.String())
	}

	if !gotPost {
		t.Fatal("expected POST /api/users/me/persona, never received")
	}
	if gotBody["persona"] != "appsec" {
		t.Errorf("posted persona = %v, want appsec", gotBody["persona"])
	}
	if gotBody["skipped"] != false {
		t.Errorf("posted skipped = %v, want false", gotBody["skipped"])
	}
}

func TestOnboard_RejectsUnknownPersona(t *testing.T) {
	withConfiguredServer(t, "http://unused.invalid")
	cmd := newOnboardCmd()
	cmd.SetArgs([]string{"--persona", "not-a-thing"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for unknown persona")
	}
	if !strings.Contains(err.Error(), "unknown persona") {
		t.Errorf("error = %v, want 'unknown persona'", err)
	}
}

// TestOnboardingState_AliasReadsCurrentState pins the additive
// `chainsaw onboarding state` alias surface — it must call GET
// /api/users/me (no POST) and render the same persona text as the
// existing `chainsaw onboard` no-flag invocation. Locks the alias
// behaviour so a future refactor doesn't accidentally rewire it.
func TestOnboardingState_AliasReadsCurrentState(t *testing.T) {
	var postCount int
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			postCount++
			http.Error(w, "alias must not POST", http.StatusInternalServerError)
		case r.Method == http.MethodGet && r.URL.Path == "/api/users/me":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "user-1",
				"email":   "alice@example.test",
				"persona": "devsecops",
			})
		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	})
	withConfiguredServer(t, srv.URL)

	cmd := newOnboardingCmd()
	cmd.SetArgs([]string{"state"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("onboarding state: %v\nstderr: %s", err, errb.String())
	}

	if postCount != 0 {
		t.Errorf("onboarding state issued %d POSTs, want 0 (read-only alias)", postCount)
	}
	if !strings.Contains(out.String(), "devsecops") {
		t.Errorf("output missing persona:\n%s", out.String())
	}
}

// TestOnboardingState_ParentPrintsHelp pins that bare `chainsaw
// onboarding` (no subcommand) does not error and prints help. The
// alias parent is a discovery surface — it should never crash.
func TestOnboardingState_ParentPrintsHelp(t *testing.T) {
	cmd := newOnboardingCmd()
	cmd.SetArgs([]string{})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("onboarding (bare): %v\nstderr: %s", err, errb.String())
	}
	if !strings.Contains(out.String(), "state") {
		t.Errorf("bare onboarding help should mention `state` subcommand:\n%s", out.String())
	}
}

func TestOnboard_SkipsWithoutPersona(t *testing.T) {
	var gotBody map[string]any
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/users/me/persona":
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &gotBody)
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": true})
		case "/api/users/me":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":                    "user-1",
				"onboarding_skipped_at": "2026-05-19T00:00:00Z",
			})
		}
	})
	withConfiguredServer(t, srv.URL)

	cmd := newOnboardCmd()
	cmd.SetArgs([]string{"--skip"})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	if err := cmd.Execute(); err != nil {
		t.Fatalf("onboard --skip: %v\nstderr: %s", err, errb.String())
	}
	if gotBody == nil {
		t.Fatal("expected POST body, got nil")
	}
	if gotBody["skipped"] != true {
		t.Errorf("posted skipped = %v, want true", gotBody["skipped"])
	}
	if _, hasPersona := gotBody["persona"]; hasPersona {
		t.Errorf("body should not include persona on bare --skip, got %v", gotBody)
	}
}
