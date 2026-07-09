package cli

// auth_status_test.go covers the Finding-3 fix to `chainsaw auth status`:
// it must (a) distinguish an expired/rejected token (401) from a server
// it simply couldn't reach (transport error), and (b) return a non-zero
// exit when not authenticated — while preserving the --json body so
// scripts get both a JSON document on stdout and a non-zero `$?`.
//
// Tests drive the real RunE through an httptest server, setting
// server_url + token via viper (cfgServerURL/cfgToken read those keys
// first). The --json flag is registered on the test command so useJSON
// resolves it.

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// runAuthStatus executes the status command against the given server,
// with optional --json, and returns stdout + the RunE error.
func runAuthStatus(t *testing.T, server, token string, asJSON bool) (string, error) {
	t.Helper()
	viper.Reset()
	t.Cleanup(viper.Reset)
	if server != "" {
		viper.Set("server_url", server)
	}
	if token != "" {
		viper.Set("token", token)
	}

	cmd := authStatusCmd()
	// useJSON reads a bool "json" flag; register it so the JSON path is reachable.
	cmd.Flags().Bool("json", asJSON, "")
	cmd.SetArgs([]string{})
	var out, errb bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errb)

	err := cmd.RunE(cmd, nil)
	return out.String(), err
}

// exitCode unwraps an *ExitCodeError and returns its code, or -1 when the
// error is nil, or 0 when it's a non-coded error.
func exitCode(err error) int {
	if err == nil {
		return -1
	}
	var coded *ExitCodeError
	if errors.As(err, &coded) {
		return coded.Code
	}
	return 0
}

func TestAuthStatus_Authenticated200_ExitZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"user_id":"u1","org_id":"o1","role":"admin","email":"a@b.com","is_admin":true}`))
	}))
	defer srv.Close()

	out, err := runAuthStatus(t, srv.URL, "tok", false)
	if err != nil {
		t.Fatalf("authenticated status should return nil error, got: %v", err)
	}
	if !strings.Contains(out, "Authenticated") {
		t.Errorf("expected Authenticated in output, got:\n%s", out)
	}
}

func TestAuthStatus_Token401_LoginHintAndNonZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"HTTP 401","message":"unauthorized"}`))
	}))
	defer srv.Close()

	out, err := runAuthStatus(t, srv.URL, "stale-tok", false)
	if code := exitCode(err); code != 1 {
		t.Fatalf("401 should return ExitCodeError{Code:1}, got code=%d err=%v", code, err)
	}
	if !strings.Contains(out, "chainsaw auth login") {
		t.Errorf("401 text should point at `chainsaw auth login`, got:\n%s", out)
	}
	if !strings.Contains(out, "expired") && !strings.Contains(out, "invalid") {
		t.Errorf("401 wording should mention expired/invalid token, got:\n%s", out)
	}
	if strings.Contains(out, "unreachable") {
		t.Errorf("401 case must not say 'unreachable' (that's the transport case):\n%s", out)
	}
}

func TestAuthStatus_TransportError_DistinctWordingAndNonZero(t *testing.T) {
	// Start a server then immediately close it so the client gets a
	// connection error (transport failure, not a 401).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	out, err := runAuthStatus(t, url, "tok", false)
	if code := exitCode(err); code != 1 {
		t.Fatalf("transport error should return ExitCodeError{Code:1}, got code=%d err=%v", code, err)
	}
	if !strings.Contains(out, "unreachable") {
		t.Errorf("transport case should say 'unreachable', got:\n%s", out)
	}
	if strings.Contains(out, "expired") {
		t.Errorf("transport case must not use the 401 'expired' wording:\n%s", out)
	}
}

func TestAuthStatus_JSON401_EncodesUnauthenticatedAndNonZero(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"code":"HTTP 401","message":"unauthorized"}`))
	}))
	defer srv.Close()

	out, err := runAuthStatus(t, srv.URL, "stale-tok", true)
	if code := exitCode(err); code != 1 {
		t.Fatalf("--json 401 should still return ExitCodeError{Code:1}, got code=%d err=%v", code, err)
	}
	var body struct {
		Authenticated bool `json:"authenticated"`
	}
	if jerr := json.Unmarshal([]byte(out), &body); jerr != nil {
		t.Fatalf("--json output is not valid JSON: %v\n%s", jerr, out)
	}
	if body.Authenticated {
		t.Errorf("--json body should encode authenticated=false on 401, got:\n%s", out)
	}
}

func TestAuthStatus_NotConfigured_ExitZero(t *testing.T) {
	out, err := runAuthStatus(t, "", "", false)
	if err != nil {
		t.Fatalf("unconfigured status should return nil error (exit 0), got: %v", err)
	}
	if !strings.Contains(out, "Not configured") {
		t.Errorf("expected 'Not configured' message, got:\n%s", out)
	}
}

func TestIsUnauthorizedErr(t *testing.T) {
	if isUnauthorizedErr(nil) {
		t.Error("nil error should not be unauthorized")
	}
	if isUnauthorizedErr(errors.New("dial tcp: connection refused")) {
		t.Error("plain transport error should not be unauthorized")
	}
	if !isUnauthorizedErr(&apiError{Code: "HTTP 401", Message: "unauthorized"}) {
		t.Error("HTTP 401 apiError should be unauthorized")
	}
	if !isUnauthorizedErr(&apiError{Code: "CHW-1234", Message: "token expired (401)"}) {
		t.Error("401 in message should be recognised as unauthorized")
	}
}
