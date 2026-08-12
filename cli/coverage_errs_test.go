package cli

// C11 — a per-id 404 must not be reported as "coverage is not enabled on this
// server". C13 — --window must be query-escaped.

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
)

func TestTranslateCoverageCollectionErr_OnlyForCollections(t *testing.T) {
	notFound := errors.New("GET /api/coverage/summary: 404 not found")
	if got := translateCoverageCollectionErr(notFound); !strings.Contains(got.Error(), "coverage is not enabled") {
		t.Errorf("a collection 404 should still translate to the feature-off message; got %v", got)
	}
	if translateCoverageCollectionErr(nil) != nil {
		t.Errorf("nil in, nil out")
	}
	other := errors.New("500 internal server error")
	if got := translateCoverageCollectionErr(other); got != other {
		t.Errorf("non-404 errors must pass through unchanged; got %v", got)
	}
}

// TestCoverageBypassConfirm_PerIDNotFoundIsNotTranslated: `coverage bypass
// confirm 999` against a server with coverage.enabled: true used to print
// "coverage is not enabled on this server (set coverage.enabled: true …)",
// sending the operator to fix a config problem that does not exist.
func TestCoverageBypassConfirm_PerIDNotFoundIsNotTranslated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"code":"CHW-4004","message":"bypass report not found"}}`, http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := &cobra.Command{Use: "confirm"}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})

	err := runCoverageBypassConfirm(cmd, []string{"999"})
	if err == nil {
		t.Fatal("expected an error for a missing bypass report id")
	}
	if strings.Contains(err.Error(), coverageDisabledMessage) {
		t.Errorf("per-id 404 mis-reported as the feature being disabled: %v", err)
	}
}

func TestCoverageWindowQuery_Escapes(t *testing.T) {
	if got := coverageWindowQuery(""); got != "" {
		t.Errorf("empty window should add no query string, got %q", got)
	}
	got := coverageWindowQuery("7d&export=true")
	if strings.Contains(got, "&export=true") {
		t.Fatalf("--window smuggled a second parameter into the request: %q", got)
	}
	parsed, err := url.ParseQuery(strings.TrimPrefix(got, "?"))
	if err != nil {
		t.Fatalf("parse %q: %v", got, err)
	}
	if len(parsed) != 1 || parsed.Get("window") != "7d&export=true" {
		t.Errorf("window query = %v, want exactly one window parameter", parsed)
	}
}

// TestCoverageSummary_WindowReachesServerEscaped is the wire-level version.
func TestCoverageSummary_WindowReachesServerEscaped(t *testing.T) {
	var mu sync.Mutex
	var gotQuery url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotQuery = r.URL.Query()
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"window":"7d"}`))
	}))
	t.Cleanup(srv.Close)
	setViperServer(t, srv.URL)

	cmd := &cobra.Command{Use: "summary"}
	cmd.Flags().String("window", "", "")
	cmd.Flags().Bool("json", false, "")
	cmd.Flags().String("format", "", "")
	cmd.Flags().String("output", "", "")
	if err := cmd.Flags().Set("window", "7d&export=true"); err != nil {
		t.Fatalf("set window: %v", err)
	}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	if err := runCoverageSummary(cmd, nil); err != nil {
		t.Fatalf("runCoverageSummary: %v", err)
	}

	mu.Lock()
	q := gotQuery
	mu.Unlock()
	if q.Get("export") != "" {
		t.Errorf("--window injected an export parameter: %v", q)
	}
	if q.Get("window") != "7d&export=true" {
		t.Errorf("window = %q, want the flag value verbatim", q.Get("window"))
	}
}
