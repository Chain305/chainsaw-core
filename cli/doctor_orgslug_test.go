package cli

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestProbeOrgSlugClassification is the core table for WS2 #10: the
// wrong-org-slug probe must fail LOUD + CLOSED on a genuine CHW-4314/400
// (or CHW-1303/404 unknown-org) rejection, pass silently on a valid slug
// (200 / any non-rejection status), and NEVER false-positive on a timeout
// or transport error.
func TestProbeOrgSlugClassification(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		body        string
		wantOutcome orgSlugOutcome
		wantCode    string
	}{
		{
			name:        "400 CHW-4314 missing slug -> loud wrong-slug",
			status:      http.StatusBadRequest,
			body:        `{"code":"CHW-4314","message":"org-scoped URL required"}`,
			wantOutcome: orgSlugWrongSlug,
			wantCode:    "CHW-4314",
		},
		{
			name:        "404 CHW-1303 unknown org -> loud wrong-slug",
			status:      http.StatusNotFound,
			body:        `{"code":"CHW-1303","message":"unknown organization \"typo-slug\""}`,
			wantOutcome: orgSlugWrongSlug,
			wantCode:    "CHW-1303",
		},
		{
			name:        "200 valid slug -> ok (silent pass)",
			status:      http.StatusOK,
			body:        `{}`,
			wantOutcome: orgSlugOK,
		},
		{
			name:        "401 on a valid org-scoped path -> ok (auth is a different problem, not a wrong slug)",
			status:      http.StatusUnauthorized,
			body:        `{"code":"CHW-1001","message":"unauthorized"}`,
			wantOutcome: orgSlugOK,
		},
		{
			name:        "generic 404 with no CHW-1303 (nonexistent package on a CORRECT slug) -> ok, NOT wrong-slug",
			status:      http.StatusNotFound,
			body:        `{"code":"CHW-4300","message":"package not found"}`,
			wantOutcome: orgSlugOK,
		},
		{
			name:        "bare 400 with no CHW code -> ok, NOT wrong-slug (no false positive on ambiguous 400)",
			status:      http.StatusBadRequest,
			body:        `bad request`,
			wantOutcome: orgSlugOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// The probe must hit the org-scoped repo base path.
				if !strings.Contains(r.URL.Path, "/repository/@acme-corp/npm") {
					t.Errorf("probe hit unexpected path %q", r.URL.Path)
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			res := probeOrgSlug(context.Background(), srv.URL, "tok", "acme-corp")
			if res.Outcome != tc.wantOutcome {
				t.Fatalf("outcome = %q, want %q (reason: %s)", res.Outcome, tc.wantOutcome, res.Reason)
			}
			if tc.wantCode != "" && res.ErrorCode != tc.wantCode {
				t.Fatalf("error_code = %q, want %q", res.ErrorCode, tc.wantCode)
			}
		})
	}
}

// TestProbeOrgSlugTimeoutIsNotWrongSlug is the load-bearing guardrail: a
// server that never responds within the probe window (timeout) must degrade
// to NET_ERROR, NOT WRONG_SLUG. A flaky/unreachable network is not a
// misconfiguration.
//
// The handler blocks on the REQUEST context (r.Context()) rather than a
// test-local channel, so when the probe's context deadline fires the client
// aborts the request, the server sees the cancelled connection, and the
// handler returns cleanly — no lingering connection to deadlock srv.Close().
func TestProbeOrgSlugTimeoutIsNotWrongSlug(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done() // return only once the client gives up (probe timeout)
	}))
	defer srv.Close()

	// Drive with a context deadline shorter than the 8s probe timeout so the
	// probe times out deterministically without waiting the full window.
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	res := probeOrgSlug(ctx, srv.URL, "tok", "acme-corp")
	if res.Outcome != orgSlugNetErr {
		t.Fatalf("timeout outcome = %q, want %q — a timeout must NEVER be reported as a wrong slug", res.Outcome, orgSlugNetErr)
	}
	if res.ErrorCode != "" {
		t.Fatalf("timeout must not carry a CHW error code, got %q", res.ErrorCode)
	}
}

// TestProbeOrgSlugTransportErrorIsNotWrongSlug: a connection-refused
// (server closed) transport error also degrades to NET_ERROR, never
// WRONG_SLUG.
func TestProbeOrgSlugTransportErrorIsNotWrongSlug(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close() // now connecting to url will be refused

	res := probeOrgSlug(context.Background(), url, "tok", "acme-corp")
	if res.Outcome != orgSlugNetErr {
		t.Fatalf("transport error outcome = %q, want %q", res.Outcome, orgSlugNetErr)
	}
}

// TestProbeOrgSlugSkips: no server or no slug means there is nothing to
// probe. The free local guard needs no org slug, so this must be SKIPPED,
// never a failure.
func TestProbeOrgSlugSkips(t *testing.T) {
	if got := probeOrgSlug(context.Background(), "", "tok", "acme-corp").Outcome; got != orgSlugSkipped {
		t.Fatalf("no server: outcome = %q, want %q", got, orgSlugSkipped)
	}
	if got := probeOrgSlug(context.Background(), "https://example.com", "tok", "").Outcome; got != orgSlugSkipped {
		t.Fatalf("no slug: outcome = %q, want %q", got, orgSlugSkipped)
	}
}

// TestClassifyOrgSlugRejection unit-tests the single decision function in
// isolation from HTTP so the wrong-slug boundary is pinned.
func TestClassifyOrgSlugRejection(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantCode string
		wantHit  bool
	}{
		{"chw-4314 json", 400, `{"code":"CHW-4314"}`, "CHW-4314", true},
		{"chw-1303 json", 404, `{"code":"CHW-1303"}`, "CHW-1303", true},
		{"chw-4314 raw body fallback on 400", 400, `error CHW-4314 org-scoped URL required`, "CHW-4314", true},
		{"generic 404 not a slug rejection", 404, `{"code":"CHW-4300"}`, "", false},
		{"generic 400 not a slug rejection", 400, `bad request`, "", false},
		{"200 never a rejection", 200, `{}`, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, hit := classifyOrgSlugRejection(c.status, []byte(c.body))
			if hit != c.wantHit || code != c.wantCode {
				t.Fatalf("classify(%d,%q) = (%q,%v), want (%q,%v)", c.status, c.body, code, hit, c.wantCode, c.wantHit)
			}
		})
	}
}

// TestOrgSlugProbeURLShape verifies the probe targets the byte-identical
// org-scoped path a wired client would use, and does not double the
// /chainproxy prefix for a self-hosted URL that already carries it.
func TestOrgSlugProbeURLShape(t *testing.T) {
	cases := []struct {
		server string
		slug   string
		want   string
	}{
		{"https://chain305.com", "acme", "https://chain305.com/chainproxy/repository/@acme/npm/"},
		{"https://chain305.com/", "acme", "https://chain305.com/chainproxy/repository/@acme/npm/"},
		{"https://host/chainproxy", "acme", "https://host/chainproxy/repository/@acme/npm/"},
	}
	for _, c := range cases {
		if got := orgSlugProbeURL(c.server, c.slug); got != c.want {
			t.Errorf("orgSlugProbeURL(%q,%q) = %q, want %q", c.server, c.slug, got, c.want)
		}
	}
}
