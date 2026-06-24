package cli

// client_test.go covers the HTTP error translation done by APIClient.do.
//
// The main thing being protected here is the "you pointed --server at the
// wrong URL" footgun: when a user passes a host without the /chainproxy
// prefix, the CLI used to dump a raw nginx 404 HTML page verbatim. The
// heuristic in client.go now detects generic infrastructure 404/502 HTML
// responses (no Chainsaw JSON envelope, HTML content-type, "Not Found" /
// "Bad Gateway" in the body) and replaces the dump with an actionable hint.
//
// We keep the existing apiError path untouched for any well-formed
// Chainsaw error envelope (those carry "code":"CHW-NNNN") — the test
// suite asserts that case is preserved.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// nginxNotFoundBody is the response body verbatim from the bug report.
const nginxNotFoundBody = `<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>`

const nginxBadGatewayBody = `<html>
<head><title>502 Bad Gateway</title></head>
<body>
<center><h1>502 Bad Gateway</h1></center>
<hr><center>nginx</center>
</body>
</html>`

func TestAPIClient_do_NginxNotFoundReturnsFriendlyHint(t *testing.T) {
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, nginxNotFoundBody)
	})

	err := clientAt(srv.URL).Get("/api/policy", nil)
	if err == nil {
		t.Fatal("expected error from nginx 404, got nil")
	}

	// Should be the friendly server-URL error, not the raw apiError.
	if _, ok := err.(*serverURLError); !ok {
		t.Fatalf("expected *serverURLError, got %T: %v", err, err)
	}

	msg := err.Error()
	for _, want := range []string{
		"generic 404 HTML page",
		"missing the API prefix",
		"/chainproxy",
		srv.URL, // the bad base URL is echoed back so the user can compare
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q\nfull message:\n%s", want, msg)
		}
	}

	// And critically: the raw nginx HTML must NOT be dumped through to the user.
	if strings.Contains(msg, "<html>") || strings.Contains(msg, "<title>") {
		t.Errorf("friendly hint should not leak raw HTML body, got:\n%s", msg)
	}
}

func TestAPIClient_do_ChainsawJSONEnvelopePreserved(t *testing.T) {
	// A well-formed Chainsaw 404 — e.g. policy not found. Must fall through
	// to the standard apiError path and NOT trigger the URL-misconfig hint.
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		_, _ = fmt.Fprint(w, `{"code":"CHW-3001","message":"policy not found"}`)
	})

	err := clientAt(srv.URL).Get("/api/policies/does-not-exist", nil)
	if err == nil {
		t.Fatal("expected error from chainsaw 404, got nil")
	}
	if _, ok := err.(*serverURLError); ok {
		t.Fatalf("chainsaw JSON envelope must not be reclassified as serverURLError: %v", err)
	}
	apiErr, ok := err.(*apiError)
	if !ok {
		t.Fatalf("expected *apiError, got %T: %v", err, err)
	}
	if apiErr.Code != "CHW-3001" {
		t.Errorf("expected code CHW-3001, got %q", apiErr.Code)
	}
	if !strings.Contains(apiErr.Message, "policy not found") {
		t.Errorf("expected message to contain 'policy not found', got %q", apiErr.Message)
	}
}

func TestAPIClient_do_NginxBadGatewayReturnsFriendlyHint(t *testing.T) {
	// 502 from a fronting proxy means the host is right but the chainsaw
	// proxy behind it is down. Different hint, same heuristic.
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = fmt.Fprint(w, nginxBadGatewayBody)
	})

	err := clientAt(srv.URL).Get("/api/policy", nil)
	if err == nil {
		t.Fatal("expected error from nginx 502, got nil")
	}
	if _, ok := err.(*serverURLError); !ok {
		t.Fatalf("expected *serverURLError, got %T: %v", err, err)
	}

	msg := err.Error()
	for _, want := range []string{
		"502 Bad Gateway",
		"chainsaw-proxy",
		srv.URL,
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("error message missing %q\nfull message:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "<html>") {
		t.Errorf("friendly hint should not leak raw HTML body, got:\n%s", msg)
	}
}

func TestServerURLMisconfigError_HeuristicBoundaries(t *testing.T) {
	// Unit-level coverage for the heuristic to prevent regression on the
	// gating predicates. Each case fixes a specific way the heuristic could
	// false-positive or false-negative.
	cases := []struct {
		name        string
		status      int
		contentType string
		body        string
		wantHint    bool
	}{
		{
			name:        "nginx 404 html -> hint",
			status:      404,
			contentType: "text/html",
			body:        nginxNotFoundBody,
			wantHint:    true,
		},
		{
			name:        "nginx 502 html -> hint",
			status:      502,
			contentType: "text/html",
			body:        nginxBadGatewayBody,
			wantHint:    true,
		},
		{
			name:        "401 html -> no hint (auth flow handles)",
			status:      401,
			contentType: "text/html",
			body:        nginxNotFoundBody,
			wantHint:    false,
		},
		{
			name:        "500 html -> no hint (server error, different problem)",
			status:      500,
			contentType: "text/html",
			body:        "<html><h1>500</h1></html>",
			wantHint:    false,
		},
		{
			name:        "404 json -> no hint",
			status:      404,
			contentType: "application/json",
			body:        `{"code":"CHW-3001","message":"x"}`,
			wantHint:    false,
		},
		{
			name:        "404 html with CHW code in body -> no hint",
			status:      404,
			contentType: "text/html",
			body:        `<html><title>404 Not Found</title>{"code":"CHW-9999"}</html>`,
			wantHint:    false,
		},
		{
			name:        "404 html no title/h1 -> no hint",
			status:      404,
			contentType: "text/html",
			body:        `<html><body>nope</body></html>`,
			wantHint:    false,
		},
		{
			name:        "404 html with title but no 404 indicator -> no hint",
			status:      404,
			contentType: "text/html",
			body:        `<html><title>Welcome</title></html>`,
			wantHint:    false,
		},
		{
			name:        "404 html with charset suffix -> hint",
			status:      404,
			contentType: "text/html; charset=utf-8",
			body:        nginxNotFoundBody,
			wantHint:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := serverURLMisconfigError("https://example.com", tc.status, tc.contentType, []byte(tc.body))
			if tc.wantHint && got == nil {
				t.Fatal("expected hint, got nil")
			}
			if !tc.wantHint && got != nil {
				t.Fatalf("expected no hint, got: %v", got)
			}
		})
	}
}

// Ensure httptest is referenced (Go compiler) — the helper lives in finding_test.go
var _ = httptest.NewServer
