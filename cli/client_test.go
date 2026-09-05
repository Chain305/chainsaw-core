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

// ── B1: the flat {"error":<string>,"hint":…} shape and the doubled 401 hint ──
//
// respondUnauthorized (internal/server) writes {"error":"authentication
// required","hint":"…"} — no code, no message. parseAPIError had no shape for
// it, so the raw JSON became Message and the user read
// `HTTP 401: {"error":"authentication required","hint":"…"} — run 'chainsaw
// auth login' to authenticate` followed by renderError's own
// `Hint: run \`chainsaw auth login\``: the JSON dumped verbatim and the same
// remediation printed twice.

func TestParseAPIError_FlatErrorStringShape(t *testing.T) {
	body := `{"error":"authentication required","hint":"include a Bearer token from /api/auth/login","request_id":"r-1"}`
	got := parseAPIError(401, []byte(body))
	if got.Code != "HTTP 401" {
		t.Errorf("Code = %q, want HTTP 401", got.Code)
	}
	if got.Message != "authentication required" {
		t.Errorf("Message = %q, want the bare error string", got.Message)
	}
	if got.Reason != "include a Bearer token from /api/auth/login" {
		t.Errorf("Reason = %q, want the hint", got.Reason)
	}
	if got.Status != 401 {
		t.Errorf("Status = %d, want 401", got.Status)
	}
	if e := got.Error(); e != "HTTP 401: authentication required" {
		t.Errorf("Error() = %q, want %q", e, "HTTP 401: authentication required")
	}
	if strings.Contains(got.Error(), "{") {
		t.Errorf("Error() still carries raw JSON: %q", got.Error())
	}
}

func TestParseAPIError_FlatErrorStringReasonFallback(t *testing.T) {
	// respondEmailNotVerified uses `reason`, not `hint`.
	got := parseAPIError(403, []byte(`{"error":"email not verified","reason":"verify your address first"}`))
	if got.Message != "email not verified" || got.Reason != "verify your address first" {
		t.Errorf("got Message=%q Reason=%q", got.Message, got.Reason)
	}
	// hint wins over reason when both are present.
	got = parseAPIError(401, []byte(`{"error":"x","hint":"h","reason":"r"}`))
	if got.Reason != "h" {
		t.Errorf("Reason = %q, want hint to outrank reason", got.Reason)
	}
	// No hint at all (admin_intelligence.go, huggingface_handlers.go).
	got = parseAPIError(400, []byte(`{"error":"bad request"}`))
	if got.Message != "bad request" || got.Reason != "" || got.Code != "HTTP 400" {
		t.Errorf("got Code=%q Message=%q Reason=%q", got.Code, got.Message, got.Reason)
	}
}

func TestParseAPIError_NestedWithoutCodeStillSynthesizes(t *testing.T) {
	// `error` is an object with neither code nor message: not the nested
	// envelope, not the flat string. It must land in the synthesized shape
	// exactly as before B1.
	for _, body := range []string{
		`{"error":{"reason":"x"}}`,
		`{"error":""}`,
		`{"error":"   "}`,
		`{"error":42}`,
		`{"error":null}`,
	} {
		got := parseAPIError(401, []byte(body))
		if got.Code != "HTTP 401" {
			t.Errorf("%s: Code = %q, want HTTP 401", body, got.Code)
		}
		if got.Message != strings.TrimSpace(body) {
			t.Errorf("%s: Message = %q, want the raw body (synthesized shape)", body, got.Message)
		}
		if got.Reason != "" {
			t.Errorf("%s: Reason = %q, want empty", body, got.Reason)
		}
	}
}

// TestAPIClient_do_401PrintsAuthLoginHintExactlyOnce is the end-to-end half:
// a flat 401 from the server, through do() and renderError, must print the
// `chainsaw auth login` remediation exactly once and never the raw JSON.
func TestAPIClient_do_401PrintsAuthLoginHintExactlyOnce(t *testing.T) {
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprint(w, `{"error":"authentication required","hint":"include a Bearer token from /api/auth/login"}`)
	})

	err := clientAt(srv.URL).Get("/api/policies", nil)
	if err == nil {
		t.Fatal("expected a 401 error, got nil")
	}
	if err.Error() != "HTTP 401: authentication required" {
		t.Errorf("Error() = %q, want %q (no 401 suffix, no JSON)", err.Error(), "HTTP 401: authentication required")
	}
	stderr := captureStderr(t, func() { renderError(err) })
	if n := strings.Count(stderr, "chainsaw auth login"); n != 1 {
		t.Errorf("`chainsaw auth login` printed %d times, want exactly 1; stderr:\n%s", n, stderr)
	}
	if strings.Contains(stderr, "{") {
		t.Errorf("raw JSON reached the user; stderr:\n%s", stderr)
	}
	if !strings.Contains(stderr, "Error: HTTP 401: authentication required") {
		t.Errorf("stderr = %q, want the Error line", stderr)
	}
}

// TestAPIClient_do_403And429SuffixesKept: only the 401 suffix was the
// duplicate; the other two have no classifier hint and must survive.
func TestAPIClient_do_403And429SuffixesKept(t *testing.T) {
	srv := withTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/forbidden":
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprint(w, `{"error":"forbidden"}`)
		default:
			w.Header().Set("Retry-After", "7")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = fmt.Fprint(w, `{"error":"slow down"}`)
		}
	})
	c := clientAt(srv.URL)
	if err := c.Get("/forbidden", nil); err == nil || !strings.Contains(err.Error(), "does not have permission") {
		t.Errorf("403 suffix lost: %v", err)
	}
	if err := c.Get("/limited", nil); err == nil || !strings.Contains(err.Error(), "retry after 7 seconds") {
		t.Errorf("429 suffix lost: %v", err)
	}
}
