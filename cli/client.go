package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
)

const userAgent = "chainsaw-cli/1.0"

// DryRunHeader is the request header the server inspects to branch a
// destructive verb into preview mode (see internal/server/dryrun.go). The CLI
// sets this header when the operator passes `--dry-run` on a command that
// implements the convention (policy delete, exception delete, token revoke).
const DryRunHeader = "X-Chainsaw-Dry-Run"

// APIClient makes authenticated JSON requests to the Chainsaw API.
type APIClient struct {
	baseURL string
	token   string
	http    *http.Client
	// extraHeaders are per-client request headers applied on every call.
	// Used by WithHeader to bolt on cross-cutting knobs like --dry-run
	// without changing every call-site's method signature.
	extraHeaders map[string]string
	// requireToken makes do() refuse BEFORE any network call when no token is
	// configured, returning ExitConfigAuth(3) instead of letting the request
	// go out unauthenticated and come back as a server 401 (which the caller
	// then rendered as an opaque operational failure).
	//
	// X4: set ONLY by newClient() (root.go) — the constructor every
	// authenticated subcommand uses. NewAPIClient deliberately leaves it
	// false: NewAPIClient(server, "") is the ANONYMOUS client used for the
	// routes on the server's allowAnonymousPath list (SSO discover,
	// /api/auth/cli/init, the device-code poll, /api/auth/cli/exchange,
	// /api/public/meta). Those must keep working with no token — that is how
	// a user obtains one.
	requireToken bool
}

// NewAPIClient constructs an APIClient for the given server and bearer token.
func NewAPIClient(baseURL, token string) *APIClient {
	return &APIClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    httpclient.New(httpclient.WithTimeout(30 * time.Second)),
	}
}

// newAPIClientWithTimeout is NewAPIClient with a caller-supplied overall HTTP
// timeout. Unexported because the 30s default is the right answer for the ~40
// commands that make one small request; the few long-running POSTs (scan with
// up to 10k packages) need their own budget without changing everyone else's.
// A non-positive timeout falls back to the shared default.
func newAPIClientWithTimeout(baseURL, token string, timeout time.Duration) *APIClient {
	c := NewAPIClient(baseURL, token)
	if timeout > 0 {
		c.http = httpclient.New(httpclient.WithTimeout(timeout))
	}
	return c
}

// WithHeader returns a shallow copy of the client with an additional request
// header that will be attached to every subsequent call. Use for flags like
// `--dry-run` that need to flow into the HTTP layer without threading a new
// parameter through every verb. Empty name or value is a no-op (returns the
// receiver unchanged) so command wrappers can always call this unconditionally.
func (c *APIClient) WithHeader(name, value string) *APIClient {
	if c == nil {
		return nil
	}
	if strings.TrimSpace(name) == "" || value == "" {
		return c
	}
	headers := make(map[string]string, len(c.extraHeaders)+1)
	for k, v := range c.extraHeaders {
		headers[k] = v
	}
	headers[name] = value
	return &APIClient{
		baseURL:      c.baseURL,
		token:        c.token,
		http:         c.http,
		extraHeaders: headers,
		requireToken: c.requireToken,
	}
}

// apiError is the standard error envelope returned by the server. The
// Code/Message/Reason/Docs fields are the CHW-NNNN structured fields the
// server emits via errcodes.WriteError.
//
// A1′: the server's wire shape is NESTED — internal/errcodes writes
// `{"error":{"code":…,"message":…,"reason":…,"docs":…}}` — while this struct
// declared the fields at the TOP level. Unmarshalling therefore always left
// Code/Reason/Docs empty, which (a) made renderError's entire CHW- branch
// dead code, (b) dumped the raw JSON body into Message, and (c) made
// classifyCLIError substring-match INSIDE that JSON: a 500 carrying
// CHW-5401 classified as "auth". parseAPIError below handles both shapes;
// do NOT go back to unmarshalling a response body straight into this struct.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Reason  string `json:"reason,omitempty"`
	Docs    string `json:"docs,omitempty"`
	// Status is the HTTP status the envelope arrived with, stamped by the
	// transport on EVERY construction path. It is the authoritative signal
	// for "was this a 401" — the CHW code is not (13 distinct auth codes live
	// in registry_auth.go alone) and the message text certainly is not.
	//
	// Tagged `json:"-"`: Status is never part of the wire shape, and a
	// server-controlled "status" field must never be able to overwrite what
	// the transport observed.
	Status int `json:"-"`
}

func (e *apiError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return e.Code
}

// parseAPIError decodes a >=400 response body into an apiError. Three shapes
// are tried in order, and Status is stamped from the response on all of them:
//
//  1. NESTED — {"error":{"code":"CHW-1001","message":…,"reason":…,"docs":…}}.
//     What internal/errcodes.WriteError emits, i.e. every structured server
//     error. This is the shape the CLI previously could not read at all.
//  2. LEGACY FLAT — {"code":…,"message":…}, written by handlers predating
//     errcodes. Kept so a mixed-version fleet degrades cleanly.
//  3. FLAT STRING (B1) — {"error":"authentication required","hint":…} or
//     {"error":…,"reason":…}: what respondUnauthorized, respondEmailNotVerified
//     and a few admin/huggingface handlers write. `error` is decoded as `any`
//     and accepted only when it is a non-empty string, so a nested object
//     without code/message ({"error":{"reason":"x"}}) does NOT match here.
//     Message=error, Reason=hint (falling back to reason), Code="HTTP <status>".
//     Before this the raw JSON landed in Message and the user read
//     `HTTP 401: {"error":"authentication required","hint":"…"}`.
//  4. SYNTHESIZED — nothing parsed (an HTML page, an empty body): Code
//     becomes "HTTP <status>" and the raw body becomes Message. Byte-identical
//     to the pre-A1′ fallback, so nothing regresses on those wire shapes.
//
// Total by construction: it never returns nil and never fails.
func parseAPIError(status int, body []byte) *apiError {
	out := &apiError{Status: status}

	var nested struct {
		Error struct {
			Code             string `json:"code"`
			Message          string `json:"message"`
			Reason           string `json:"reason"`
			Docs             string `json:"docs"`
			DocumentationURL string `json:"documentation_url"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &nested); err == nil &&
		(nested.Error.Code != "" || nested.Error.Message != "") {
		out.Code = nested.Error.Code
		out.Message = nested.Error.Message
		out.Reason = nested.Error.Reason
		out.Docs = nested.Error.Docs
		if out.Docs == "" {
			out.Docs = nested.Error.DocumentationURL
		}
		if out.Code == "" {
			out.Code = fmt.Sprintf("HTTP %d", status)
		}
		return out
	}

	var flat apiError
	if err := json.Unmarshal(body, &flat); err == nil &&
		(flat.Code != "" || flat.Message != "") {
		out.Code = flat.Code
		out.Message = flat.Message
		out.Reason = flat.Reason
		out.Docs = flat.Docs
		if out.Code == "" {
			out.Code = fmt.Sprintf("HTTP %d", status)
		}
		return out
	}

	var flatString struct {
		Error  any    `json:"error"`
		Hint   string `json:"hint"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(body, &flatString); err == nil {
		if msg, ok := flatString.Error.(string); ok && strings.TrimSpace(msg) != "" {
			out.Code = fmt.Sprintf("HTTP %d", status)
			out.Message = strings.TrimSpace(msg)
			out.Reason = flatString.Hint
			if out.Reason == "" {
				out.Reason = flatString.Reason
			}
			return out
		}
	}

	out.Code = fmt.Sprintf("HTTP %d", status)
	out.Message = strings.TrimSpace(string(body))
	return out
}

func (c *APIClient) do(method, path string, body, out any) error {
	// X4 preflight: refuse before the network call rather than after a 401.
	// Only clients built by newClient() opt into this (see requireToken).
	// A2: when the token is missing because --token / CHAINSAW_TOKEN was
	// passed EMPTY, say so — the stored credential exists and was skipped on
	// purpose, so "run auth login" would send the operator the wrong way.
	if c.requireToken && c.token == "" {
		return notAuthenticatedError(nil)
	}
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.baseURL+path, bodyReader)
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	// Apply any client-scoped extra headers (e.g. X-Chainsaw-Dry-Run set
	// via WithHeader). Applied after the baseline headers so a caller
	// can't accidentally overwrite Authorization.
	for name, value := range c.extraHeaders {
		req.Header.Set(name, value)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("request to %s failed: %w", c.baseURL+path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode >= 400 {
		// Detect generic infrastructure 404/502 HTML responses before falling
		// through to the standard error envelope. When the user points
		// --server at a host that's missing the /chainproxy prefix, nginx (or
		// whatever fronts the proxy) replies with a raw HTML 404 page that
		// has nothing to do with Chainsaw. Dumping that body verbatim is
		// unhelpful — surface a hint that they probably misconfigured the URL.
		if hint := serverURLMisconfigError(c.baseURL, resp.StatusCode, resp.Header.Get("Content-Type"), respBody); hint != nil {
			return hint
		}
		apiErr := parseAPIError(resp.StatusCode, respBody)
		// B1: no 401 suffix here. renderError's classifier already prints
		// "Hint: run `chainsaw auth login`" for Status==401 (root.go), so a
		// suffix on the message made the same hint print twice. 403 and 429
		// keep theirs — no classifier hint exists for them.
		switch resp.StatusCode {
		case 403:
			apiErr.Message = apiErr.Message + " — your token does not have permission for this action"
		case 429:
			hint := resp.Header.Get("Retry-After")
			if hint != "" {
				apiErr.Message = apiErr.Message + fmt.Sprintf(" — rate limited; retry after %s seconds", hint)
			} else {
				apiErr.Message = apiErr.Message + " — rate limited; please wait before retrying"
			}
		}
		return apiErr
	}

	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

func (c *APIClient) Get(path string, out any) error {
	return c.do(http.MethodGet, path, nil, out)
}

func (c *APIClient) Post(path string, body, out any) error {
	return c.do(http.MethodPost, path, body, out)
}

func (c *APIClient) Patch(path string, body, out any) error {
	return c.do(http.MethodPatch, path, body, out)
}

func (c *APIClient) Delete(path string) error {
	return c.do(http.MethodDelete, path, nil, nil)
}

// DeleteInto issues DELETE and decodes the response body into out. Used on
// the dry-run path, where the server replies with a 200 {dry_run, would,
// target} payload instead of the usual 204 No Content.
func (c *APIClient) DeleteInto(path string, out any) error {
	return c.do(http.MethodDelete, path, nil, out)
}

// serverURLError is the friendly error we return when the heuristic decides
// the user pointed --server at a host that isn't actually a Chainsaw proxy
// (raw nginx 404, upstream 502, etc.). Distinct from apiError so output
// formatters can recognize and skip the usual "HTTP NNN:" framing.
type serverURLError struct {
	baseURL string
	status  int
	message string
}

func (e *serverURLError) Error() string { return e.message }

// serverURLMisconfigError returns a friendly error when the response looks
// like a generic infrastructure 404/502 HTML page rather than a Chainsaw
// JSON error envelope. Returns nil to let the normal error path run.
//
// Heuristic (all must hold):
//   - status is 404 or 502
//   - Content-Type starts with text/html
//   - body contains a <title> or <h1> mentioning "404" / "Not Found" /
//     "Bad Gateway"
//   - body does NOT contain "code":"CHW-" (any well-formed Chainsaw error
//     envelope will include that substring)
func serverURLMisconfigError(baseURL string, status int, contentType string, body []byte) error {
	if status != http.StatusNotFound && status != http.StatusBadGateway {
		return nil
	}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if !strings.HasPrefix(ct, "text/html") {
		return nil
	}
	if bytes.Contains(body, []byte(`"code":"CHW-`)) {
		return nil
	}
	lower := bytes.ToLower(body)
	hasTitleOrH1 := bytes.Contains(lower, []byte("<title>")) || bytes.Contains(lower, []byte("<h1>"))
	if !hasTitleOrH1 {
		return nil
	}
	indicator := bytes.Contains(lower, []byte("404")) ||
		bytes.Contains(lower, []byte("not found")) ||
		bytes.Contains(lower, []byte("bad gateway"))
	if !indicator {
		return nil
	}

	display := strings.TrimRight(baseURL, "/")
	suggested := display + "/chainproxy"

	var msg string
	switch status {
	case http.StatusNotFound:
		msg = fmt.Sprintf(
			"server URL %q returned a generic 404 HTML page.\n"+
				"This usually means the URL is missing the API prefix.\n\n"+
				"Try one of:\n"+
				"  --server %s        (standard production)\n"+
				"  --server https://your-host/chainproxy           (self-hosted)\n\n"+
				"If the URL is correct, verify the Chainsaw proxy is running at that host.",
			display, suggested,
		)
	case http.StatusBadGateway:
		msg = fmt.Sprintf(
			"server URL %q returned a generic 502 Bad Gateway HTML page.\n"+
				"The host is reachable but the Chainsaw proxy behind it is not responding.\n\n"+
				"Check that:\n"+
				"  - the chainsaw-proxy process is running and healthy\n"+
				"  - the load balancer / reverse proxy can reach it\n"+
				"  - the URL still includes the /chainproxy prefix if required\n\n"+
				"If you control the deployment, see the chainsaw-proxy runbook.",
			display,
		)
	}
	return &serverURLError{baseURL: display, status: status, message: msg}
}
