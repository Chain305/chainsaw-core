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
}

// NewAPIClient constructs an APIClient for the given server and bearer token.
func NewAPIClient(baseURL, token string) *APIClient {
	return &APIClient{
		baseURL: strings.TrimRight(baseURL, "/"),
		token:   token,
		http:    httpclient.New(httpclient.WithTimeout(30 * time.Second)),
	}
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
	}
}

// apiError is the standard error envelope returned by the server. The shape
// mirrors internal/errcodes.responseError — Code/Message/Reason/Docs are the
// CHW-NNNN structured fields the server emits via errcodes.WriteError. Reason
// and Docs are optional on legacy callsites that have not yet migrated.
type apiError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Reason  string `json:"reason,omitempty"`
	Docs    string `json:"docs,omitempty"`
}

func (e *apiError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return e.Code
}

func (c *APIClient) do(method, path string, body, out any) error {
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
		var apiErr apiError
		_ = json.Unmarshal(respBody, &apiErr)
		if apiErr.Code == "" {
			apiErr.Code = fmt.Sprintf("HTTP %d", resp.StatusCode)
			if apiErr.Message == "" {
				apiErr.Message = strings.TrimSpace(string(respBody))
			}
		}
		switch resp.StatusCode {
		case 401:
			apiErr.Message = apiErr.Message + " — run 'chainsaw auth login' to authenticate"
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
		return &apiErr
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
