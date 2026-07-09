package provenance

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
)

// OCITransport is an http.RoundTripper-like wrapper that transparently
// handles the OCI distribution-spec bearer-token challenge. On a 401 with
// a Bearer WWW-Authenticate header it exchanges the advertised scope for
// an anonymous token at the named auth realm, then retries the request.
//
// Tokens are cached per (realm, service, scope) for their advertised
// lifetime (with a 5 s safety margin, floored to a 30 s minimum). Only
// anonymous scopes are requested — this is a read-only public-registry
// client, not a full credential manager.
//
// Use OCITransport.Do like http.Client.Do. The transport distinguishes
// error paths so callers can map responses to the right provenance
// Status:
//
//   - final HTTP 401 after token exchange → registry refused the
//     advertised scope (auth misconfigured) — caller should return
//     StatusFailed, not StatusMissing
//   - HTTP 404 → artifact genuinely absent — StatusMissing
//   - network / transport failure → StatusFailed
//
// OCITransport is exported so follow-on provenance fetchers in this
// package (e.g. the Referrers-API cryptographic-verify path) can share
// the same auth + token-caching behaviour instead of re-implementing the
// challenge flow.
type OCITransport struct {
	client *http.Client

	mu     sync.Mutex
	tokens map[string]cachedToken
	clock  func() time.Time
}

// ociTransport is an unexported alias retained so existing call sites in
// this package don't all have to be touched when we exported the type.
// New code should prefer OCITransport.
type ociTransport = OCITransport

type cachedToken struct {
	token     string
	expiresAt time.Time
}

// NewOCITransport constructs an OCITransport that wraps the given
// http.Client. A nil client falls back to a chainsaw-tuned client; the
// previous fallback was http.DefaultClient (no timeout,
// MaxIdleConnsPerHost=2). The returned transport is safe for
// concurrent use.
func NewOCITransport(base *http.Client) *OCITransport {
	if base == nil {
		base = httpclient.New()
	}
	return &OCITransport{
		client: base,
		tokens: map[string]cachedToken{},
		clock:  time.Now,
	}
}

// newOCITransport is an internal alias for NewOCITransport kept so that
// in-package callers stay stylistically consistent with other unexported
// constructors (newNPMChecker, newOCIChecker, ...).
func newOCITransport(base *http.Client) *OCITransport { return NewOCITransport(base) }

// Do sends req, transparently handling a single 401/Bearer challenge cycle.
// Callers use this like an http.Client.Do but may get the request back with
// an Authorization header injected.
func (t *OCITransport) Do(req *http.Request) (*http.Response, error) {
	// First, try an unauthenticated request. Anonymous public-read
	// endpoints succeed here without any auth, so we avoid burning a token
	// exchange on every request.
	resp, err := t.client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}
	challenge := parseWWWAuthenticate(resp.Header.Get("Www-Authenticate"))
	if !strings.EqualFold(challenge.scheme, "Bearer") || challenge.realm == "" {
		// Not a recoverable challenge — return the 401 for the caller to
		// handle.
		return resp, nil
	}
	_ = resp.Body.Close()

	token, err := t.fetchToken(req.Context(), challenge)
	if err != nil {
		return nil, fmt.Errorf("oci token exchange: %w", err)
	}

	// Retry with the token. Clone the request so we don't mutate the
	// caller's copy.
	req2 := req.Clone(req.Context())
	req2.Header.Set("Authorization", "Bearer "+token)
	// Ensure the body can be re-sent. For GET/HEAD there's typically no
	// body; for the paths we exercise (manifests, blobs, referrers) this
	// is always the case.
	return t.client.Do(req2)
}

type bearerChallenge struct {
	scheme  string
	realm   string
	service string
	scope   string
}

// parseWWWAuthenticate extracts the parameters from a WWW-Authenticate
// header of the form `Bearer realm="…",service="…",scope="…"`. Minimal
// tokenizer sufficient for the OCI distribution spec; ignores parameters
// it does not recognize.
func parseWWWAuthenticate(h string) bearerChallenge {
	c := bearerChallenge{}
	if h == "" {
		return c
	}
	// Split into scheme and params.
	space := strings.IndexByte(h, ' ')
	if space < 0 {
		c.scheme = strings.TrimSpace(h)
		return c
	}
	c.scheme = strings.TrimSpace(h[:space])
	params := h[space+1:]

	// Params are comma-separated key=value, where value may be quoted.
	// A minimal state machine handles quoted commas.
	var key, val strings.Builder
	inKey, inQuote := true, false
	flush := func() {
		k := strings.TrimSpace(key.String())
		v := val.String()
		switch strings.ToLower(k) {
		case "realm":
			c.realm = v
		case "service":
			c.service = v
		case "scope":
			c.scope = v
		}
		key.Reset()
		val.Reset()
		inKey = true
	}
	for i := 0; i < len(params); i++ {
		ch := params[i]
		switch {
		case inKey && ch == '=':
			inKey = false
		case !inKey && ch == '"':
			inQuote = !inQuote
		case !inKey && ch == ',' && !inQuote:
			flush()
		case inKey:
			key.WriteByte(ch)
		default:
			val.WriteByte(ch)
		}
	}
	// Flush tail if we accumulated anything.
	if key.Len() > 0 || val.Len() > 0 {
		flush()
	}
	return c
}

// fetchToken exchanges a bearer challenge for an anonymous token. Results
// are cached per (realm, service, scope) until expiresAt.
func (t *OCITransport) fetchToken(ctx context.Context, c bearerChallenge) (string, error) {
	key := c.realm + "|" + c.service + "|" + c.scope
	t.mu.Lock()
	if tok, ok := t.tokens[key]; ok && t.clock().Before(tok.expiresAt) {
		t.mu.Unlock()
		return tok.token, nil
	}
	t.mu.Unlock()

	tokenURL := c.realm
	q := queryBuilder{}
	q.add("service", c.service)
	q.add("scope", c.scope)
	if q.has() {
		sep := "?"
		if strings.Contains(tokenURL, "?") {
			sep = "&"
		}
		tokenURL = tokenURL + sep + q.encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tokenURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := t.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint %s: HTTP %d", tokenURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	var payload struct {
		Token     string `json:"token"`
		Access    string `json:"access_token"` // some registries (GCR) use this key
		ExpiresIn int    `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return "", fmt.Errorf("parse token response: %w", err)
	}
	tok := payload.Token
	if tok == "" {
		tok = payload.Access
	}
	if tok == "" {
		return "", fmt.Errorf("token response missing token field")
	}
	// Default TTL = 60 s. Real tokens often advertise 300 s; we shave a few
	// seconds so a near-expiry cache hit doesn't race the server.
	ttl := time.Duration(payload.ExpiresIn-5) * time.Second
	if ttl < 30*time.Second {
		ttl = 30 * time.Second
	}
	t.mu.Lock()
	t.tokens[key] = cachedToken{token: tok, expiresAt: t.clock().Add(ttl)}
	t.mu.Unlock()
	return tok, nil
}

// queryBuilder is a tiny query-string builder that preserves param order.
// The standard library's url.Values sorts keys alphabetically, which some
// registries are sensitive to when signing the token request.
type queryBuilder struct {
	pairs [][2]string
}

func (u *queryBuilder) add(k, v string) {
	if v == "" {
		return
	}
	u.pairs = append(u.pairs, [2]string{k, v})
}
func (u *queryBuilder) has() bool { return len(u.pairs) > 0 }
func (u *queryBuilder) encode() string {
	var b strings.Builder
	for i, p := range u.pairs {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(queryEscape(p[0]))
		b.WriteByte('=')
		b.WriteString(queryEscape(p[1]))
	}
	return b.String()
}

// queryEscape is a minimal percent-encoder for query values. We avoid
// net/url.QueryEscape because it encodes ':' which some registries reject
// in scope values like "repository:library/nginx:pull".
func queryEscape(s string) string {
	const safe = "-._~/:"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
			b.WriteByte(c)
		case strings.IndexByte(safe, c) >= 0:
			b.WriteByte(c)
		default:
			const hex = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&0x0F])
		}
	}
	return b.String()
}
