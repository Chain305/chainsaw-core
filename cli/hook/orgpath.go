// Package hook — org-scoped repository path helper (BUG-A6).
//
// Every ecosystem URL emitted by install-hook must include the caller's
// org slug as `/repository/@<orgSlug>/<ecosystem>/...`. Legacy slug-less
// URLs are rejected by the backend with CHW-4314
// ("org-scoped URL required: /repository/@{org-slug}/{repo-name}/...;
// legacy URLs without the org slug are disabled on this instance").
//
// The server-side renderer in internal/server/server_configsnippets.go
// applies the same rule, and this file is its CLI mirror — deliberately
// down to the returned string, so `chainsaw install-hook <ecosystem>` and
// the dashboard's "Save this secret now" snippet emit the same URL.
// See docs/smoke-test-appsec-journey.md (BUG-A6, BUG-14) for the full
// failure recipe and the rationale for the fail-closed placeholder.
package hook

import (
	"fmt"
	"regexp"
	"strings"
)

// orgSlugPattern is the shape the server's own slugify produces and the only
// shape orgScopedRepoPath will splice into a config file (H4).
//
// The slug reaches us from --org (arbitrary user input) or from the server's
// /api/orgs JSON (arbitrary input if the server is hostile or MITM'd), and it
// lands in a Kotlin string literal, an XML element, a shell assignment and
// four URL templates. Constraining it here means none of those renderers can
// be broken out of via the slug, whatever their own escaping does. 63 chars
// matches the DNS-label limit the server slugs against.
var orgSlugPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// placeholderOrgSlug is the visible-broken fallback used when the CLI
// can't discover the caller's real org slug (no --org flag, no auth
// token, or the /api/orgs call failed). Picking a visible placeholder
// over the empty string keeps the resulting URL syntactically valid AND
// guarantees the proxy will reject it with CHW-4314, so the user gets
// a loud error instead of a silently-broken install months later.
const placeholderOrgSlug = "your-org-slug"

// OrgScopedRepoPath returns "repository/@<orgSlug>/<ecosystem>" — the path
// segment every install-hook template splices in between the server base
// URL and the ecosystem-specific suffix (e.g. "/simple/" for pip,
// "/v3/index.json" for nuget, "/" for npm/yarn/bun/cargo).
//
// NO deployment prefix is baked in here, and that is load-bearing (B5).
// `/chainproxy` is an OPTIONAL edge mount: nginx/Traefik route
// chain305.com/chainproxy/* to the proxy and STRIP the prefix before
// forwarding (docs/dockerized/README.md, docs/install-k3s-helm.md). The
// server itself routes on the literal `/repository/` prefix and has no
// StripPrefix anywhere — so a hardcoded `chainproxy/` here 404s on every
// root-mounted deployment: the documented `docker compose up` quick-start,
// a bare `chainsaw-proxy -listen :8787`, a `kubectl port-forward`.
//
// The deployment's base path, when it has one, therefore comes from the
// CONFIGURED SERVER URL's own path (`--server https://chain305.com/chainproxy`
// → `/chainproxy`; `--server http://localhost:8787` → none). Callers
// concatenate `<serverURL>/<this>/`. That is exactly the server's own model:
// internal/server/server_configsnippets.go's orgScopedRepoPath is likewise
// prefix-free and its callers prepend requestBaseURL(r), which contributes a
// base path only when the request actually arrived through one.
//
// Empty orgSlug falls back to placeholderOrgSlug rather than emitting
// the legacy slug-less form, which the proxy rejects with CHW-4314.
//
// Docker registry mirroring deliberately does NOT use this helper —
// dockerd's registry-mirrors entries must be a bare scheme://host with no
// path at all, and the proxy mounts the docker registry under a different
// routing rule. See docker.go.
// OrgScopedRepoPath is the lenient, exported form kept for callers that have
// no error channel (doctor's org-slug probe). An unusable slug degrades to
// the visible placeholder rather than being spliced in raw.
//
// Every install-hook renderer uses orgScopedRepoPath instead, so a bad slug
// there fails the wire loudly instead of writing a config the proxy will
// reject with CHW-4314.
func OrgScopedRepoPath(orgSlug, ecosystem string) string {
	path, err := orgScopedRepoPath(orgSlug, ecosystem)
	if err != nil {
		path, _ = orgScopedRepoPath("", ecosystem)
	}
	return path
}

// orgScopedRepoPath validates the slug before splicing it in. Empty is
// allowed and yields placeholderOrgSlug; anything else must match
// orgSlugPattern after lower-casing.
func orgScopedRepoPath(orgSlug, ecosystem string) (string, error) {
	slug := strings.ToLower(strings.TrimSpace(orgSlug))
	if slug == "" {
		slug = placeholderOrgSlug
	}
	if !orgSlugPattern.MatchString(slug) {
		return "", fmt.Errorf("invalid org slug %q: expected 1-63 characters matching [a-z0-9][a-z0-9-]* (e.g. acme-corp)", orgSlug)
	}
	return "repository/@" + slug + "/" + ecosystem, nil
}
