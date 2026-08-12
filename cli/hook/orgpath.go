// Package hook — org-scoped repository path helper (BUG-A6).
//
// Every ecosystem URL emitted by install-hook must include the caller's
// org slug as `/repository/@<orgSlug>/<ecosystem>/...`. Legacy slug-less
// URLs are rejected by the backend with CHW-4314
// ("org-scoped URL required: /repository/@{org-slug}/{repo-name}/...;
// legacy URLs without the org slug are disabled on this instance").
//
// The server-side renderer in internal/server/server_configsnippets.go
// applies the same rule. This file mirrors that helper for the CLI so
// `chainsaw install-hook <ecosystem>` produces URLs the proxy accepts.
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

// OrgScopedRepoPath returns "chainproxy/repository/@<orgSlug>/<ecosystem>"
// — the path segment every install-hook template splices in between the
// host base and the ecosystem-specific suffix (e.g. "/simple/" for pip,
// "/v3/index.json" for nuget, "/" for npm/yarn/bun/cargo).
//
// The `chainproxy/` prefix matches the production reverse-proxy mount —
// nginx routes chain305.com/chainproxy/* to the proxy backend, and the
// dashboard's "Save this secret now" page (POST /api/clients) emits
// snippets in the exact same `chainproxy/repository/@<slug>/<ecosystem>/`
// shape. The CLI's `chainsaw --server https://chain305.com install-hook
// <ecosystem>` MUST produce the same URL or every install fails with
// HTTP 400 / 404 because the bare /repository/... path is unrouted at
// the edge.
//
// Empty orgSlug falls back to placeholderOrgSlug rather than emitting
// the legacy slug-less form, which the proxy rejects with CHW-4314.
//
// Docker registry mirroring deliberately does NOT use this helper —
// docker login takes a bare host (no path), and the proxy mounts the
// docker registry under a different routing rule. See docker.go.
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
	return "chainproxy/repository/@" + slug + "/" + ecosystem, nil
}
