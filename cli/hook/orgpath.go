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

import "strings"

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
func OrgScopedRepoPath(orgSlug, ecosystem string) string {
	slug := strings.TrimSpace(orgSlug)
	if slug == "" {
		slug = placeholderOrgSlug
	}
	return "chainproxy/repository/@" + slug + "/" + ecosystem
}
