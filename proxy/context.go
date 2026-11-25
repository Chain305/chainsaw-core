package proxy

import (
	"context"
	"net/url"
	"strings"
)

type contextKey string

const (
	baseURLContextKey  contextKey = "proxy-base-url"
	orgIDContextKey    contextKey = "proxy-org-id"
	orgSlugContextKey  contextKey = "proxy-org-slug"
	linkRepoContextKey contextKey = "proxy-link-repo"
)

// WithLinkRepoName stores the repository name clients address when it differs
// from the one serving: a group repository routes a request to a member, and
// the links that member's documents emit must keep pointing at the group.
func WithLinkRepoName(ctx context.Context, name string) context.Context {
	if ctx == nil || name == "" {
		return ctx
	}
	return context.WithValue(ctx, linkRepoContextKey, name)
}

// LinkRepoName returns the name stored with WithLinkRepoName, or fallback.
func LinkRepoName(ctx context.Context, fallback string) string {
	if ctx != nil {
		if name, _ := ctx.Value(linkRepoContextKey).(string); name != "" {
			return name
		}
	}
	return fallback
}

// WithBaseURL stores the externally reachable base URL (scheme://host[:port][/prefix])
// for the current HTTP request so response transformers can emit absolute URLs.
//
// SECURITY (F25 belt-and-suspenders): any userinfo component (user:pass@) is
// stripped before storage. The proper fix lives in the caller (the server's
// requestBaseURL no longer extracts Basic-auth credentials), but this layer
// enforces the invariant: nothing emitted into a registry response body —
// npm tarball URLs, pypi files index links, cargo download URLs, etc. — may
// carry the requester's client_id:client_secret. See SECURITY.md.
func WithBaseURL(ctx context.Context, baseURL string) context.Context {
	baseURL = stripUserinfo(baseURL)
	if baseURL == "" {
		return ctx
	}
	return context.WithValue(ctx, baseURLContextKey, baseURL)
}

// stripUserinfo removes the userinfo component ("user:pass@") from a URL-like
// string. Returns the input unchanged when it does not parse as a URL with a
// scheme. Whitespace is trimmed.
func stripUserinfo(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return raw
	}
	if u.User == nil {
		return raw
	}
	u.User = nil
	return u.String()
}

// BaseURLFromContext returns the base URL previously stored with WithBaseURL.
func BaseURLFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	base, _ := ctx.Value(baseURLContextKey).(string)
	return base
}

// WithOrgID stores the org identifier for tenant-scoped proxy operations.
func WithOrgID(ctx context.Context, orgID string) context.Context {
	if ctx == nil || orgID == "" {
		return ctx
	}
	return context.WithValue(ctx, orgIDContextKey, orgID)
}

// OrgIDFromContext returns the org identifier stored with WithOrgID.
func OrgIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	orgID, _ := ctx.Value(orgIDContextKey).(string)
	return orgID
}

// WithOrgSlug stores the org slug for building org-scoped repository URLs.
func WithOrgSlug(ctx context.Context, slug string) context.Context {
	if ctx == nil || slug == "" {
		return ctx
	}
	return context.WithValue(ctx, orgSlugContextKey, slug)
}

// OrgSlugFromContext returns the org slug stored with WithOrgSlug.
func OrgSlugFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	slug, _ := ctx.Value(orgSlugContextKey).(string)
	return slug
}

type localOnlyKey struct{}

// WithLocalOnly marks a read the caller has already decided is a local
// upload: Get serves the stored copy or answers 404, and never fetches
// upstream. Without it, a copy removed between the caller's check and the
// facet's read (a concurrent delete) was filled from the public namesake.
func WithLocalOnly(ctx context.Context) context.Context {
	return context.WithValue(ctx, localOnlyKey{}, true)
}

// LocalOnlyFromContext reports whether ctx carries WithLocalOnly.
func LocalOnlyFromContext(ctx context.Context) bool {
	v, _ := ctx.Value(localOnlyKey{}).(bool)
	return v
}

// OrgScopedRepoPrefix returns the repository path prefix with org slug scoping.
// If orgSlug is empty, it returns the legacy unscoped prefix.
func OrgScopedRepoPrefix(orgSlug, repoName string) string {
	if orgSlug != "" {
		return "/repository/@" + orgSlug + "/" + repoName + "/"
	}
	return "/repository/" + repoName + "/"
}
