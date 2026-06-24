package proxy

import (
	"context"
	"testing"
)

func TestWithBaseURL_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"simple", "https://example.com", "https://example.com"},
		{"with prefix", "https://example.com/api", "https://example.com/api"},
		{"with port", "http://localhost:8080", "http://localhost:8080"},
		{"empty no-op", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := WithBaseURL(context.Background(), tc.in)
			got := BaseURLFromContext(ctx)
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBaseURLFromContext_MissingAndNil(t *testing.T) {
	if v := BaseURLFromContext(context.Background()); v != "" {
		t.Errorf("plain ctx: got %q, want empty", v)
	}
	//nolint:staticcheck // intentionally testing nil-ctx resilience
	if v := BaseURLFromContext(nil); v != "" {
		t.Errorf("nil ctx: got %q, want empty", v)
	}
}

func TestBaseURLFromContext_WrongTypeStored(t *testing.T) {
	// If someone stored the wrong type under our key, we must return "" not panic.
	ctx := context.WithValue(context.Background(), baseURLContextKey, 42)
	if v := BaseURLFromContext(ctx); v != "" {
		t.Errorf("expected empty on type mismatch, got %q", v)
	}
}

func TestWithBaseURL_EmptyReturnsSameCtx(t *testing.T) {
	parent := context.Background()
	got := WithBaseURL(parent, "")
	if got != parent {
		t.Errorf("empty baseURL should return original ctx unchanged")
	}
}

// regression-check: F25 — every ecosystem rewriter (npm, pypi, cargo,
// composer, swift, cocoapods) reads the base URL from this context. Any
// userinfo present in the input must be stripped before storage so a
// caller cannot leak Basic-auth credentials into a registry response
// body. This is the belt-and-suspenders defence; the proper fix lives in
// the server's requestBaseURL, which now constructs scheme://host only.
func TestPackumentTarballURL_NoEmbeddedCredentials_ContextStrip(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "user:pass strips to host-only",
			in:   "https://user:pass@chainsaw.example.com/chainproxy",
			want: "https://chainsaw.example.com/chainproxy",
		},
		{
			name: "real-shape secret is removed",
			in:   "https://smoke-test:PuSz3x2g4FaIzAcAz6JHFJCYpkK4zLkU@chain305.com/chainproxy",
			want: "https://chain305.com/chainproxy",
		},
		{
			name: "user-only (no password) is removed",
			in:   "https://lonely-user@chainsaw.example.com",
			want: "https://chainsaw.example.com",
		},
		{
			name: "no userinfo is preserved verbatim",
			in:   "https://chainsaw.example.com/chainproxy",
			want: "https://chainsaw.example.com/chainproxy",
		},
		{
			name: "URL-encoded userinfo is stripped",
			in:   "https://us%40er:p%40ss@chainsaw.example.com",
			want: "https://chainsaw.example.com",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := WithBaseURL(context.Background(), tc.in)
			got := BaseURLFromContext(ctx)
			if got != tc.want {
				t.Fatalf("F25 regression: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestWithBaseURL_Override(t *testing.T) {
	ctx := WithBaseURL(context.Background(), "https://a.example")
	ctx = WithBaseURL(ctx, "https://b.example")
	if got := BaseURLFromContext(ctx); got != "https://b.example" {
		t.Errorf("later WithBaseURL should shadow earlier: got %q", got)
	}
}

func TestWithOrgID_RoundTrip(t *testing.T) {
	ctx := WithOrgID(context.Background(), "org-123")
	if got := OrgIDFromContext(ctx); got != "org-123" {
		t.Errorf("got %q, want org-123", got)
	}
}

func TestWithOrgID_EmptyIsNoop(t *testing.T) {
	parent := context.Background()
	got := WithOrgID(parent, "")
	if got != parent {
		t.Errorf("empty orgID should be no-op")
	}
	if v := OrgIDFromContext(parent); v != "" {
		t.Errorf("expected empty, got %q", v)
	}
}

func TestWithOrgID_NilCtx(t *testing.T) {
	//nolint:staticcheck // testing nil-ctx resilience
	if got := WithOrgID(nil, "org-1"); got != nil {
		t.Errorf("nil ctx should stay nil")
	}
	//nolint:staticcheck
	if v := OrgIDFromContext(nil); v != "" {
		t.Errorf("nil ctx read: got %q", v)
	}
}

func TestOrgIDFromContext_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), orgIDContextKey, struct{}{})
	if v := OrgIDFromContext(ctx); v != "" {
		t.Errorf("wrong type should yield empty, got %q", v)
	}
}

func TestWithOrgSlug_RoundTrip(t *testing.T) {
	ctx := WithOrgSlug(context.Background(), "acme")
	if got := OrgSlugFromContext(ctx); got != "acme" {
		t.Errorf("got %q, want acme", got)
	}
}

func TestWithOrgSlug_EmptyIsNoop(t *testing.T) {
	parent := context.Background()
	got := WithOrgSlug(parent, "")
	if got != parent {
		t.Errorf("empty slug should be no-op")
	}
}

func TestWithOrgSlug_NilCtx(t *testing.T) {
	//nolint:staticcheck
	if got := WithOrgSlug(nil, "acme"); got != nil {
		t.Errorf("nil ctx should stay nil")
	}
	//nolint:staticcheck
	if v := OrgSlugFromContext(nil); v != "" {
		t.Errorf("nil ctx read: got %q", v)
	}
}

func TestOrgSlugFromContext_WrongType(t *testing.T) {
	ctx := context.WithValue(context.Background(), orgSlugContextKey, 99)
	if v := OrgSlugFromContext(ctx); v != "" {
		t.Errorf("wrong type should yield empty, got %q", v)
	}
}

func TestContextValues_Independent(t *testing.T) {
	// Keys must be independent — setting one must not leak into the others.
	ctx := context.Background()
	ctx = WithBaseURL(ctx, "https://example.com")
	ctx = WithOrgID(ctx, "org-1")
	ctx = WithOrgSlug(ctx, "slug-1")

	if got := BaseURLFromContext(ctx); got != "https://example.com" {
		t.Errorf("base url: %q", got)
	}
	if got := OrgIDFromContext(ctx); got != "org-1" {
		t.Errorf("org id: %q", got)
	}
	if got := OrgSlugFromContext(ctx); got != "slug-1" {
		t.Errorf("org slug: %q", got)
	}
}

func TestContextCancellationPropagates(t *testing.T) {
	// Wrapping with proxy metadata must preserve cancellation semantics.
	parent, cancel := context.WithCancel(context.Background())
	ctx := WithBaseURL(parent, "https://example.com")
	ctx = WithOrgID(ctx, "org-1")
	ctx = WithOrgSlug(ctx, "acme")

	if ctx.Err() != nil {
		t.Fatalf("unexpected early cancel: %v", ctx.Err())
	}
	cancel()
	if ctx.Err() != context.Canceled {
		t.Errorf("expected Canceled after parent cancel, got %v", ctx.Err())
	}
	// Values still retrievable after cancel.
	if got := BaseURLFromContext(ctx); got != "https://example.com" {
		t.Errorf("base url after cancel: %q", got)
	}
}

func TestOrgScopedRepoPrefix(t *testing.T) {
	tests := []struct {
		name, slug, repo, want string
	}{
		{"with slug", "acme", "pypi", "/repository/@acme/pypi/"},
		{"empty slug legacy", "", "pypi", "/repository/pypi/"},
		{"slug with dash", "my-org", "npm", "/repository/@my-org/npm/"},
		{"empty both", "", "", "/repository//"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := OrgScopedRepoPrefix(tc.slug, tc.repo); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}
