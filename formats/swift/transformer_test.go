package swift

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/proxy"
)

func TestShouldTransform(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{"plain JSON", "application/json", true},
		{"registry v1 JSON", "application/vnd.swift.registry.v1+json", true},
		{"registry v2 JSON (future)", "application/vnd.swift.registry.v2+json", true},
		{"registry JSON with charset", "application/vnd.swift.registry.v1+json; charset=utf-8", true},
		{"problem+json", "application/problem+json", true},
		{"zip archive", "application/zip", false},
		{"Swift manifest", "text/x-swift", false},
		{"registry v1 zip", "application/vnd.swift.registry.v1+zip", false},
		{"empty content type", "", false},
	}
	tr := NewMetadataTransformer("swift-proxy")
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.content != "" {
				h.Set("Content-Type", tc.content)
			}
			resp := &http.Response{Header: h}
			if got := tr.ShouldTransform("apple/swift-nio", resp); got != tc.want {
				t.Errorf("ShouldTransform Content-Type=%q = %v, want %v", tc.content, got, tc.want)
			}
		})
	}
}

func TestTransformRewritesUpstreamURLs(t *testing.T) {
	body := map[string]any{
		"releases": map[string]any{
			"1.0.0": map[string]any{"url": "https://upstream.example.com/apple/swift-nio/1.0.0"},
			"1.1.0": map[string]any{"url": "https://upstream.example.com/apple/swift-nio/1.1.0"},
		},
	}
	raw, _ := json.Marshal(body)

	ctx := proxy.WithBaseURL(context.Background(), "https://chainsaw.example.com")
	ctx = proxy.WithOrgSlug(ctx, "acme")

	tr := NewMetadataTransformer("swift-proxy")
	out, err := tr.Transform(ctx, "apple/swift-nio", raw)
	if err != nil {
		t.Fatalf("Transform: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal transformed body: %v", err)
	}
	releases := parsed["releases"].(map[string]any)
	for version, entry := range releases {
		m := entry.(map[string]any)
		got := m["url"].(string)
		if strings.Contains(got, "upstream.example.com") {
			t.Errorf("version %s url still references upstream: %q", version, got)
		}
		if !strings.HasPrefix(got, "https://chainsaw.example.com/") {
			t.Errorf("version %s url does not point at proxy: %q", version, got)
		}
	}
}

func TestTransformRewritesResourceURLs(t *testing.T) {
	body := map[string]any{
		"id":          "apple.swift-nio",
		"version":     "1.0.0",
		"publishedAt": "2024-01-15T12:34:56Z",
		"resources": []any{
			map[string]any{
				"name":     "source-archive",
				"type":     "application/zip",
				"checksum": "deadbeef",
				"url":      "https://upstream.example.com/apple/swift-nio/1.0.0.zip",
			},
		},
	}
	raw, _ := json.Marshal(body)

	ctx := proxy.WithBaseURL(context.Background(), "https://chainsaw.example.com")
	ctx = proxy.WithOrgSlug(ctx, "acme")

	tr := NewMetadataTransformer("swift-proxy")
	out, err := tr.Transform(ctx, "apple/swift-nio/1.0.0", raw)
	if err != nil {
		t.Fatalf("Transform: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	resources := parsed["resources"].([]any)
	got := resources[0].(map[string]any)["url"].(string)
	if strings.Contains(got, "upstream.example.com") {
		t.Errorf("resource url still references upstream: %q", got)
	}
}

func TestTransformLeavesNonAbsoluteURLs(t *testing.T) {
	body := map[string]any{
		"releases": map[string]any{
			"1.0.0": map[string]any{"url": "/apple/swift-nio/1.0.0"},
		},
	}
	raw, _ := json.Marshal(body)
	ctx := proxy.WithBaseURL(context.Background(), "https://chainsaw.example.com")

	tr := NewMetadataTransformer("swift-proxy")
	out, err := tr.Transform(ctx, "apple/swift-nio", raw)
	if err != nil {
		t.Fatalf("Transform: %v", err)
	}
	// Relative URLs are passed through unchanged.
	if !strings.Contains(string(out), "/apple/swift-nio/1.0.0") {
		t.Errorf("relative URL was lost: %s", out)
	}
}

func TestRewriteLinkHeader(t *testing.T) {
	base := "https://chainsaw.example.com"
	prefix := "/repo/swift-proxy"

	tests := []struct {
		name, in, want string
	}{
		{
			name: "rewrites latest-version",
			in:   `<https://upstream.example.com/apple/swift-nio/2.62.0>; rel="latest-version"`,
			want: `<https://chainsaw.example.com/repo/swift-proxy/apple/swift-nio/2.62.0>; rel="latest-version"`,
		},
		{
			name: "rewrites canonical and successor",
			in:   `<https://upstream.example.com/apple/swift-nio>; rel="canonical", <https://upstream.example.com/apple/swift-nio/2.63.0>; rel="successor-version"`,
			want: `<https://chainsaw.example.com/repo/swift-proxy/apple/swift-nio>; rel="canonical", <https://chainsaw.example.com/repo/swift-proxy/apple/swift-nio/2.63.0>; rel="successor-version"`,
		},
		{
			name: "leaves already-proxy URLs unchanged",
			in:   `<https://chainsaw.example.com/repo/swift-proxy/apple/swift-nio>; rel="canonical"`,
			want: `<https://chainsaw.example.com/repo/swift-proxy/apple/swift-nio>; rel="canonical"`,
		},
		{
			name: "empty header",
			in:   ``,
			want: ``,
		},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := RewriteLinkHeader(tc.in, base, prefix)
			if got != tc.want {
				t.Errorf("RewriteLinkHeader\n  in:   %s\n  got:  %s\n  want: %s", tc.in, got, tc.want)
			}
		})
	}
}

func TestRewriteAbsoluteURL(t *testing.T) {
	base := "https://chainsaw.example.com"
	prefix := "/repo/swift-proxy"
	tests := []struct {
		in, want string
	}{
		{"https://upstream.example.com/apple/swift-nio", base + prefix + "/apple/swift-nio"},
		{"http://upstream.example.com:8080/apple/swift-nio/1.0.0", base + prefix + "/apple/swift-nio/1.0.0"},
		{base + prefix + "/apple/swift-nio", base + prefix + "/apple/swift-nio"}, // already proxy
		{"/relative/path", "/relative/path"},                                     // non-absolute untouched
		{"", ""},
	}
	for _, tc := range tests {
		got := rewriteAbsoluteURL(tc.in, base, prefix)
		if got != tc.want {
			t.Errorf("rewriteAbsoluteURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
