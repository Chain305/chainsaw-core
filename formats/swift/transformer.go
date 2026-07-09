package swift

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"

	"github.com/chain305/chainsaw-core/proxy"
)

// NewMetadataTransformer rewrites SE-0292 JSON bodies so absolute URLs
// pointing at the upstream registry are redirected through Chainsaw.
// Non-JSON responses (Package.swift manifests, .zip archives) are passed
// through unmodified — signature headers (Digest, X-Swift-Package-Signature*)
// must survive verbatim for SE-0391 verification to work.
func NewMetadataTransformer(repoName string) proxy.ResponseTransformer {
	return &metadataTransformer{repoName: repoName}
}

type metadataTransformer struct {
	repoName string
}

// swiftRegistryMediaTypeRE matches application/vnd.swift.registry.v1[+suffix].
// SPM negotiates content via this media type; we rewrite JSON bodies only.
var swiftRegistryMediaTypeRE = regexp.MustCompile(`^application/vnd\.swift\.registry\.v\d+(\+\w+)?$`)

func (t *metadataTransformer) ShouldTransform(logicalPath string, resp *http.Response) bool {
	if resp == nil {
		return false
	}
	// Rewrite metadata JSON bodies only — archives and manifests must
	// remain byte-identical so signature verification works on the client.
	ct := strings.ToLower(strings.TrimSpace(strings.SplitN(resp.Header.Get("Content-Type"), ";", 2)[0]))
	if ct == "" {
		return false
	}
	if ct == "application/json" || ct == "application/problem+json" {
		return true
	}
	// Registry v1 JSON: application/vnd.swift.registry.v1+json
	if swiftRegistryMediaTypeRE.MatchString(ct) && strings.HasSuffix(ct, "+json") {
		return true
	}
	return false
}

// Transform walks a parsed JSON document and rewrites absolute upstream
// URLs to proxy-relative paths for the SE-0292 fields SPM uses to
// navigate:
//
//   - releases.{v}.url                               (release-list response)
//   - resources[*].url, metadata.repositoryURLs[*]   (release-metadata response)
//
// Any other URL fields are left untouched.
func (t *metadataTransformer) Transform(ctx context.Context, _ string, original []byte) ([]byte, error) {
	var payload map[string]any
	if err := json.Unmarshal(original, &payload); err != nil {
		// Problem+JSON documents or other small payloads we don't mutate
		// — return them as-is rather than erroring.
		return original, nil
	}
	baseURL := forceHTTPSIfConfigured(strings.TrimSuffix(strings.TrimSpace(proxy.BaseURLFromContext(ctx)), "/"))
	orgSlug := proxy.OrgSlugFromContext(ctx)
	repoPrefix := strings.TrimSuffix(proxy.OrgScopedRepoPrefix(orgSlug, t.repoName), "/")

	rewrite := func(u string) string {
		return rewriteAbsoluteURL(u, baseURL, repoPrefix)
	}

	changed := false

	// releases: {"<ver>": {"url": "..."}}
	if releases, ok := payload["releases"].(map[string]any); ok {
		for _, entry := range releases {
			m, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			if cur, ok := m["url"].(string); ok && cur != "" {
				if next := rewrite(cur); next != cur {
					m["url"] = next
					changed = true
				}
			}
		}
	}

	// resources: [ {"url": "...", ...} ]
	if resources, ok := payload["resources"].([]any); ok {
		for _, entry := range resources {
			m, ok := entry.(map[string]any)
			if !ok {
				continue
			}
			if cur, ok := m["url"].(string); ok && cur != "" {
				if next := rewrite(cur); next != cur {
					m["url"] = next
					changed = true
				}
			}
		}
	}

	if !changed {
		return original, nil
	}
	out, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("encode swift registry body: %w", err)
	}
	return out, nil
}

// rewriteAbsoluteURL returns target if it already points at the proxy or
// is non-absolute; otherwise strips the upstream scheme+host and
// re-anchors the path under baseURL + repoPrefix. This is intentionally
// conservative — we only rewrite when we're confident we have a valid
// baseURL and repoPrefix, leaving the URL alone in ambiguous cases.
func rewriteAbsoluteURL(target, baseURL, repoPrefix string) string {
	if target == "" || baseURL == "" || repoPrefix == "" {
		return target
	}
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return target
	}
	if strings.HasPrefix(target, baseURL+repoPrefix) {
		return target
	}
	// Drop scheme+host+port — keep everything from the first path segment on.
	withoutScheme := target
	if i := strings.Index(withoutScheme, "://"); i >= 0 {
		withoutScheme = withoutScheme[i+3:]
	}
	slash := strings.Index(withoutScheme, "/")
	if slash < 0 {
		// No path — give up.
		return target
	}
	path := withoutScheme[slash:] // starts with "/"
	return baseURL + repoPrefix + path
}

// RewriteLinkHeader rewrites RFC 8288 Link header values so any
// absolute URLs wrapped in <...> that point at the upstream registry
// now point back through the proxy. Preserves rel=/type= parameters
// and passes through entries that are already proxy-local or relative.
//
// Exposed for reuse from the builder and tests.
func RewriteLinkHeader(value, baseURL, repoPrefix string) string {
	if value == "" || baseURL == "" || repoPrefix == "" {
		return value
	}
	parts := strings.Split(value, ",")
	changed := false
	for i, part := range parts {
		trimmed := strings.TrimSpace(part)
		lt := strings.IndexByte(trimmed, '<')
		gt := strings.IndexByte(trimmed, '>')
		if lt < 0 || gt < 0 || gt <= lt+1 {
			continue
		}
		target := trimmed[lt+1 : gt]
		rewritten := rewriteAbsoluteURL(target, baseURL, repoPrefix)
		if rewritten == target {
			continue
		}
		parts[i] = trimmed[:lt+1] + rewritten + trimmed[gt:]
		changed = true
	}
	if !changed {
		return value
	}
	return strings.Join(parts, ", ")
}

// forceHTTPSIfConfigured upgrades the base URL scheme to HTTPS when the
// FORCE_HTTPS env var is set or when CHAINSAW_API_BASE_URL uses an HTTPS
// scheme. Mirrors the helper cargo uses so SPM clients that follow
// rewritten URLs don't trip through an HTTP→HTTPS redirect that would
// strip bearer credentials.
func forceHTTPSIfConfigured(base string) string {
	if base == "" {
		return base
	}
	if strings.EqualFold(os.Getenv("FORCE_HTTPS"), "true") {
		return strings.Replace(base, "http://", "https://", 1)
	}
	for _, key := range []string{"CHAINSAW_API_BASE_URL", "NEXT_PUBLIC_CHAINSAW_API_BASE_URL"} {
		if v := strings.TrimSpace(os.Getenv(key)); v != "" {
			if strings.HasPrefix(strings.ToLower(v), "https://") {
				return strings.Replace(base, "http://", "https://", 1)
			}
		}
	}
	return base
}
