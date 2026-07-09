package swift

import (
	"net/http"
	"net/url"

	"github.com/chain305/chainsaw-core/httpclient"
)

// Sentinel base URL used when the user enables git-fallback without
// configuring an upstream registry. The CompositeRoundTripper ignores
// this host entirely; it exists only so proxy.Facet has a non-nil
// BaseURL to route against.
const gitFallbackBaseURL = "https://swift-git-fallback.chainsaw.local/"

// GitFallbackBaseURL returns a parsed copy of the sentinel URL used
// when git-fallback is enabled without an upstream registry.
func GitFallbackBaseURL() *url.URL {
	u, _ := url.Parse(gitFallbackBaseURL)
	return u
}

// WrapClient returns a shallow copy of client whose Transport is
// replaced with a CompositeRoundTripper that tries the registry first
// and falls back to the git translator. When git is nil the original
// client is returned unchanged so registry-only deployments pay no
// extra cost.
func WrapClient(client *http.Client, registryBase *url.URL, git *GitUpstream) *http.Client {
	if git == nil {
		return client
	}
	if client == nil {
		// F-12: previously fell back to http.DefaultClient (no timeout,
		// MaxIdleConnsPerHost=2). httpclient.New gives the same drop-in
		// shape with the chainsaw-tuned transport pool.
		client = httpclient.New()
	}
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	wrapped := *client
	wrapped.Transport = &CompositeRoundTripper{
		Registry:     base,
		RegistryBase: registryBase,
		Git:          git,
	}
	return &wrapped
}
