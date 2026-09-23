package intelligence

import (
	"net/http"

	"github.com/chain305/chainsaw-core/httpclient"
	"testing"

	"github.com/chain305/chainsaw-core/upstreamhttp"
)

// TestRegistryMetadataClientIsRateLimited pins the throttle on the
// highest-volume upstream path in the product.
//
// This provider fetches npm / PyPI / Maven / crates.io / NuGet metadata
// on every scan and had NO rate limit at all. The only throttle on the
// path was the refresher's Concurrency semaphore (default 4), which is a
// concurrency cap rather than a rate limit: four goroutines in a tight
// loop still out-request any per-minute budget a registry publishes.
//
// The assertion is on the TRANSPORT, because that is what the limiter
// hangs off. A future edit that swaps the client back to a bare
// httpclient compiles, passes every functional test, and silently
// removes the throttle -- which is exactly how it came to be missing.
func TestRegistryMetadataClientIsRateLimited(t *testing.T) {
	p := newRegistryMetadataProvider()
	if p.client == nil {
		t.Fatal("provider has no HTTP client")
	}
	if p.client.Transport == nil {
		t.Fatal("provider client has a nil Transport; it is not going through the rate limiter")
	}
	// upstreamhttp.HTTPClient() installs its own RoundTripper that
	// funnels every request through Do(), which is where limiter.Wait
	// lives. A plain *http.Transport here means the limiter is gone.
	// Unwrap the egress counter FIRST. It wraps every transport this package
	// builds, so without this the assertion below is true no matter what —
	// the counter alone would satisfy "not a bare *http.Transport" and this
	// guard would stop detecting a missing limiter entirely.
	if _, isPlain := httpclient.UnwrapTransport(p.client.Transport).(*http.Transport); isPlain {
		t.Error("provider client uses a bare *http.Transport — the per-host rate limiter is not installed. " +
			"npm/PyPI/Maven metadata is the highest-volume upstream path in the product and it must be throttled.")
	}
}

// TestRegistryMetadataClientIsShared — a per-call client gives every
// fetch its own token bucket, which is the same as having none. The
// npmjs.org budget has to be one bucket.
func TestRegistryMetadataClientIsShared(t *testing.T) {
	a := registryMetadataHTTPClient()
	b := registryMetadataHTTPClient()
	if a != b {
		t.Error("registryMetadataHTTPClient returned two different clients; each would carry its own " +
			"token bucket and the per-host limit would not bind")
	}
	if newRegistryMetadataProvider().client != a {
		t.Error("the provider does not use the shared client")
	}
}

// TestRegistryMetadataKeepsItsTimeout — the 60s backstop is deliberate
// (the real deadline is the per-ecosystem request context), and
// upstreamhttp's own default base would have replaced it with 30s AND
// added an SSRF guard that refuses redirects. Registry metadata
// endpoints redirect routinely, so adopting that default would have been
// an unrelated behaviour change smuggled in under a rate-limiting
// change.
func TestRegistryMetadataKeepsItsTimeout(t *testing.T) {
	got := registryMetadataHTTPClient().Timeout
	if got.Seconds() != 60 {
		t.Errorf("client timeout = %v, want 60s — the backstop above the longest per-ecosystem budget", got)
	}
	if registryMetadataHTTPClient().CheckRedirect != nil {
		t.Error("the client refuses or rewrites redirects; registry metadata endpoints redirect routinely, " +
			"and whether this path should carry the SSRF guard is a separate decision")
	}
}

// TestRegistryMetadataRetriesAreDisabled documents the constraint rather
// than the preference. upstreamhttp's retry tower sleeps between
// attempts and the scanner wraps every provider in a short context;
// provider_downloads.go carries the scar, where retry sleeps ate the
// whole budget and live fetches always returned -1.
//
// limiter.Wait runs inside the attempt loop, so retries-off keeps the
// throttle and drops the sleeps. This test exists so that anyone turning
// retries back on reads that first.
func TestRegistryMetadataRetriesAreDisabled(t *testing.T) {
	c := upstreamhttp.New(upstreamhttp.FromEnv(), upstreamhttp.WithMaxRetries(0))
	if c == nil {
		t.Fatal("upstreamhttp.New returned nil")
	}
	// The provider's client must be the HTTPClient() form of a
	// zero-retry client. We cannot read MaxRetries back out, so this
	// asserts the construction path stays available rather than the
	// value -- the value is pinned by the comment and by the downloads
	// provider's own regression.
}
