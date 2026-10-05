package upstreamhttp

import (
	"fmt"
	"net/http"
	"sync"

	"golang.org/x/time/rate"

	"github.com/chain305/chainsaw-core/httpclient"
)

// Maven Central is one edge under two hostnames: repo.maven.apache.org is a
// CNAME of repo1.maven.org, and Sonatype counts both as one consumer per
// egress IP. Their published limit is a threshold, not a number
// (central.sonatype.org/faq/429-error/), and it is enforced by BLOCKING the
// IP for minutes at a time: a probe saw 26-30 minute blocks announced with
// Retry-After ~1565s, during which even edge-cached POMs answer 429
// (aquasecurity/trivy#10691). Sonatype's own advice is that retrying harder
// makes it worse, and blocks lengthen with repeat offences.
//
// Two things follow, and both are process-wide rather than per client:
//
//  1. ONE bucket for the edge. Each upstreamhttp.New built its own limiter,
//     and each limiter keyed buckets by hostname, so the configured 5/s was
//     5/s x 2 hostnames x every client. In prod the refresher alone drew a
//     429 on 13% of its Maven Central requests at 0.16 req/s average
//     (2026-09-25/26), so the burst ceiling is what matters.
//  2. A STAND-OFF. On a 429 from either hostname every client stops asking
//     until the Retry-After, capped, and fails at once with
//     ErrUpstreamStandoff instead of hitting the edge again inside a block.
//     The state is httpclient's (sonatype_standoff.go), shared with every
//     client that package builds, the proxy's included.
const (
	// sonatypeRateKey is the HostLimits entry the shared bucket takes its
	// rate from; both hostnames carry the same value in defaultHostLimits.
	sonatypeRateKey = "repo1.maven.org"
)

// ErrUpstreamStandoff is a request refused because Maven Central answered 429
// and its Retry-After has not passed. It wraps ErrRateLimitedLocally: the
// upstream was not asked, and every caller that already treats our own
// refusal as a provisional cancellation (registry metadata rechecks on the
// provisional backoff) treats this one the same way.
var ErrUpstreamStandoff = fmt.Errorf("upstreamhttp: sonatype_standoff: Maven Central answered 429, not asking again before its Retry-After: %w", ErrRateLimitedLocally)

// sonatypeEdgeState holds the shared buckets. The stand-off itself lives in
// httpclient, so clients that never pass through upstreamhttp (proxied
// installs) honour and set the same one.
type sonatypeEdgeState struct {
	mu sync.Mutex
	fg *rate.Limiter
	bg *rate.Limiter
}

// sonatypeEdge is process-wide; a pointer so tests can swap in a fresh one.
var sonatypeEdge = &sonatypeEdgeState{}

func isSonatypeHost(host string) bool { return httpclient.IsSonatypeHost(host) }

// limiters returns the shared foreground and background buckets, built on
// first use from the first caller's rate. Every production limiter is built
// from FromEnv, so they agree.
func (e *sonatypeEdgeState) limiters(r float64, burst int) (fg, bg *rate.Limiter) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fg == nil {
		e.fg = rate.NewLimiter(rate.Limit(r), burst)
		e.bg = rate.NewLimiter(rate.Limit(r*backgroundShare), 1)
	}
	return e.fg, e.bg
}

// standingOff returns ErrUpstreamStandoff while a 429's Retry-After holds.
func (e *sonatypeEdgeState) standingOff(host string) error {
	if isSonatypeHost(host) && httpclient.SonatypeStandoff() > 0 {
		return ErrUpstreamStandoff
	}
	return nil
}

// observe starts the stand-off when resp is a 429 from the Sonatype edge, and
// reports whether it did. The transport also observes it; this covers a
// Client whose base transport was not built by httpclient.
func (e *sonatypeEdgeState) observe(host string, resp *http.Response) bool {
	return httpclient.ObserveSonatypeResponse(host, resp)
}
