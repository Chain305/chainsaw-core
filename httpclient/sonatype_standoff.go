package httpclient

// Standing off Maven Central, once, for every caller.
//
// Maven Central is one edge under two hostnames (repo.maven.apache.org is a
// CNAME of repo1.maven.org), and Sonatype enforces its consumption limit by
// BLOCKING the egress IP: 26-30 minute blocks announced with a Retry-After,
// during which even edge-cached POMs answer 429, lengthening on repeat
// (central.sonatype.org/faq/429-error/, aquasecurity/trivy#10691). Every
// request we send inside a block is one more the edge holds against us.
//
// So the process keeps ONE stand-off for the edge, set by a 429 from either
// hostname on any client this package builds (proxied installs, the
// refresher, registry metadata, the artifact fetcher) and honoured by all of
// them: while it holds, the transport answers locally with a 503 and a
// Retry-After, before the network and before the egress count. A 503 is
// "upstream unavailable": the proxy serves stale cache or passes it on, and
// does not retry inside a Retry-After. upstreamhttp reads the same state and
// refuses with its own error before reaching the transport.
//
// It costs one mutex read per Maven request outside a stand-off and adds no
// wait: install latency changes only while Sonatype is refusing us anyway.

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var sonatypeHosts = map[string]bool{"repo1.maven.org": true, "repo.maven.apache.org": true}

const (
	// sonatypeStandoffMax caps a Retry-After. A longer block is re-learned
	// from the next 429, which costs one request.
	sonatypeStandoffMax = 30 * time.Minute
	// sonatypeStandoffDefault is the stand-off for a 429 without a usable
	// Retry-After.
	sonatypeStandoffDefault = time.Minute
	// SonatypeStandoffHeader marks a response answered locally during a
	// stand-off, so logs and tests can tell it from a real 503.
	SonatypeStandoffHeader = "X-Chainsaw-Upstream-Standoff"
)

var (
	sonatypeMu    sync.Mutex
	sonatypeUntil time.Time
)

// IsSonatypeHost reports whether host is one of Maven Central's hostnames.
func IsSonatypeHost(host string) bool { return sonatypeHosts[strings.ToLower(host)] }

// SonatypeStandoff reports how long the current stand-off has left, or 0.
func SonatypeStandoff() time.Duration {
	sonatypeMu.Lock()
	defer sonatypeMu.Unlock()
	return max(time.Until(sonatypeUntil), 0)
}

// ObserveSonatypeResponse starts (or extends) the stand-off when resp is a 429
// from Maven Central, and reports whether it did.
func ObserveSonatypeResponse(host string, resp *http.Response) bool {
	if resp == nil || resp.StatusCode != http.StatusTooManyRequests || !IsSonatypeHost(host) {
		return false
	}
	d, ok := retryAfterDuration(resp.Header.Get("Retry-After"), time.Now())
	if !ok {
		d = sonatypeStandoffDefault
	}
	d = min(d, sonatypeStandoffMax)
	sonatypeMu.Lock()
	defer sonatypeMu.Unlock()
	if until := time.Now().Add(d); until.After(sonatypeUntil) {
		sonatypeUntil = until
	}
	return true
}

// ResetSonatypeStandoff clears the stand-off. For tests.
func ResetSonatypeStandoff() {
	sonatypeMu.Lock()
	sonatypeUntil = time.Time{}
	sonatypeMu.Unlock()
}

// sonatypePausedResponse answers req locally while the stand-off holds.
func sonatypePausedResponse(req *http.Request) *http.Response {
	if req == nil || req.URL == nil || !IsSonatypeHost(req.URL.Hostname()) {
		return nil
	}
	left := SonatypeStandoff()
	if left <= 0 {
		return nil
	}
	h := make(http.Header)
	h.Set("Retry-After", strconv.Itoa(int(left.Seconds())+1))
	h.Set(SonatypeStandoffHeader, "sonatype")
	return &http.Response{
		StatusCode: http.StatusServiceUnavailable,
		Status:     "503 Service Unavailable (chainsaw: Maven Central rate-limited this server, standing off)",
		Header:     h,
		Body:       io.NopCloser(bytes.NewReader(nil)),
		Request:    req,
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	}
}

// retryAfterDuration parses Retry-After as delay-seconds or an HTTP-date.
func retryAfterDuration(header string, now time.Time) (time.Duration, bool) {
	s := strings.TrimSpace(header)
	if n, err := strconv.Atoi(s); err == nil {
		return time.Duration(n) * time.Second, n > 0
	}
	if t, err := http.ParseTime(s); err == nil && t.After(now) {
		return t.Sub(now), true
	}
	return 0, false
}
