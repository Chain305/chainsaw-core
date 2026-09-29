package httpclient

// Honouring GitHub's rate-limit signals, once, for every caller.
//
// Several providers call api.github.com (registry metadata, repo liveness,
// maintainer age, repo stars, OCI attestations). Each retried a 403 at most
// once and moved on, so nothing ever backed off. On 2026-09-28 03:00Z a single
// hour produced 3,954 403s from api.github.com (2,830 of them from the
// refresher) against zero in every other hour since the token fix: once GitHub
// says stop, every later call in the burst is another request it will refuse.
//
// So the transport keeps one pause per (host, authenticated?) pair. A 403 or
// 429 that carries GitHub's rate-limit signal — Retry-After, or
// x-ratelimit-remaining: 0 with x-ratelimit-reset — pauses that pair until the
// reset (capped at an hour). While paused, a request is answered locally with
// a 429 and a Retry-After, and never reaches the network or the egress count.
//
// A 403 WITHOUT those headers (a blocked or private resource) is a real answer
// about one resource and pauses nothing. Anonymous and authenticated calls are
// paused separately: the anonymous budget is per IP and exhausting it says
// nothing about the token's 5,000/hour.

import (
	"bytes"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// githubAPIHost is the only host whose rate-limit headers this trusts.
const githubAPIHost = "api.github.com"

// githubMaxPause bounds any pause: GitHub's primary window is an hour.
const githubMaxPause = time.Hour

type githubBackoffKey struct {
	authed bool
}

var (
	githubBackoffMu    sync.Mutex
	githubPausedUntil  = map[githubBackoffKey]time.Time{}
	githubBackoffClock = time.Now
)

func githubKey(req *http.Request) (githubBackoffKey, bool) {
	if req == nil || req.URL == nil || req.URL.Hostname() != githubAPIHost {
		return githubBackoffKey{}, false
	}
	return githubBackoffKey{authed: req.Header.Get("Authorization") != ""}, true
}

// githubPausedResponse answers req locally when its pair is paused.
func githubPausedResponse(req *http.Request) *http.Response {
	key, ok := githubKey(req)
	if !ok {
		return nil
	}
	now := githubBackoffClock()
	githubBackoffMu.Lock()
	until := githubPausedUntil[key]
	githubBackoffMu.Unlock()
	if !now.Before(until) {
		return nil
	}
	secs := int(until.Sub(now).Seconds()) + 1
	h := make(http.Header)
	h.Set("Retry-After", strconv.Itoa(secs))
	h.Set("X-Chainsaw-Github-Backoff", "1")
	return &http.Response{
		StatusCode: http.StatusTooManyRequests,
		Status:     "429 Too Many Requests (chainsaw github backoff)",
		Header:     h,
		Body:       io.NopCloser(bytes.NewReader(nil)),
		Request:    req,
		Proto:      "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	}
}

// githubPauseFor reports how long GitHub asked us to stop, or 0 when resp is
// not a rate-limit signal.
func githubPauseFor(resp *http.Response, now time.Time) time.Duration {
	if resp == nil || (resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusTooManyRequests) {
		return 0
	}
	var d time.Duration
	if ra := strings.TrimSpace(resp.Header.Get("Retry-After")); ra != "" {
		if s, err := strconv.Atoi(ra); err == nil && s > 0 {
			d = time.Duration(s) * time.Second
		}
	}
	if d == 0 && strings.TrimSpace(resp.Header.Get("X-Ratelimit-Remaining")) == "0" {
		if r, err := strconv.ParseInt(strings.TrimSpace(resp.Header.Get("X-Ratelimit-Reset")), 10, 64); err == nil {
			d = time.Unix(r, 0).Sub(now)
		}
		if d <= 0 {
			d = time.Minute
		}
	}
	if d > githubMaxPause {
		d = githubMaxPause
	}
	return d
}

// observeGitHubResponse records a pause when resp is a GitHub rate-limit signal.
func observeGitHubResponse(req *http.Request, resp *http.Response) {
	key, ok := githubKey(req)
	if !ok {
		return
	}
	now := githubBackoffClock()
	d := githubPauseFor(resp, now)
	if d <= 0 {
		return
	}
	until := now.Add(d)
	githubBackoffMu.Lock()
	if until.After(githubPausedUntil[key]) {
		githubPausedUntil[key] = until
	}
	githubBackoffMu.Unlock()
}

func resetGitHubBackoff() {
	githubBackoffMu.Lock()
	githubPausedUntil = map[githubBackoffKey]time.Time{}
	githubBackoffMu.Unlock()
}
