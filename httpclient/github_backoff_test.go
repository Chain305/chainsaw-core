package httpclient

import (
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// fakeGitHub answers every request with the given status and headers and
// counts how many actually reached it.
type fakeGitHub struct {
	status int
	header http.Header
	hits   atomic.Int32
}

func (f *fakeGitHub) RoundTrip(req *http.Request) (*http.Response, error) {
	f.hits.Add(1)
	h := f.header.Clone()
	if h == nil {
		h = http.Header{}
	}
	return &http.Response{StatusCode: f.status, Header: h, Body: http.NoBody, Request: req}, nil
}

func githubReq(t *testing.T, authed bool) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/repos/o/r", nil)
	if err != nil {
		t.Fatal(err)
	}
	if authed {
		req.Header.Set("Authorization", "Bearer x")
	}
	return req
}

func withFixedClock(t *testing.T, now time.Time) {
	t.Helper()
	resetGitHubBackoff()
	prev := githubBackoffClock
	githubBackoffClock = func() time.Time { return now }
	t.Cleanup(func() { githubBackoffClock = prev; resetGitHubBackoff() })
}

// After GitHub signals a rate limit, the rest of the burst must not go out:
// on 2026-09-28 03:00Z one hour sent 3,954 requests GitHub had already refused.
func TestGitHubRateLimitPausesFurtherCalls(t *testing.T) {
	now := time.Date(2026, 9, 28, 3, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name   string
		status int
		header http.Header
	}{
		{"secondary limit, Retry-After", 403, http.Header{"Retry-After": {"60"}}},
		{"429 Retry-After", 429, http.Header{"Retry-After": {"60"}}},
		{"primary limit exhausted", 403, http.Header{
			"X-Ratelimit-Remaining": {"0"},
			"X-Ratelimit-Reset":     {strconv.FormatInt(now.Add(10*time.Minute).Unix(), 10)},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withFixedClock(t, now)
			up := &fakeGitHub{status: tc.status, header: tc.header}
			rt := withEgressCounting(up)
			for i := 0; i < 5; i++ {
				resp, err := rt.RoundTrip(githubReq(t, true))
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
			}
			if got := up.hits.Load(); got != 1 {
				t.Errorf("%d requests reached GitHub after it signalled a rate limit; want 1", got)
			}
			resp, _ := rt.RoundTrip(githubReq(t, true))
			if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
				t.Errorf("paused call = %d Retry-After=%q; want a local 429 with Retry-After",
					resp.StatusCode, resp.Header.Get("Retry-After"))
			}
		})
	}
}

// A 403 with no rate-limit signal is an answer about one resource (blocked,
// private) and must not stop every other GitHub call.
func TestPlainGitHub403DoesNotPause(t *testing.T) {
	withFixedClock(t, time.Date(2026, 9, 28, 3, 0, 0, 0, time.UTC))
	up := &fakeGitHub{status: 403}
	rt := withEgressCounting(up)
	for i := 0; i < 3; i++ {
		resp, _ := rt.RoundTrip(githubReq(t, true))
		resp.Body.Close()
	}
	if got := up.hits.Load(); got != 3 {
		t.Errorf("plain 403s let %d of 3 requests through; a 403 without rate-limit headers must not pause", got)
	}
}

// The anonymous budget is per IP; exhausting it says nothing about the token.
func TestAnonymousLimitDoesNotPauseTokenCalls(t *testing.T) {
	withFixedClock(t, time.Date(2026, 9, 28, 3, 0, 0, 0, time.UTC))
	anon := &fakeGitHub{status: 403, header: http.Header{"Retry-After": {"600"}}}
	withEgressCounting(anon).RoundTrip(githubReq(t, false))
	authed := &fakeGitHub{status: 200}
	resp, _ := withEgressCounting(authed).RoundTrip(githubReq(t, true))
	if resp.StatusCode != 200 || authed.hits.Load() != 1 {
		t.Errorf("token call was paused by the anonymous limit (status %d, hits %d)", resp.StatusCode, authed.hits.Load())
	}
}

// The pause ends: once the reset passes, requests go out again.
func TestGitHubPauseExpires(t *testing.T) {
	now := time.Date(2026, 9, 28, 3, 0, 0, 0, time.UTC)
	withFixedClock(t, now)
	up := &fakeGitHub{status: 403, header: http.Header{"Retry-After": {"30"}}}
	rt := withEgressCounting(up)
	rt.RoundTrip(githubReq(t, true))
	githubBackoffClock = func() time.Time { return now.Add(31 * time.Second) }
	rt.RoundTrip(githubReq(t, true))
	if got := up.hits.Load(); got != 2 {
		t.Errorf("hits after the pause expired = %d; want 2", got)
	}
}

// Other hosts are untouched even while GitHub is paused.
func TestGitHubPauseIsHostScoped(t *testing.T) {
	withFixedClock(t, time.Date(2026, 9, 28, 3, 0, 0, 0, time.UTC))
	withEgressCounting(&fakeGitHub{status: 429, header: http.Header{"Retry-After": {"600"}}}).RoundTrip(githubReq(t, true))
	other := &fakeGitHub{status: 200}
	req, _ := http.NewRequest(http.MethodGet, "https://registry.npmjs.org/lodash", nil)
	req.Header.Set("Authorization", "Bearer x")
	resp, _ := withEgressCounting(other).RoundTrip(req)
	if resp.StatusCode != 200 || other.hits.Load() != 1 {
		t.Errorf("npm call blocked by a GitHub pause (status %d)", resp.StatusCode)
	}
}
