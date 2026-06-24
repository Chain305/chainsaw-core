package upstreamhttp

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// shouldRetry reports whether a response status warrants another
// attempt. We retry on 429 (Too Many Requests) and 5xx (server
// errors) — both are transient from the caller's perspective. 4xx
// other than 429 (e.g. 400, 404, 422) is a caller bug and retrying
// would just burn quota.
func shouldRetry(status int) bool {
	return status == http.StatusTooManyRequests || (status >= 500 && status <= 599)
}

// parseRetryAfter parses an HTTP Retry-After header in either of the
// two RFC 7231 forms:
//
//	Retry-After: 120            (delta-seconds)
//	Retry-After: Fri, 31 Dec 2099 23:59:59 GMT   (HTTP-date)
//
// Returns the resolved duration and whether parsing succeeded. If the
// parsed delay is non-positive (e.g. HTTP-date in the past) we treat
// it as "no useful hint" so the caller falls through to exponential
// backoff rather than retrying immediately.
//
// now is injectable so retry_test.go can pin the clock.
func parseRetryAfter(header string, now time.Time) (time.Duration, bool) {
	s := strings.TrimSpace(header)
	if s == "" {
		return 0, false
	}
	// Seconds form — the common case, servers usually emit a small
	// integer (Retry-After: 5).
	if n, err := strconv.Atoi(s); err == nil {
		if n <= 0 {
			return 0, false
		}
		return time.Duration(n) * time.Second, true
	}
	// HTTP-date form. Accept all three RFC 7231-permitted layouts —
	// Go's http.ParseTime tries each in turn.
	if t, err := http.ParseTime(s); err == nil {
		d := t.Sub(now)
		if d <= 0 {
			return 0, false
		}
		return d, true
	}
	return 0, false
}

// computeBackoff decides how long to sleep before attempt `attempt`
// (0-indexed, i.e. attempt=0 is the wait *before* the first retry).
// Prefers the server's Retry-After when parseable, capped by
// cfg.MaxBackoff; otherwise doubles cfg.RetryBaseDelay each attempt
// (1s, 2s, 4s, 8s...) until the cap.
//
// now is injected so tests can freeze time for HTTP-date parsing.
func computeBackoff(cfg Config, resp *http.Response, attempt int, now time.Time) time.Duration {
	if resp != nil {
		if d, ok := parseRetryAfter(resp.Header.Get("Retry-After"), now); ok {
			if cfg.MaxBackoff > 0 && d > cfg.MaxBackoff {
				d = cfg.MaxBackoff
			}
			return d
		}
	}
	base := cfg.RetryBaseDelay
	if base <= 0 {
		base = DefaultRetryBaseDelay
	}
	// attempt is 0-indexed, so the 1st retry waits base, 2nd waits
	// 2*base, 3rd waits 4*base — matching the docstring (1s, 2s, 4s).
	shift := attempt
	if shift < 0 {
		shift = 0
	}
	// Protect against absurdly large shift values; 30 is ~17 minutes
	// at base=1s, already far beyond MaxBackoff.
	if shift > 30 {
		shift = 30
	}
	d := base << shift
	if cfg.MaxBackoff > 0 && d > cfg.MaxBackoff {
		d = cfg.MaxBackoff
	}
	return d
}

// sleepCtx waits for d to elapse or ctx to be cancelled. Returns
// ctx.Err() if cancelled mid-wait. Used by the retry loop so a
// shutdown during a long Retry-After wait doesn't hang the server.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
