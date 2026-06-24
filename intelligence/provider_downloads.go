package intelligence

// provider_downloads.go — weekly-download-count fetchers for npm and PyPI.
//
// These are helper functions, not full Provider implementations. The
// projection wiring that calls them and populates risk.Input.WeeklyDownloads
// is in provider_weekly_downloads.go.
//
// Fail-open contract: on any fetch error the functions return
// unknownDownloadsSentinel (-1) so that the risk signal fires with severity
// "unknown" rather than staying silent. Air-gap (CHAINSAW_OFFLINE=1) is
// handled at the *provider* layer (see provider_weekly_downloads.go) — the
// provider returns an empty PartialReport so risk.Input.WeeklyDownloads
// stays nil and the signal stays dormant. The fetchers below also honour
// CHAINSAW_OFFLINE as a defensive backstop for direct callers, returning -1
// in that path because they cannot express "no data" from a function that
// returns int. Production callers should always go through the provider.
//
// Timeout & retry budget
// ----------------------
// The outer scanner already wraps every provider invocation in a 3s context
// (DefaultProviderTimeout). Layering an inner timeout on top is dead code —
// the outer context fires first — and historically caused the symptom this
// file's git blame describes: live fetches always returned -1 because the
// retry sleeps inside upstreamhttp ate the entire budget before the first
// response could be read.
//
// The fix is twofold:
//   1. Don't add a second timeout. Trust the provider context.
//   2. Disable retries on the dedicated client used here. Weekly download
//      counts are informational; a transient 5xx from npmjs.org is a
//      one-shot "unknown" rather than a 1s/2s/4s retry tower.
// The base 30s upstream client timeout still applies as the absolute
// per-attempt cap, but in practice the provider context cancels first.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"github.com/chain305/chainsaw-core/upstreamhttp"
)

// unknownDownloads is the sentinel that signals "data unavailable". Must
// match the constant in internal/risk/registry_maintenance.go.
const unknownDownloads = -1

// downloadsClient is a dedicated upstreamhttp.Client with retries disabled
// (MaxRetries=0). Sharing one client across calls keeps the rate limiter's
// per-host bucket coherent — the npmjs.org budget should be one bucket,
// not a fresh one per fetch.
//
// Tests do not use this client directly; they go through wave4Do, which
// honours the test override seam (SetWave4HTTPDoerForTest). The client is
// only constructed when production code path needs it.
var (
	downloadsClientOnce sync.Once
	downloadsClient     *upstreamhttp.Client
)

func getDownloadsClient() *upstreamhttp.Client {
	downloadsClientOnce.Do(func() {
		downloadsClient = upstreamhttp.New(upstreamhttp.FromEnv(), upstreamhttp.WithMaxRetries(0))
	})
	return downloadsClient
}

// --- shared outbound HTTP doer seam --------------------------------------
//
// The Wave-4 RTT / maintainer-age providers (now in
// internal/intelligence/premium) and this core downloads fetcher share a
// single test-override hook so fixtures stay uniform across providers. The
// seam lives in core because core code (DownloadsDo, below) reads it; the
// premium providers reach it through the exported Wave4Do wrapper.
var (
	wave4ClientOnce sync.Once
	wave4Client     *upstreamhttp.Client
	// wave4DoOverride lets tests swap the outbound path. When non-nil
	// it is used instead of the production upstreamhttp.Client.
	wave4DoOverride func(*http.Request) (*http.Response, error)
	wave4DoMu       sync.RWMutex
)

// Wave4Do runs req through the shared Wave-4 upstream client unless a test
// has installed an override via SetWave4HTTPDoerForTest. Exported so the
// premium RTT / maintainer-age providers (internal/intelligence/premium)
// can route their outbound HTTP through the same rate-limited client and
// test seam.
func Wave4Do(req *http.Request) (*http.Response, error) {
	wave4DoMu.RLock()
	override := wave4DoOverride
	wave4DoMu.RUnlock()
	if override != nil {
		return override(req)
	}
	wave4ClientOnce.Do(func() {
		wave4Client = upstreamhttp.New(upstreamhttp.FromEnv())
	})
	return wave4Client.Do(req)
}

// SetWave4HTTPDoerForTest overrides the outbound HTTP path used by the
// Wave-4 RTT providers AND the core downloads fetcher. Callers pass nil to
// restore the production upstreamhttp.Client. Exported so tests in
// downstream packages can exercise the 404 / success paths without hitting
// the network.
func SetWave4HTTPDoerForTest(do func(*http.Request) (*http.Response, error)) {
	wave4DoMu.Lock()
	wave4DoOverride = do
	wave4DoMu.Unlock()
}

// DownloadsDo runs req through the dedicated no-retry client unless a test
// has installed the shared Wave-4 override (we share that seam so test
// fixtures stay uniform across providers).
//
// Exported as part of the open-core seam: the premium weekly-downloads
// provider (internal/intelligence/premium) reuses this fetcher.
func DownloadsDo(req *http.Request) (*http.Response, error) {
	wave4DoMu.RLock()
	override := wave4DoOverride
	wave4DoMu.RUnlock()
	if override != nil {
		return override(req)
	}
	return getDownloadsClient().Do(req)
}

// FetchNPMWeeklyDownloads fetches the last-week download count for the given
// npm package name from the npm downloads API.
//
// Returns unknownDownloads (-1) when:
//   - CHAINSAW_OFFLINE=1 is set (defensive backstop; production goes through
//     the provider which short-circuits earlier with nil instead).
//   - The HTTP request fails for any reason.
//   - The response cannot be decoded.
//
// The caller should treat -1 as "data unavailable" and emit SevUnknown.
// No inner context timeout is applied — the provider context (typically
// 3s) is the deadline.
func FetchNPMWeeklyDownloads(ctx context.Context, packageName string) int {
	if IsOffline() {
		return unknownDownloads
	}

	encoded := url.PathEscape(packageName)
	apiURL := "https://api.npmjs.org/downloads/point/last-week/" + encoded

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return unknownDownloads
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "chainsaw-intelligence/downloads")

	resp, err := DownloadsDo(req)
	if err != nil {
		return unknownDownloads
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return unknownDownloads
	}

	var body struct {
		Downloads int `json:"downloads"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return unknownDownloads
	}
	return body.Downloads
}

// FetchPyPIWeeklyDownloads fetches the last-week download count for the given
// PyPI package name from the pypistats.org API.
//
// Returns unknownDownloads (-1) when:
//   - CHAINSAW_OFFLINE=1 is set (defensive backstop; production goes through
//     the provider which short-circuits earlier with nil instead).
//   - The HTTP request fails for any reason.
//   - The response cannot be decoded.
//
// The caller should treat -1 as "data unavailable" and emit SevUnknown.
// No inner context timeout is applied — the provider context is the deadline.
func FetchPyPIWeeklyDownloads(ctx context.Context, packageName string) int {
	if IsOffline() {
		return unknownDownloads
	}

	// pypistats normalises package names to lowercase with hyphens.
	name := strings.ToLower(strings.ReplaceAll(packageName, "_", "-"))
	apiURL := fmt.Sprintf("https://pypistats.org/api/packages/%s/recent?period=week", url.PathEscape(name))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return unknownDownloads
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "chainsaw-intelligence/downloads")

	resp, err := DownloadsDo(req)
	if err != nil {
		return unknownDownloads
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return unknownDownloads
	}

	var body struct {
		Data struct {
			LastWeek int `json:"last_week"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return unknownDownloads
	}
	return body.Data.LastWeek
}

// IsOffline reports whether CHAINSAW_OFFLINE=1 is set (any truthy value).
//
// Exported as part of the open-core seam: the premium weekly-downloads
// provider (internal/intelligence/premium) uses the same air-gap check.
func IsOffline() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("CHAINSAW_OFFLINE")))
	switch v {
	case "1", "true", "on", "yes":
		return true
	}
	return false
}
