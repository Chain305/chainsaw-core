// Package kev provides an in-memory index of the CISA Known Exploited
// Vulnerabilities catalog. Consumers (chainsaw's intelligence KEV
// provider) use Lookup to tag CVEs that are known to be actively
// exploited so the risk-engine's vuln-kev signal can fire.
//
// The index is lazy-loaded on first use and refreshes at most every
// 24h. A fetch failure degrades gracefully: the last-known snapshot is
// kept in memory, and if there is none, lookups simply miss.
package kev

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/chain305/chainsaw-core/httpclient"
)

// DefaultFeedURL points at CISA's published KEV JSON catalog.
const DefaultFeedURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

// DefaultRefreshInterval caps how often Load will re-fetch the feed when
// EnsureFresh is called repeatedly.
const DefaultRefreshInterval = 24 * time.Hour

// DefaultHTTPTimeout is the hard deadline on a single feed fetch.
const DefaultHTTPTimeout = 30 * time.Second

// Entry is one row in the CISA KEV catalog, trimmed to the fields
// chainsaw actually uses.
type Entry struct {
	CVE                        string `json:"cveID"`
	DateAdded                  string `json:"dateAdded"`
	KnownRansomwareCampaignUse bool   `json:"knownRansomwareCampaignUse"`
}

// feedPayload is the wire shape the CISA JSON publishes.
type feedPayload struct {
	Vulnerabilities []feedEntry `json:"vulnerabilities"`
}

// feedEntry uses the raw "Known"/"Unknown" string that CISA emits and
// is flattened to a bool in Entry.
type feedEntry struct {
	CVE                        string `json:"cveID"`
	DateAdded                  string `json:"dateAdded"`
	KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
}

// Index is the in-memory, thread-safe KEV catalog. Zero value is a
// usable, empty index; call Load to populate from the feed.
type Index struct {
	mu          sync.RWMutex
	entries     map[string]Entry
	lastRefresh time.Time

	// Configurable bits — defaults apply when zero.
	FeedURL         string
	RefreshInterval time.Duration
	HTTPTimeout     time.Duration
	HTTPClient      *http.Client
	Logger          *slog.Logger
}

// New returns a ready-to-use Index with sensible defaults. Callers who
// need to override the feed URL or logger can set the fields directly
// before first use.
func New() *Index {
	return &Index{entries: map[string]Entry{}}
}

// LastRefresh is the wall-clock time of the most recent successful
// fetch. Zero means the index has never been loaded.
func (i *Index) LastRefresh() time.Time {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.lastRefresh
}

// Lookup returns the Entry for a CVE ID, if any.
func (i *Index) Lookup(cve string) (Entry, bool) {
	if cve == "" {
		return Entry{}, false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	e, ok := i.entries[cve]
	return e, ok
}

// All returns a snapshot of every entry. Safe for iteration; the slice
// is freshly allocated so callers may sort or modify it.
func (i *Index) All() []Entry {
	i.mu.RLock()
	defer i.mu.RUnlock()
	out := make([]Entry, 0, len(i.entries))
	for _, e := range i.entries {
		out = append(out, e)
	}
	return out
}

// EnsureFresh triggers Load only when the last refresh is older than
// RefreshInterval (or never happened). Callers on the hot path invoke
// this before a batch of Lookups so the first query per ~24h warms the
// cache lazily.
func (i *Index) EnsureFresh(ctx context.Context) error {
	interval := i.RefreshInterval
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}
	i.mu.RLock()
	fresh := !i.lastRefresh.IsZero() && time.Since(i.lastRefresh) < interval
	i.mu.RUnlock()
	if fresh {
		return nil
	}
	return i.Load(ctx)
}

// Load fetches the KEV feed and atomically replaces the in-memory
// index. On fetch/parse failure, the prior snapshot is kept and an
// error is returned — callers that want graceful degradation should
// log and proceed rather than surface the error.
func (i *Index) Load(ctx context.Context) error {
	url := i.FeedURL
	if url == "" {
		url = DefaultFeedURL
	}
	timeout := i.HTTPTimeout
	if timeout <= 0 {
		timeout = DefaultHTTPTimeout
	}
	client := i.HTTPClient
	if client == nil {
		client = httpclient.New(httpclient.WithTimeout(timeout))
	}

	fetchCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("kev: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("kev: fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("kev: fetch status %d", resp.StatusCode)
	}

	var payload feedPayload
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return fmt.Errorf("kev: decode: %w", err)
	}

	entries := make(map[string]Entry, len(payload.Vulnerabilities))
	for _, e := range payload.Vulnerabilities {
		if e.CVE == "" {
			continue
		}
		entries[e.CVE] = Entry{
			CVE:                        e.CVE,
			DateAdded:                  e.DateAdded,
			KnownRansomwareCampaignUse: e.KnownRansomwareCampaignUse == "Known",
		}
	}

	i.mu.Lock()
	i.entries = entries
	i.lastRefresh = time.Now().UTC()
	i.mu.Unlock()

	if i.Logger != nil {
		i.Logger.Info("kev index refreshed", "entries", len(entries))
	}
	return nil
}

// LoadFromJSON is a testing hook: it accepts raw feed-shape JSON and
// populates the index without any network call.
func (i *Index) LoadFromJSON(data []byte) error {
	var payload feedPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return fmt.Errorf("kev: decode: %w", err)
	}
	entries := make(map[string]Entry, len(payload.Vulnerabilities))
	for _, e := range payload.Vulnerabilities {
		if e.CVE == "" {
			continue
		}
		entries[e.CVE] = Entry{
			CVE:                        e.CVE,
			DateAdded:                  e.DateAdded,
			KnownRansomwareCampaignUse: e.KnownRansomwareCampaignUse == "Known",
		}
	}
	i.mu.Lock()
	i.entries = entries
	i.lastRefresh = time.Now().UTC()
	i.mu.Unlock()
	return nil
}
