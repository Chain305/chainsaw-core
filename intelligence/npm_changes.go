package intelligence

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"
)

// Following npm's replication feed (docs/REPORTS.md
// #backend-perf-load-test-2026-10-29 J.4, npm `_changes`).
//
// The refresher learns of a new npm version from its latest-version probe,
// re-asked every MaxStaleness (24 h) per package. replicate.npmjs.com's
// `_changes` names every package that changed, in order, from a sequence
// number. NpmChangesFollower reads it from a checkpoint kept in Postgres and
// expires the probes of the packages it names, so a change is seen on the
// next tick instead of within a day. While it keeps up, an npm probe stays
// current for npmFeedProbeTTL; the moment it stops keeping up, ProbeFeedHealthy
// says so and the refresher goes back to re-asking every MaxStaleness. The
// TTL stays the ceiling either way.
//
// It runs where the refresher runs (the leader); a missed window is replayed
// from the checkpoint. The first run starts at the feed's current sequence
// rather than replaying npm's history.
const (
	npmChangesFeed     = "npm_changes"
	npmChangesPageSize = 1000
	// npmChangesMaxPages bounds one Poll; the rest is read on the next.
	npmChangesMaxPages = 50
	npmChangesBodyCap  = 16 << 20
	// npmFeedProbeTTL is how long an npm probe stays current while the
	// feed is healthy.
	npmFeedProbeTTL = 7 * 24 * time.Hour
)

// npmProbeEcosystems are the ecosystems whose probes ask registry.npmjs.org.
var npmProbeEcosystems = []string{"npm", "yarn", "bun"}

// ProbeFeedHealthy, when set, reports whether a change feed is keeping an
// ecosystem's latest-version probes current (NpmChangesFollower.
// ProbeFeedHealthy, wired where the follower starts). Nil means no feed.
var ProbeFeedHealthy func(ecosystem string) bool

// probeWithinFeedBound is the one rule every reader of a latest-version
// probe applies on top of its own fresh_until check: a probe older than
// bound is current only while a feed keeps its ecosystem current. A probe
// written with the feed's long TTL therefore stops counting the moment the
// feed stalls, wherever it is read.
func probeWithinFeedBound(p *LatestVersionProbe, now time.Time, bound time.Duration) bool {
	if p == nil {
		return false
	}
	if now.Sub(p.ProbedAt) < bound {
		return true
	}
	h := ProbeFeedHealthy
	return h != nil && h(p.Ecosystem)
}

// probeTTL is how long a probe for ecosystem written now stays current.
func probeTTL(ecosystem string, base time.Duration) time.Duration {
	if h := ProbeFeedHealthy; h != nil && h(ecosystem) {
		return npmFeedProbeTTL
	}
	return base
}

// NpmChangesStore is what the follower needs from Postgres.
type NpmChangesStore interface {
	GetFeedCheckpoint(ctx context.Context, feed string) (seq string, ok bool, err error)
	SetFeedCheckpoint(ctx context.Context, feed, seq string) error
	ExpireLatestProbes(ctx context.Context, ecosystems, packages []string) (int64, error)
}

// changeFeed is one upstream's change feed: where its head is, how to read
// a page after a checkpoint, and whose probes its package names expire.
type changeFeed interface {
	checkpointKey() string
	ecosystems() []string
	defaultBase() string
	// head returns the checkpoint for "now", for a follower's first run.
	head(ctx context.Context, f *NpmChangesFollower) (string, error)
	// page returns the package names changed after since, the checkpoint
	// after them, and whether the feed has more.
	page(ctx context.Context, f *NpmChangesFollower, since string) (names []string, next string, more bool, err error)
}

// NpmChangesFollower polls one change feed (npm's by default; see
// NewGoIndexFollower); see the comment above.
type NpmChangesFollower struct {
	Store    NpmChangesStore
	BaseURL  string // default the feed's public endpoint
	Interval time.Duration
	// Feed is the upstream followed; nil means npm's _changes.
	Feed   changeFeed
	Logger *slog.Logger
	Client *http.Client // default the shared-limiter registry client
	// Gate, when set, runs each Poll (the leader lease); false means this
	// process did not poll, and its probes then fall back to the 24h bound.
	Gate func(ctx context.Context, poll func(context.Context)) bool

	lastCaughtUp atomic.Int64 // unix nanos of the last Poll that reached the head
}

func (f *NpmChangesFollower) feed() changeFeed {
	if f.Feed != nil {
		return f.Feed
	}
	return npmChangesFeedSource{}
}

func (f *NpmChangesFollower) base() string {
	if f.BaseURL != "" {
		return f.BaseURL
	}
	return f.feed().defaultBase()
}

func (f *NpmChangesFollower) interval() time.Duration {
	if f.Interval > 0 {
		return f.Interval
	}
	return time.Minute
}

// ProbeFeedHealthy reports whether ecosystem's probes are kept current by
// the feed: the feed covers the ecosystem and its last Poll that reached
// the head was within three intervals.
func (f *NpmChangesFollower) ProbeFeedHealthy(ecosystem string) bool {
	if f == nil {
		return false
	}
	covered := false
	for _, e := range f.feed().ecosystems() {
		covered = covered || e == ecosystem
	}
	last := f.lastCaughtUp.Load()
	return covered && last > 0 && time.Since(time.Unix(0, last)) < 3*f.interval()
}

// Run polls until ctx ends.
func (f *NpmChangesFollower) Run(ctx context.Context) {
	t := time.NewTicker(f.interval())
	defer t.Stop()
	for {
		var err error
		if f.Gate != nil {
			f.Gate(ctx, func(c context.Context) { err = f.Poll(c) })
		} else {
			err = f.Poll(ctx)
		}
		if err != nil && f.Logger != nil && ctx.Err() == nil {
			f.Logger.Warn("change feed poll failed; its probes fall back to the 24h refresh", "feed", f.feed().checkpointKey(), "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Poll reads the feed from the checkpoint to its head (or npmChangesMaxPages
// pages) and expires the probes of every package it names. The checkpoint
// moves only after the probes of its page are expired, so a failure replays
// rather than skips.
func (f *NpmChangesFollower) Poll(ctx context.Context) error {
	feed := f.feed()
	seq, ok, err := f.Store.GetFeedCheckpoint(ctx, feed.checkpointKey())
	if err != nil {
		return err
	}
	if !ok {
		head, err := feed.head(ctx, f)
		if err != nil {
			return err
		}
		if err := f.Store.SetFeedCheckpoint(ctx, feed.checkpointKey(), head); err != nil {
			return err
		}
		f.lastCaughtUp.Store(time.Now().UnixNano())
		return nil
	}
	for page := 0; page < npmChangesMaxPages; page++ {
		names, next, more, err := feed.page(ctx, f, seq)
		if err != nil {
			return err
		}
		if len(names) > 0 {
			if _, err := f.Store.ExpireLatestProbes(ctx, feed.ecosystems(), names); err != nil {
				return err
			}
		}
		if next != "" && next != seq {
			if err := f.Store.SetFeedCheckpoint(ctx, feed.checkpointKey(), next); err != nil {
				return err
			}
			seq = next
		} else if more {
			return fmt.Errorf("change feed %s: a full page did not advance past %s", feed.checkpointKey(), seq)
		}
		if !more {
			f.lastCaughtUp.Store(time.Now().UnixNano())
			return nil
		}
	}
	return nil // behind; the next Poll continues, and health lapses if it stays behind
}

// npmChangesFeedSource is replicate.npmjs.com's CouchDB-style _changes.
type npmChangesFeedSource struct{}

func (npmChangesFeedSource) checkpointKey() string { return npmChangesFeed }
func (npmChangesFeedSource) ecosystems() []string  { return npmProbeEcosystems }
func (npmChangesFeedSource) defaultBase() string   { return "https://replicate.npmjs.com" }

func (npmChangesFeedSource) head(ctx context.Context, f *NpmChangesFollower) (string, error) {
	var root struct {
		UpdateSeq json.RawMessage `json:"update_seq"`
	}
	if err := f.getJSON(ctx, f.base()+"/", &root); err != nil {
		return "", err
	}
	head := rawSeq(root.UpdateSeq)
	if head == "" {
		return "", fmt.Errorf("npm changes: no update_seq")
	}
	return head, nil
}

func (npmChangesFeedSource) page(ctx context.Context, f *NpmChangesFollower, since string) ([]string, string, bool, error) {
	var p struct {
		Results []struct {
			ID string `json:"id"`
		} `json:"results"`
		LastSeq json.RawMessage `json:"last_seq"`
	}
	u := f.base() + "/_changes?since=" + url.QueryEscape(since) + "&limit=" + strconv.Itoa(npmChangesPageSize)
	if err := f.getJSON(ctx, u, &p); err != nil {
		return nil, "", false, err
	}
	names := make([]string, 0, len(p.Results))
	for _, r := range p.Results {
		if r.ID != "" {
			names = append(names, r.ID)
		}
	}
	return names, rawSeq(p.LastSeq), len(p.Results) >= npmChangesPageSize, nil
}

// goIndexFeedSource is index.golang.org: newline-delimited JSON of module
// versions in publication order, paged by timestamp. A Go probe is keyed by
// module path, which is what the index names.
type goIndexFeedSource struct{}

const goIndexPageSize = 2000

func (goIndexFeedSource) checkpointKey() string { return "go_index" }
func (goIndexFeedSource) ecosystems() []string  { return []string{"go"} }
func (goIndexFeedSource) defaultBase() string   { return "https://index.golang.org" }

func (goIndexFeedSource) head(context.Context, *NpmChangesFollower) (string, error) {
	return time.Now().UTC().Format(time.RFC3339Nano), nil
}

func (goIndexFeedSource) page(ctx context.Context, f *NpmChangesFollower, since string) ([]string, string, bool, error) {
	u := f.base() + "/index?since=" + url.QueryEscape(since) + "&limit=" + strconv.Itoa(goIndexPageSize)
	body, err := f.get(ctx, u)
	if err != nil {
		return nil, "", false, err
	}
	defer body.Close()
	dec := json.NewDecoder(io.LimitReader(body, npmChangesBodyCap))
	var names []string
	next, n := since, 0
	for {
		var e struct {
			Path      string
			Timestamp string
		}
		if err := dec.Decode(&e); err == io.EOF {
			break
		} else if err != nil {
			return nil, "", false, fmt.Errorf("go index: %w", err)
		}
		n++
		if e.Path != "" {
			names = append(names, e.Path)
		}
		if e.Timestamp != "" {
			next = e.Timestamp
		}
	}
	return names, next, n >= goIndexPageSize, nil
}

// NewGoIndexFollower follows index.golang.org for Go probes.
func NewGoIndexFollower(store NpmChangesStore) *NpmChangesFollower {
	return &NpmChangesFollower{Store: store, Feed: goIndexFeedSource{}}
}

// rawSeq accepts a sequence as a JSON number or string.
func rawSeq(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var n json.Number
	if json.Unmarshal(raw, &n) == nil {
		return n.String()
	}
	return ""
}

func (f *NpmChangesFollower) getJSON(ctx context.Context, u string, out any) error {
	body, err := f.get(ctx, u)
	if err != nil {
		return err
	}
	defer body.Close()
	return json.NewDecoder(io.LimitReader(body, npmChangesBodyCap)).Decode(out)
}

func (f *NpmChangesFollower) get(ctx context.Context, u string) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent("changes"))
	client := f.Client
	if client == nil {
		client = autoDepHTTPClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("change feed: http %d", resp.StatusCode)
	}
	return resp.Body, nil
}
