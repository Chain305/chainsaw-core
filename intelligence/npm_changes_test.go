package intelligence

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/pgstore"
)

type fakeChangesStore struct {
	seq       string
	has       bool
	expired   []string
	expireErr error
	wantEcos  string // "" means npm's
}

func (f *fakeChangesStore) GetFeedCheckpoint(context.Context, string) (string, bool, error) {
	return f.seq, f.has, nil
}
func (f *fakeChangesStore) SetFeedCheckpoint(_ context.Context, _ string, seq string) error {
	f.seq, f.has = seq, true
	return nil
}
func (f *fakeChangesStore) ExpireLatestProbes(_ context.Context, ecos, names []string) (int64, error) {
	if f.expireErr != nil {
		return 0, f.expireErr
	}
	if want := f.wantEcos; strings.Join(ecos, ",") != want && !(want == "" && strings.Join(ecos, ",") == "npm,yarn,bun") {
		return 0, fmt.Errorf("ecosystems %v", ecos)
	}
	f.expired = append(f.expired, names...)
	return int64(len(names)), nil
}

// fakeFeed serves update_seq at the root and `total` changes after seq 100,
// one per sequence number, `npmChangesPageSize` per page.
func fakeFeed(t *testing.T, total int, fail *bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *fail {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte(`{"db_name":"registry","update_seq":100}`))
			return
		}
		since, _ := strconv.Atoi(r.URL.Query().Get("since"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		var parts []string
		last := since
		for s := since + 1; s <= 100+total && len(parts) < limit; s++ {
			parts = append(parts, fmt.Sprintf(`{"seq":%d,"id":"pkg-%d","changes":[{"rev":"1-x"}]}`, s, s))
			last = s
		}
		// last_seq as a string on purpose: both shapes occur.
		fmt.Fprintf(w, `{"results":[%s],"last_seq":"%d"}`, strings.Join(parts, ","), last)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestNpmChangesFollowerPolls(t *testing.T) {
	fail := false
	srv := fakeFeed(t, npmChangesPageSize+5, &fail)
	st := &fakeChangesStore{}
	f := &NpmChangesFollower{Store: st, BaseURL: srv.URL, Client: srv.Client(), Interval: 50 * time.Millisecond}
	ctx := context.Background()

	if f.ProbeFeedHealthy("npm") {
		t.Fatal("healthy before any poll")
	}
	// First poll: start at the head, replay nothing.
	if err := f.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if st.seq != "100" || len(st.expired) != 0 || !f.ProbeFeedHealthy("npm") {
		t.Fatalf("first poll: seq=%q expired=%d healthy=%v", st.seq, len(st.expired), f.ProbeFeedHealthy("npm"))
	}
	if f.ProbeFeedHealthy("pypi") {
		t.Fatal("the npm feed reported pypi healthy")
	}
	// Second poll: two pages to the head, every name expired, checkpoint at
	// the last change.
	if err := f.Poll(ctx); err != nil {
		t.Fatal(err)
	}
	if len(st.expired) != npmChangesPageSize+5 || st.expired[0] != "pkg-101" || st.seq != strconv.Itoa(100+npmChangesPageSize+5) {
		t.Fatalf("second poll: expired=%d first=%q seq=%q", len(st.expired), st.expired[0], st.seq)
	}

	// A failed expiry does not move the checkpoint: the window replays.
	st.seq, st.expired, st.expireErr = "100", nil, errors.New("db down")
	if err := f.Poll(ctx); err == nil || st.seq != "100" {
		t.Fatalf("expiry failure: err=%v seq=%q, want an error and seq 100", err, st.seq)
	}

	// A feed that stops answering stops being healthy within 3 intervals.
	st.expireErr, fail = nil, true
	if err := f.Poll(ctx); err == nil {
		t.Fatal("poll of a down feed returned nil")
	}
	time.Sleep(4 * f.Interval)
	if f.ProbeFeedHealthy("npm") {
		t.Fatal("still healthy after the feed stopped answering")
	}
}

// One rule for every probe reader: older than the bound counts only while
// the feed says the ecosystem is current; the long TTL only while it does.
func TestProbeFeedBoundAndTTL(t *testing.T) {
	now := time.Now()
	old := &LatestVersionProbe{Ecosystem: "npm", ProbedAt: now.Add(-48 * time.Hour)}
	young := &LatestVersionProbe{Ecosystem: "npm", ProbedAt: now.Add(-time.Hour)}
	t.Cleanup(func() { ProbeFeedHealthy = nil })

	ProbeFeedHealthy = nil
	if probeWithinFeedBound(old, now, 24*time.Hour) || !probeWithinFeedBound(young, now, 24*time.Hour) {
		t.Fatal("without a feed: an old probe counted or a young one did not")
	}
	if probeTTL("npm", 24*time.Hour) != 24*time.Hour {
		t.Fatal("long TTL without a feed")
	}
	ProbeFeedHealthy = func(eco string) bool { return eco == "npm" }
	if !probeWithinFeedBound(old, now, 24*time.Hour) {
		t.Fatal("with a healthy feed an old npm probe did not count")
	}
	if probeWithinFeedBound(&LatestVersionProbe{Ecosystem: "pypi", ProbedAt: old.ProbedAt}, now, 24*time.Hour) {
		t.Fatal("the npm feed kept an old pypi probe current")
	}
	if probeTTL("npm", 24*time.Hour) != npmFeedProbeTTL || probeTTL("pypi", 24*time.Hour) != 24*time.Hour {
		t.Fatal("TTL not long for npm only")
	}
}

// Every reader of a probe applies the bound; they need a database to reach,
// so the source is what is checked.
func TestProbeReadersApplyFeedBound(t *testing.T) {
	for file, want := range map[string]string{
		"refresher.go":    "probe.FreshUntil.After(r.now()) && probeWithinFeedBound(probe, r.now(), r.cfg.MaxStaleness)",
		"dep_enqueuer.go": "probeWithinFeedBound(p, s.now(), DefaultMaxStaleness)",
		"store.go":        "if !probeWithinFeedBound(probe, time.Now(), DefaultMaxStaleness) {",
	} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), want) {
			t.Fatalf("%s no longer contains %q", file, want)
		}
	}
	src, _ := os.ReadFile("refresher.go")
	if !strings.Contains(string(src), "ttl = probeTTL(ecosystem, ttl)") {
		t.Fatal("refresher.go no longer writes probes with probeTTL")
	}
}

func TestStoreFeedCheckpointAndExpire(t *testing.T) {
	dsn := os.Getenv("CHAINSAW_DATABASE_URL")
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set")
	}
	db, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := NewStore(db)
	ctx := context.Background()
	feed := "test-feed-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	t.Cleanup(func() { _, _ = db.DB().Exec(`DELETE FROM upstream_feed_checkpoints WHERE feed = $1`, feed) })
	if _, ok, err := s.GetFeedCheckpoint(ctx, feed); ok || err != nil {
		t.Fatalf("new feed: ok=%v err=%v", ok, err)
	}
	for _, seq := range []string{"10", "11"} {
		if err := s.SetFeedCheckpoint(ctx, feed, seq); err != nil {
			t.Fatal(err)
		}
	}
	if seq, ok, _ := s.GetFeedCheckpoint(ctx, feed); !ok || seq != "11" {
		t.Fatalf("checkpoint = %q %v, want 11", seq, ok)
	}

	pkg := "feedtest-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	now := time.Now()
	for _, p := range []LatestVersionProbe{
		{Ecosystem: "npm", Package: pkg, LatestVersion: "1.0.0", ProbedAt: now, FreshUntil: now.Add(time.Hour)},
		{Ecosystem: "pypi", Package: pkg, LatestVersion: "1.0.0", ProbedAt: now, FreshUntil: now.Add(time.Hour)},
		{Ecosystem: "npm", Package: pkg + "-other", LatestVersion: "1.0.0", ProbedAt: now, FreshUntil: now.Add(time.Hour)},
	} {
		if err := s.UpsertLatestVersionProbe(ctx, "", p); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = db.DB().Exec(`DELETE FROM intelligence_latest_probes WHERE package_name LIKE $1`, pkg+"%")
	})
	n, err := s.ExpireLatestProbes(ctx, []string{"npm", "yarn", "bun"}, []string{pkg, "not-held"})
	if err != nil || n != 1 {
		t.Fatalf("expired %d (%v), want 1", n, err)
	}
	stale := func(eco, name string) bool {
		p, err := s.GetLatestVersionProbe(ctx, "", eco, name)
		return err == nil && !p.FreshUntil.After(time.Now())
	}
	if !stale("npm", pkg) || stale("pypi", pkg) || stale("npm", pkg+"-other") {
		t.Fatal("expired the wrong probes")
	}
}

// The Go module index: timestamps as the checkpoint, module paths expired
// for "go" only, pages of goIndexPageSize, and a full page that does not
// advance is an error rather than a loop.
func TestGoIndexFollowerPolls(t *testing.T) {
	base := time.Date(2026, 10, 29, 7, 0, 0, 0, time.UTC)
	total := goIndexPageSize + 3
	stuck := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		since, err := time.Parse(time.RFC3339Nano, r.URL.Query().Get("since"))
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		n := 0
		for i := 1; i <= total && n < goIndexPageSize; i++ {
			ts := base.Add(time.Duration(i) * time.Millisecond)
			if stuck {
				ts = since
			} else if !ts.After(since) {
				continue
			}
			fmt.Fprintf(w, "{\"Path\":\"example.com/m%d\",\"Version\":\"v1.0.%d\",\"Timestamp\":%q}\n", i, i, ts.Format(time.RFC3339Nano))
			n++
		}
	}))
	t.Cleanup(srv.Close)
	st := &fakeChangesStore{wantEcos: "go", seq: base.Format(time.RFC3339Nano), has: true}
	f := NewGoIndexFollower(st)
	f.BaseURL, f.Client, f.Interval = srv.URL, srv.Client(), time.Minute
	if err := f.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(st.expired) != total || st.expired[0] != "example.com/m1" || !f.ProbeFeedHealthy("go") || f.ProbeFeedHealthy("npm") {
		t.Fatalf("expired=%d first=%v healthy go=%v npm=%v", len(st.expired), st.expired[:1], f.ProbeFeedHealthy("go"), f.ProbeFeedHealthy("npm"))
	}
	if want := base.Add(time.Duration(total) * time.Millisecond).Format(time.RFC3339Nano); st.seq != want {
		t.Fatalf("checkpoint %q, want %q", st.seq, want)
	}
	stuck = true
	if err := f.Poll(context.Background()); err == nil || !strings.Contains(err.Error(), "did not advance") {
		t.Fatalf("a full page at one timestamp: err=%v, want the stuck-page error", err)
	}

	// A first run starts at now, replaying nothing.
	fresh := &fakeChangesStore{wantEcos: "go"}
	g := NewGoIndexFollower(fresh)
	g.BaseURL, g.Client = srv.URL, srv.Client()
	if err := g.Poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ts, err := time.Parse(time.RFC3339Nano, fresh.seq); err != nil || time.Since(ts) > time.Minute || len(fresh.expired) != 0 {
		t.Fatalf("first run: seq=%q expired=%d", fresh.seq, len(fresh.expired))
	}
}
