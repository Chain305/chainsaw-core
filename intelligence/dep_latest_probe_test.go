package intelligence

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The dependency walk answers "latest" from the shared probe row when it is
// current, and goes upstream only when it is missing, expired or errored,
// writing a success back (I12a).
func TestDepLatestVersionUsesSharedProbeRow(t *testing.T) {
	var hits atomic.Int64
	withStubLatestRegistries(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if !strings.Contains(r.Header.Get("Accept"), "application/vnd.npm.install-v1+json") {
			t.Errorf("npm latest lookup asked for %q, want the abbreviated document", r.Header.Get("Accept"))
		}
		_, _ = w.Write([]byte(`{"dist-tags":{"latest":"1.2.3"}}`))
	}))
	store := NewStore(openAnalysisDB(t))
	svc := &DefaultService{store: store, now: time.Now}
	ctx := context.Background()
	pkg := "deplatest-" + strings.ReplaceAll(time.Now().UTC().Format("150405.000000000"), ".", "")
	put := func(latest, errStr string, freshUntil time.Time) {
		t.Helper()
		if err := store.UpsertLatestVersionProbe(ctx, "", LatestVersionProbe{
			Ecosystem: "npm", Package: pkg, LatestVersion: latest,
			ProbedAt: time.Now(), FreshUntil: freshUntil, Error: errStr,
		}); err != nil {
			t.Fatal(err)
		}
	}

	put("9.9.9", "", time.Now().Add(time.Hour))
	if got := svc.depLatestVersion(ctx, "npm", pkg); got != "9.9.9" || hits.Load() != 0 {
		t.Fatalf("fresh row: got %q with %d upstream calls, want 9.9.9 and 0", got, hits.Load())
	}

	for _, tc := range []struct {
		name, latest, errStr string
		freshUntil           time.Time
	}{
		{"expired", "9.9.9", "", time.Now().Add(-time.Hour)},
		{"errored", "", "http 503", time.Now().Add(time.Hour)},
	} {
		put(tc.latest, tc.errStr, tc.freshUntil)
		before := hits.Load()
		if got := svc.depLatestVersion(ctx, "npm", pkg); got != "1.2.3" || hits.Load() != before+1 {
			t.Fatalf("%s row: got %q with %d upstream calls, want 1.2.3 and 1", tc.name, got, hits.Load()-before)
		}
		p, err := store.GetLatestVersionProbe(ctx, "", "npm", pkg)
		if err != nil || p.LatestVersion != "1.2.3" || p.Error != "" || !p.FreshUntil.After(time.Now()) {
			t.Fatalf("%s row: upstream answer not written back: %+v err=%v", tc.name, p, err)
		}
	}
}
