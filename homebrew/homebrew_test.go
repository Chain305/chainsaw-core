package homebrew

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const digestA = "d048dd4c28d867e939065a3bc8209f37e2a5be3e2c18d18c8c7da8f4d1629a4a"
const digestB = "dcc989315a2efd06ca4a3fac5c33c237897a1059ed74f35c464a8967ffbb8aaf"
const digestNew = "1111111111111111111111111111111111111111111111111111111111111111"

func formulaJSON(name, version string, revision, rebuild int, digests ...string) map[string]any {
	files := map[string]any{}
	for i, d := range digests {
		files[[]string{"arm64_sequoia", "x86_64_linux", "arm64_tahoe"}[i]] = map[string]any{"url": "https://ghcr.io/v2/homebrew/core/" + ImageName(name) + "/blobs/sha256:" + d, "sha256": d}
	}
	return map[string]any{
		"name": name, "full_name": name, "tap": "homebrew/core", "license": "MIT",
		"versions": map[string]any{"stable": version, "bottle": true},
		"revision": revision,
		"bottle":   map[string]any{"stable": map[string]any{"rebuild": rebuild, "files": files}},
	}
}

func newTestServer(t *testing.T, list []map[string]any, single map[string]map[string]any) (*httptest.Server, *int32) {
	t.Helper()
	var listHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// formulae.brew.sh is a shared public API: every request names us.
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "chainsaw-intelligence") {
			http.Error(w, "no User-Agent", http.StatusBadRequest)
			return
		}
		switch {
		case r.URL.Path == "/api/formula.json":
			atomic.AddInt32(&listHits, 1)
			if r.Header.Get("If-None-Match") == `"v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"v1"`)
			_ = json.NewEncoder(w).Encode(list)
		case strings.HasPrefix(r.URL.Path, "/api/formula/"):
			name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/formula/"), ".json")
			if f, ok := single[name]; ok {
				_ = json.NewEncoder(w).Encode(f)
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &listHits
}

func TestIndexResolvesBottleDigests(t *testing.T) {
	list := []map[string]any{
		formulaJSON("jq", "1.8.2", 0, 1, digestA),
		formulaJSON("openssl@3", "3.4.1", 2, 0, digestB),
		formulaJSON("libxml++", "2.42.4", 0, 0),
	}
	bumped := formulaJSON("jq", "1.8.3", 0, 0, digestNew)
	srv, hits := newTestServer(t, list, map[string]map[string]any{"jq": bumped})
	now := time.Unix(1_800_000_000, 0)
	ix := NewIndex(IndexConfig{APIBase: srv.URL + "/api", Client: srv.Client(), Now: func() time.Time { return now }})
	ctx := context.Background()

	ref, err := ix.ResolveBottle(ctx, "homebrew/core/jq", "sha256:"+digestA)
	ok := err == nil
	if !ok || ref.Formula != "jq" || ref.PkgVersion != "1.8.2" || ref.Platform != "arm64_sequoia" {
		t.Fatalf("jq digest: got %+v ok=%v", ref, ok)
	}
	ref, err = ix.ResolveBottle(ctx, "openssl/3", digestB)
	ok = err == nil
	if !ok || ref.Formula != "openssl@3" || ref.PkgVersion != "3.4.1_2" {
		t.Fatalf("openssl digest: got %+v ok=%v", ref, ok)
	}
	// A digest the full index has never seen falls back to the per-formula
	// document (formula bumped since the last load).
	ref, err = ix.ResolveBottle(ctx, "jq", digestNew)
	ok = err == nil
	if !ok || ref.PkgVersion != "1.8.3" {
		t.Fatalf("bumped digest: got %+v ok=%v", ref, ok)
	}
	// An undeclared digest must not resolve.
	if _, err := ix.ResolveBottle(ctx, "jq", strings.Repeat("ab", 32)); !errors.Is(err, ErrNotFound) {
		t.Fatal("undeclared digest resolved")
	}
	if _, err := ix.ResolveBottle(ctx, "jq", "not-a-digest"); !errors.Is(err, ErrNotFound) {
		t.Fatal("malformed digest resolved")
	}
	// Non-invertible image name resolves through the index.
	f, err := ix.FormulaForImage(ctx, "libxmlxx")
	if err != nil || f.Name != "libxml++" {
		t.Fatalf("libxmlxx: got %v, %v", f, err)
	}
	if got := atomic.LoadInt32(hits); got != 1 {
		t.Fatalf("formula.json fetched %d times within the refresh window, want 1", got)
	}
	// After the refresh window the reload is conditional.
	now = now.Add(11 * time.Minute)
	if _, err := ix.Formula(ctx, "jq"); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(hits); got != 2 {
		t.Fatalf("expected a conditional refetch after the window, hits=%d", got)
	}
	if _, err := ix.ResolveBottle(ctx, "jq", digestA); err != nil {
		t.Fatal("304 refresh dropped the index")
	}
}

func TestVersionHelpers(t *testing.T) {
	f := &Formula{Revision: 1}
	f.Versions.Stable = "2.9.3"
	f.Bottle.Stable.Rebuild = 2
	if f.PkgVersion() != "2.9.3_1" || f.BottleTag() != "2.9.3_1-2" {
		t.Fatalf("pkg=%q tag=%q", f.PkgVersion(), f.BottleTag())
	}
	cases := map[string]string{"1.8.2-1": "1.8.2", "1.8.2": "1.8.2", "2.9.3_1-2": "2.9.3_1", "2024-01": "2024"}
	for tag, want := range cases {
		if got := VersionFromTag(tag, nil); got != want {
			t.Errorf("VersionFromTag(%q)=%q want %q", tag, got, want)
		}
	}
	if got := VersionFromTag("2.9.3_1-2", f); got != "2.9.3_1" {
		t.Errorf("known formula tag: %q", got)
	}
	// A hyphen inside the version itself is not a rebuild marker.
	im := &Formula{}
	im.Versions.Stable = "7.1.2-35"
	for tag, want := range map[string]string{"7.1.2-35": "7.1.2-35", "7.1.2-34": "7.1.2-34", "7.1.2-34-1": "7.1.2-34", "2.9.3_1-2": "2.9.3_1-2"} {
		if got := VersionFromTag(tag, im); got != want {
			t.Errorf("VersionFromTag(%q, imagemagick)=%q want %q", tag, got, want)
		}
	}
	if ImageName("openssl@3") != "openssl/3" || ImageName("libxml++") != "libxmlxx" {
		t.Fatal("ImageName")
	}
	if NormalizeName("homebrew/core/JQ") != "jq" || NormalizeName("user/tap/jq") != "user/tap/jq" {
		t.Fatal("NormalizeName")
	}
	if !IsThirdPartyTapName("user/tap/jq") || IsThirdPartyTapName("homebrew/core/jq") || IsThirdPartyTapName("jq") {
		t.Fatal("IsThirdPartyTapName")
	}
}

func TestCaskFlags(t *testing.T) {
	var c Cask
	raw := `{"token":"x","tap":"homebrew/cask","sha256":"no_check","url":"https://cdn.other.net/x.pkg","homepage":"https://vendor.com","auto_updates":true,
	"artifacts":[{"pkg":["x.pkg"]},{"postflight":null},{"app":["X.app"]}],"disabled":true,"disable_reason":"fails_gatekeeper_check"}`
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatal(err)
	}
	f := c.Flags()
	if !f.NoChecksum || !f.AutoUpdates || !f.RunsInstaller || !f.HasHooks || !f.DownloadHostMismatch || !f.Disabled || f.Reason != "fails_gatekeeper_check" || f.ThirdPartyTap {
		t.Fatalf("flags: %+v", f)
	}
	c2 := Cask{SHA256: strings.Repeat("a", 64), URL: "https://dl.vendor.com/x.dmg", Homepage: "https://www.vendor.com", Tap: "acme/tools"}
	f2 := c2.Flags()
	if f2.NoChecksum || f2.DownloadHostMismatch || !f2.ThirdPartyTap {
		t.Fatalf("flags2: %+v", f2)
	}
}

// Review 2026-11-04: an index that fetched upstream for every unknown name
// let anyone turn made-up names into formulae.brew.sh requests and a cache
// that never shrank; a reload dropped the previous bottle digest while brew
// (behind the proxy's 600s API cache) still asked for it; and a failed
// lookup read as "not declared".
func TestIndexHardening(t *testing.T) {
	var perFormula, fail int32
	list := []map[string]any{formulaJSON("jq", "1.8.2", 0, 0, digestA)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// formulae.brew.sh is a shared public API: every request names us.
		if !strings.HasPrefix(r.Header.Get("User-Agent"), "chainsaw-intelligence") {
			http.Error(w, "no User-Agent", http.StatusBadRequest)
			return
		}
		switch {
		case r.URL.Path == "/api/formula.json":
			_ = json.NewEncoder(w).Encode(list)
		case strings.HasPrefix(r.URL.Path, "/api/formula/"):
			atomic.AddInt32(&perFormula, 1)
			if atomic.LoadInt32(&fail) == 1 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			if r.URL.Path == "/api/formula/jq.json" {
				_ = json.NewEncoder(w).Encode(list[0])
				return
			}
			http.NotFound(w, r)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	now := time.Unix(1_800_000_000, 0)
	ix := NewIndex(IndexConfig{APIBase: srv.URL + "/api", Client: srv.Client(), Now: func() time.Time { return now }})
	ctx := context.Background()

	// 1. Unknown names against a loaded index: not found, no upstream request.
	for i := 0; i < 50; i++ {
		name := "made-up-" + strings.Repeat("x", i%7) + string(rune('a'+i%26))
		if _, err := ix.Formula(ctx, name); !errors.Is(err, ErrNotFound) {
			t.Fatalf("Formula(%q) err=%v", name, err)
		}
		if _, err := ix.ResolveBottle(ctx, name, strings.Repeat("ab", 32)); !errors.Is(err, ErrNotFound) {
			t.Fatalf("ResolveBottle(%q) err=%v", name, err)
		}
	}
	if n := atomic.LoadInt32(&perFormula); n != 0 {
		t.Fatalf("unknown names caused %d per-formula fetches against a loaded index", n)
	}

	// 2. A known formula whose digest misses: one per-formula fetch, then
	//    cached; a failed lookup is an error, not ErrNotFound.
	if _, err := ix.ResolveBottle(ctx, "jq", strings.Repeat("cd", 32)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("undeclared digest err=%v", err)
	}
	if n := atomic.LoadInt32(&perFormula); n != 1 {
		t.Fatalf("per-formula fetches=%d want 1", n)
	}
	now = now.Add(11 * time.Minute) // per-formula TTL over; full index reloads (unchanged)
	atomic.StoreInt32(&fail, 1)
	_, err := ix.ResolveBottle(ctx, "jq", strings.Repeat("cd", 32))
	if err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("failed lookup reported as %v, want a lookup error", err)
	}
	atomic.StoreInt32(&fail, 0)

	// 3. A bump: the reload replaces digestA, which stays declared — as
	//    the PREVIOUS version — for the grace window, then expires.
	list[0] = formulaJSON("jq", "1.8.3", 0, 0, digestNew)
	now = now.Add(11 * time.Minute)
	ref, err := ix.ResolveBottle(ctx, "jq", digestNew)
	if err != nil || ref.PkgVersion != "1.8.3" {
		t.Fatalf("new digest: %+v %v", ref, err)
	}
	ref, err = ix.ResolveBottle(ctx, "jq", digestA)
	if err != nil || ref.PkgVersion != "1.8.2" {
		t.Fatalf("retired digest within grace: %+v %v", ref, err)
	}
	now = now.Add(retiredDigestGrace + time.Minute)
	if _, err := ix.ResolveBottle(ctx, "jq", digestA); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retired digest after grace: err=%v", err)
	}

	// 4. The per-name cache is bounded, and invalid names never go upstream.
	for i := 0; i < maxPerName+10; i++ {
		ix.storePerName("n"+strings.Repeat("0", i%3)+string(rune('a'+i%26))+itoa(i), cachedFormula{fetched: now, missing: true})
	}
	if l := len(ix.perName); l > maxPerName {
		t.Fatalf("perName grew to %d", l)
	}
	before := atomic.LoadInt32(&perFormula)
	for _, bad := range []string{"../etc", "a b", "UPPER\n", strings.Repeat("a", 129), ""} {
		if _, err := ix.fetchOne(ctx, bad); !errors.Is(err, ErrNotFound) {
			t.Fatalf("fetchOne(%q) err=%v", bad, err)
		}
	}
	if atomic.LoadInt32(&perFormula) != before {
		t.Fatal("an invalid name reached the upstream")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

// The live API reports post_install_defined false for every formula;
// post_install_steps is what says one exists (python@3.13, node and
// shared-mime-info have them, jq does not; checked 2026-11-06).
func TestFormulaHasPostInstall(t *testing.T) {
	for body, want := range map[string]bool{
		`{"post_install_defined":false,"post_install_steps":[{"type":"mkdir"}]}`: true,
		`{"post_install_defined":false,"post_install_steps":{"x":1}}`:            true,
		`{"post_install_defined":true}`:                                          true,
		`{"post_install_defined":false,"post_install_steps":null}`:               false,
		`{"post_install_defined":false,"post_install_steps":[]}`:                 false,
		`{"post_install_defined":false}`:                                         false,
	} {
		var f Formula
		if err := json.Unmarshal([]byte(body), &f); err != nil {
			t.Fatal(err)
		}
		if got := f.HasPostInstall(); got != want {
			t.Errorf("%s: %v", body, got)
		}
	}
	if (*Formula)(nil).HasPostInstall() {
		t.Error("nil formula")
	}
}
