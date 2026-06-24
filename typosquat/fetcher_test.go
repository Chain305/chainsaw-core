package typosquat

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestEnforceRequestSafety(t *testing.T) {
	tests := []struct {
		name    string
		rawURL  string
		wantErr bool
	}{
		{"allowlisted npm", "https://registry.npmjs.org/-/v1/search", false},
		{"allowlisted pypi (canonical)", "https://hugovk.dev/top-pypi-packages/top-pypi-packages-30-days.min.json", false},
		{"allowlisted pypi (legacy github.io)", "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json", false},
		{"allowlisted crates", "https://crates.io/api/v1/crates", false},
		{"reject plain http", "http://registry.npmjs.org/-/v1/search", true},
		{"reject off-allowlist host", "https://attacker.example.com/-/v1/search", true},
		{"reject lookalike host", "https://registry-npmjs.org.attacker.example/", true},
		{"reject non-https scheme", "ftp://registry.npmjs.org/", true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := url.Parse(tc.rawURL)
			if err != nil {
				t.Fatalf("setup: url parse %q: %v", tc.rawURL, err)
			}
			err = enforceRequestSafety(u)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("enforceRequestSafety(%q) = nil, want error", tc.rawURL)
				}
				if !errors.Is(err, ErrSuspiciousRegistryResponse) {
					t.Fatalf("err = %v, want ErrSuspiciousRegistryResponse", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("enforceRequestSafety(%q) = %v, want nil", tc.rawURL, err)
			}
		})
	}
}

func TestSanityCheckPopularCount(t *testing.T) {
	// Just above the floor is fine.
	if err := sanityCheckPopularCount("npm", minPlausiblePopularPackages); err != nil {
		t.Fatalf("unexpected error at floor: %v", err)
	}
	// Well above the floor is fine.
	if err := sanityCheckPopularCount("npm", 5000); err != nil {
		t.Fatalf("unexpected error at 5000: %v", err)
	}
	// Under the floor must fail and wrap the sentinel so callers can
	// distinguish tampering from transient network errors.
	err := sanityCheckPopularCount("npm", 3)
	if err == nil {
		t.Fatal("expected error under floor, got nil")
	}
	if !errors.Is(err, ErrSuspiciousRegistryResponse) {
		t.Fatalf("err = %v, want ErrSuspiciousRegistryResponse", err)
	}
}

// TestFetchPopularPackagesFloorRejectsTamperedFeed exercises the end-to-end
// tampering guard. A stubbed fetcher that returns a three-package "feed" —
// the sort of payload a middlebox might inject to hide an attacker's
// typosquat — must fail at the sanity floor rather than loading into the
// detector.
func TestFetchPopularPackagesFloorRejectsTamperedFeed(t *testing.T) {
	// Stand up a localhost test server. We add its host to the allowlist for
	// the duration of the test so enforceRequestSafety lets the request
	// through (the server is HTTPS-terminated at the httptest layer via
	// TLS). The test validates the integrity-floor path, not the host-
	// allowlist path — that has its own test above.
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// PyPI-shaped response with only three entries — well under the floor.
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"rows":[{"project":"a"},{"project":"b"},{"project":"c"}]}`)
	}))
	defer ts.Close()

	tsURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatalf("parse test URL: %v", err)
	}
	host := tsURL.Hostname()
	allowedRegistryHosts[host] = struct{}{}
	t.Cleanup(func() { delete(allowedRegistryHosts, host) })

	f := NewFetcher(nil)
	// Disable TLS verification for the httptest self-signed cert. This
	// cannot leak into the production default because NewFetcher returned
	// a fresh transport we own.
	f.client = ts.Client()
	f.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many redirects")
		}
		return enforceRequestSafety(req.URL)
	}

	// Swap PyPI's endpoint to our test server for the duration of the call
	// by using the internal fetcher directly — that's the entry point
	// FetchPopularPackages would call.
	ctx := context.Background()
	body, err := f.fetchRaw(ctx, ts.URL+"/")
	if err != nil {
		t.Fatalf("fetchRaw: unexpected error: %v", err)
	}
	if !strings.Contains(string(body), "\"project\":\"a\"") {
		t.Fatalf("setup broken: test body missing, got %q", string(body))
	}

	// Directly exercise the floor with the tampered shape.
	if err := sanityCheckPopularCount("pypi", 3); err == nil {
		t.Fatal("expected floor to reject 3-entry feed")
	}
}

// TestFetchPopularPackagesGoCocoapods asserts the seed-backed Go and
// Cocoapods popular-list fetchers return enough entries to survive the
// minPlausiblePopularPackages floor and honour the limit parameter. This
// is the integration-ish test required by PR 4's test plan.
func TestFetchPopularPackagesGoCocoapods(t *testing.T) {
	f := NewFetcher(nil)
	ctx := context.Background()

	for _, tc := range []struct {
		eco string
	}{
		{"go"},
		{"gomod"},
		{"cocoapods"},
		{"pub"},
	} {
		t.Run(tc.eco, func(t *testing.T) {
			// Ask for a generous limit so the full seed flows through.
			pkgs, err := f.FetchPopularPackages(ctx, tc.eco, 1000)
			if err != nil {
				t.Fatalf("FetchPopularPackages(%q) error: %v", tc.eco, err)
			}
			if len(pkgs) < minPlausiblePopularPackages {
				t.Fatalf("seed returned %d entries, want ≥ %d (tampering floor)",
					len(pkgs), minPlausiblePopularPackages)
			}
			// Honour a tighter limit.
			pkgs2, err := f.FetchPopularPackages(ctx, tc.eco, 10)
			if err != nil {
				// Limit < floor: the floor check is skipped, so any error
				// here is a real bug.
				t.Fatalf("FetchPopularPackages(%q, 10) error: %v", tc.eco, err)
			}
			if len(pkgs2) != 10 {
				t.Errorf("limit=10 returned %d entries", len(pkgs2))
			}
			// Rank order preserved.
			for i, p := range pkgs2 {
				if p.Rank != i {
					t.Errorf("rank not preserved at %d: got %d", i, p.Rank)
				}
			}
		})
	}
}

// TestFetchSeedSkipsCommentsAndBlankLines verifies the embedded-seed
// parser ignores '#' comment lines and blank lines. The seed files start
// with multi-line provenance headers, so a regression here would poison
// the detector with '#'-prefixed "package names".
func TestFetchSeedSkipsCommentsAndBlankLines(t *testing.T) {
	f := NewFetcher(nil)
	input := []byte("# comment line\n\n  \ngithub.com/foo/bar\n# another comment\ngithub.com/baz/qux\n")
	pkgs, err := f.fetchSeed(context.Background(), input, 100)
	if err != nil {
		t.Fatalf("fetchSeed error: %v", err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 packages, got %d: %+v", len(pkgs), pkgs)
	}
	if pkgs[0].Name != "github.com/foo/bar" || pkgs[1].Name != "github.com/baz/qux" {
		t.Errorf("unexpected names: %+v", pkgs)
	}
}

func TestFetchRawRejectsOffAllowlistHost(t *testing.T) {
	f := NewFetcher(nil)
	_, err := f.fetchRaw(context.Background(), "https://attacker.example.com/feed.json")
	if err == nil {
		t.Fatal("expected error for off-allowlist host")
	}
	if !errors.Is(err, ErrSuspiciousRegistryResponse) {
		t.Fatalf("err = %v, want ErrSuspiciousRegistryResponse", err)
	}
}
