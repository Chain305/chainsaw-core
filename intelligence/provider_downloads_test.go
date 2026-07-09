package intelligence

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// withWave4Doer installs a test HTTP doer for the shared Wave-4 / downloads
// outbound seam and restores the production client on cleanup. The seam
// (SetWave4HTTPDoerForTest) lives in core (provider_downloads.go) since the
// open-core split; the premium Wave-4 tests carry their own copy of this
// helper (it cannot cross the package boundary unexported).
func withWave4Doer(t *testing.T, do func(*http.Request) (*http.Response, error)) {
	t.Helper()
	SetWave4HTTPDoerForTest(do)
	t.Cleanup(func() { SetWave4HTTPDoerForTest(nil) })
}

// --- npm download fetcher tests -------------------------------------------

func TestFetchNPMWeeklyDownloads_LowDownloads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "my-pkg") {
			t.Errorf("unexpected URL path: %s", r.URL.Path)
		}
		fmt.Fprintln(w, `{"downloads":42,"start":"2026-04-24","end":"2026-04-30","package":"my-pkg"}`)
	}))
	defer srv.Close()

	withWave4Doer(t, func(req *http.Request) (*http.Response, error) {
		// Rewrite URL to test server.
		req.URL.Host = strings.TrimPrefix(srv.URL, "http://")
		req.URL.Scheme = "http"
		return http.DefaultTransport.RoundTrip(req)
	})

	dl := FetchNPMWeeklyDownloads(context.Background(), "my-pkg")
	if dl != 42 {
		t.Errorf("expected 42 downloads, got %d", dl)
	}
}

func TestFetchNPMWeeklyDownloads_HighDownloads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"downloads":500000}`)
	}))
	defer srv.Close()

	withWave4Doer(t, func(req *http.Request) (*http.Response, error) {
		req.URL.Host = strings.TrimPrefix(srv.URL, "http://")
		req.URL.Scheme = "http"
		return http.DefaultTransport.RoundTrip(req)
	})

	dl := FetchNPMWeeklyDownloads(context.Background(), "popular-pkg")
	if dl != 500000 {
		t.Errorf("expected 500000, got %d", dl)
	}
}

func TestFetchNPMWeeklyDownloads_HTTPError_ReturnsUnknown(t *testing.T) {
	withWave4Doer(t, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusInternalServerError,
			Body:       http.NoBody,
		}, nil
	})

	dl := FetchNPMWeeklyDownloads(context.Background(), "some-pkg")
	if dl != unknownDownloads {
		t.Errorf("expected unknownDownloads sentinel, got %d", dl)
	}
}

func TestFetchNPMWeeklyDownloads_NetworkError_ReturnsUnknown(t *testing.T) {
	withWave4Doer(t, func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("connection refused")
	})

	dl := FetchNPMWeeklyDownloads(context.Background(), "some-pkg")
	if dl != unknownDownloads {
		t.Errorf("expected unknownDownloads sentinel on network error, got %d", dl)
	}
}

func TestFetchNPMWeeklyDownloads_AirGap_ReturnsUnknown(t *testing.T) {
	t.Setenv("CHAINSAW_OFFLINE", "1")

	// No HTTP doer override — if any HTTP is attempted the test would fail.
	dl := FetchNPMWeeklyDownloads(context.Background(), "some-pkg")
	if dl != unknownDownloads {
		t.Errorf("expected unknownDownloads in air-gap mode, got %d", dl)
	}
}

// --- PyPI download fetcher tests ------------------------------------------

func TestFetchPyPIWeeklyDownloads_LowDownloads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"data":{"last_week":15},"type":"recent_downloads"}`)
	}))
	defer srv.Close()

	withWave4Doer(t, func(req *http.Request) (*http.Response, error) {
		req.URL.Host = strings.TrimPrefix(srv.URL, "http://")
		req.URL.Scheme = "http"
		return http.DefaultTransport.RoundTrip(req)
	})

	dl := FetchPyPIWeeklyDownloads(context.Background(), "my-pypackage")
	if dl != 15 {
		t.Errorf("expected 15 downloads, got %d", dl)
	}
}

func TestFetchPyPIWeeklyDownloads_HighDownloads(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, `{"data":{"last_week":200000},"type":"recent_downloads"}`)
	}))
	defer srv.Close()

	withWave4Doer(t, func(req *http.Request) (*http.Response, error) {
		req.URL.Host = strings.TrimPrefix(srv.URL, "http://")
		req.URL.Scheme = "http"
		return http.DefaultTransport.RoundTrip(req)
	})

	dl := FetchPyPIWeeklyDownloads(context.Background(), "popular-lib")
	if dl != 200000 {
		t.Errorf("expected 200000, got %d", dl)
	}
}

func TestFetchPyPIWeeklyDownloads_HTTPError_ReturnsUnknown(t *testing.T) {
	withWave4Doer(t, func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       http.NoBody,
		}, nil
	})

	dl := FetchPyPIWeeklyDownloads(context.Background(), "some-lib")
	if dl != unknownDownloads {
		t.Errorf("expected unknownDownloads on HTTP error, got %d", dl)
	}
}

func TestFetchPyPIWeeklyDownloads_NetworkError_ReturnsUnknown(t *testing.T) {
	withWave4Doer(t, func(req *http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("dial tcp: connection refused")
	})

	dl := FetchPyPIWeeklyDownloads(context.Background(), "some-lib")
	if dl != unknownDownloads {
		t.Errorf("expected unknownDownloads on network error, got %d", dl)
	}
}

func TestFetchPyPIWeeklyDownloads_AirGap_ReturnsUnknown(t *testing.T) {
	t.Setenv("CHAINSAW_OFFLINE", "1")

	dl := FetchPyPIWeeklyDownloads(context.Background(), "some-lib")
	if dl != unknownDownloads {
		t.Errorf("expected unknownDownloads in air-gap mode, got %d", dl)
	}
}

// TestFetchPyPIWeeklyDownloads_NameNormalization verifies that underscores are
// converted to hyphens before hitting the pypistats API.
func TestFetchPyPIWeeklyDownloads_NameNormalization(t *testing.T) {
	var capturedPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		fmt.Fprintln(w, `{"data":{"last_week":10},"type":"recent_downloads"}`)
	}))
	defer srv.Close()

	withWave4Doer(t, func(req *http.Request) (*http.Response, error) {
		req.URL.Host = strings.TrimPrefix(srv.URL, "http://")
		req.URL.Scheme = "http"
		return http.DefaultTransport.RoundTrip(req)
	})

	FetchPyPIWeeklyDownloads(context.Background(), "my_package")
	if !strings.Contains(capturedPath, "my-package") {
		t.Errorf("expected normalized name 'my-package' in path %q", capturedPath)
	}
}
