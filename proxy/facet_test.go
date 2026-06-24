package proxy

import (
	"net/http"
	"sync"
	"testing"
)

// TestRecordUpstreamErrorNormalizesEcosystem pins the cardinality bound
// added in finding #13 of the post-Wave-9 sanity audit: an unvalidated
// ecosystem string passed to the recorder seam must collapse to "other"
// rather than minting a fresh Prometheus label.
func TestRecordUpstreamErrorNormalizesEcosystem(t *testing.T) {
	prev := upstreamErrorRecorder
	t.Cleanup(func() { upstreamErrorRecorder = prev })

	var mu sync.Mutex
	var captured []string
	SetUpstreamErrorRecorder(func(eco string) {
		mu.Lock()
		defer mu.Unlock()
		captured = append(captured, eco)
	})

	cases := []struct {
		in, want string
	}{
		{"npm", "npm"},
		{"pypi", "other"}, // not in repository.Format enum (the enum uses "pip")
		{"pip", "pip"},
		{"docker", "docker"},
		{"", "other"},
		{"something-an-attacker-injected", "other"},
	}
	for _, c := range cases {
		recordUpstreamError(c.in)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(captured) != len(cases) {
		t.Fatalf("captured %d, want %d", len(captured), len(cases))
	}
	for i, c := range cases {
		if captured[i] != c.want {
			t.Errorf("recordUpstreamError(%q) emitted %q, want %q", c.in, captured[i], c.want)
		}
	}
}

func TestReleaseTimestampIgnoresDateHeader(t *testing.T) {
	// The HTTP Date header is the time the upstream served the response, not
	// when the artifact was published. Trusting it caused the "released
	// within N days" quarantine rule to block arbitrarily old packages on
	// first fetch.
	resp := &http.Response{
		Header: http.Header{
			"Date": {"Mon, 14 Apr 2026 12:00:00 GMT"},
		},
	}
	if ts := releaseTimestamp(resp); !ts.IsZero() {
		t.Fatalf("expected Date-only response to yield zero release time, got %v", ts)
	}
}

func TestReleaseTimestampUsesLastModified(t *testing.T) {
	resp := &http.Response{
		Header: http.Header{
			"Last-Modified": {"Mon, 01 Jan 2024 00:00:00 GMT"},
			"Date":          {"Mon, 14 Apr 2026 12:00:00 GMT"},
		},
	}
	ts := releaseTimestamp(resp)
	if ts.IsZero() {
		t.Fatalf("expected Last-Modified to be used as release time")
	}
	if ts.Year() != 2024 {
		t.Fatalf("expected 2024 from Last-Modified, got %v", ts)
	}
}

func TestStripConditionalHeaders(t *testing.T) {
	header := http.Header{
		"If-None-Match":       {`"abc"`},
		"If-Modified-Since":   {"Thu, 20 Nov 2025 00:00:00 GMT"},
		"If-Match":            {`"foo"`},
		"If-Unmodified-Since": {"Thu, 20 Nov 2025 00:00:00 GMT"},
		"If-Range":            {"Wed, 19 Nov 2025 00:00:00 GMT"},
		"Accept":              {"*/*"},
	}

	stripConditionalHeaders(header)

	for _, key := range []string{
		"If-None-Match",
		"If-Modified-Since",
		"If-Match",
		"If-Unmodified-Since",
		"If-Range",
	} {
		if values := header.Values(key); len(values) != 0 {
			t.Fatalf("header %s was not removed: %v", key, values)
		}
	}
	if got := header.Get("Accept"); got != "*/*" {
		t.Fatalf("non-conditional header was altered, got %q", got)
	}
}

func TestStripConditionalHeadersNil(t *testing.T) {
	var header http.Header
	stripConditionalHeaders(header)
	// Should not panic; header remains nil.
	if header != nil {
		t.Fatalf("expected nil header to stay nil, got %#v", header)
	}
}
