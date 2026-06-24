package pgpverify

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestLookupKeyDispatchesByLength asserts that 40-char fingerprints hit the
// by-fingerprint endpoint and 16-char long key IDs hit the by-keyid endpoint.
func TestLookupKeyDispatchesByLength(t *testing.T) {
	const (
		fp40 = "ABCDEF0123456789ABCDEF0123456789ABCDEF01"
		id16 = "ABCDEF0123456789"
	)
	seen := map[string]int{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen[r.URL.Path]++
		// Respond with a deliberately unparseable body so LookupKey returns
		// an error — we only care about endpoint routing here.
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not a real pgp key"))
	}))
	defer srv.Close()

	v := NewVerifier(srv.Client(), srv.URL)

	// 40-char → by-fingerprint.
	_, _ = v.LookupKey(context.Background(), fp40)
	wantFP := "/vks/v1/by-fingerprint/" + fp40
	if seen[wantFP] != 1 {
		t.Errorf("want 1 hit on %s, got %d (seen=%v)", wantFP, seen[wantFP], seen)
	}

	// 16-char → by-keyid.
	_, _ = v.LookupKey(context.Background(), id16)
	wantID := "/vks/v1/by-keyid/" + id16
	if seen[wantID] != 1 {
		t.Errorf("want 1 hit on %s, got %d (seen=%v)", wantID, seen[wantID], seen)
	}
}

// TestLookupKeyRejectsInvalidLength asserts that unsupported identifier
// lengths (e.g. 8 hex chars = 32-bit short ID) return an error locally
// without making a network call.
func TestLookupKeyRejectsInvalidLength(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	v := NewVerifier(srv.Client(), srv.URL)
	_, err := v.LookupKey(context.Background(), "ABCDEF01") // 8 hex chars
	if err == nil {
		t.Fatal("want error for 8-char key ID, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported pgp key identifier length") {
		t.Errorf("want length error, got: %v", err)
	}
	if called {
		t.Error("keyserver should not have been contacted for invalid length")
	}
}
