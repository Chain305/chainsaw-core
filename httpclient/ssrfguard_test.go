package httpclient

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestWithSSRFGuardBlocksLoopback pins the dial half of WithSSRFGuard.
//
// The guard exists because core/provenance.NewChecker and
// core/upstreamhttp.New both built a bare client and were then handed an
// org admin's repository remote_url (P8-52). This test fails if either
// the option stops installing SafeDialer or SafeDialer stops classifying
// loopback as unsafe — verified by deletion: removing WithSSRFGuard from
// the client below makes the request succeed and the test fail.
func TestWithSSRFGuardBlocksLoopback(t *testing.T) {
	t.Setenv("CHAINSAW_ALLOW_PRIVATE_UPSTREAMS", "")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	guarded := New(WithTimeout(5*time.Second), WithSSRFGuard())
	if _, err := guarded.Get(srv.URL); err == nil {
		t.Fatalf("guarded client reached loopback %s; SafeDialer did not run", srv.URL)
	}

	// Negative control: without the option the same request succeeds, so
	// a failure above is attributable to the guard and not to the server.
	bare := New(WithTimeout(5 * time.Second))
	resp, err := bare.Get(srv.URL)
	if err != nil {
		t.Fatalf("unguarded client could not reach test server: %v", err)
	}
	_ = resp.Body.Close()
}

// TestWithSSRFGuardDoesNotFollowRedirects pins the redirect half.
//
// Without it, an allowed public host can 302 to 169.254.169.254 and the
// address check never sees the metadata IP, because the dialer only ever
// classifies the first hop's address.
func TestWithSSRFGuardDoesNotFollowRedirects(t *testing.T) {
	t.Setenv("CHAINSAW_ALLOW_PRIVATE_UPSTREAMS", "1") // isolate redirect behaviour from the dial block

	var hops int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hops++
		if strings.HasSuffix(r.URL.Path, "/start") {
			http.Redirect(w, r, "/landed", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	resp, err := New(WithTimeout(5*time.Second), WithSSRFGuard()).Get(srv.URL + "/start")
	if err != nil {
		t.Fatalf("unexpected transport error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected the 302 to be returned unfollowed, got %d", resp.StatusCode)
	}
	if hops != 1 {
		t.Fatalf("expected exactly 1 hop, got %d — the redirect was followed", hops)
	}
}
