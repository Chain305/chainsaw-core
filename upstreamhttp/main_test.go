package upstreamhttp

import (
	"os"
	"testing"
)

// TestMain opts this package's tests out of the SSRF dial guard.
//
// upstreamhttp.New now builds its base client with httpclient.WithSSRFGuard
// (see the P8-52 fix), which refuses to dial loopback, RFC1918 and
// link-local addresses. Every test in this package drives a
// httptest.NewServer on 127.0.0.1, so without this they all fail with
// "refusing to dial private/link-local address" — which is the guard
// doing exactly its job.
//
// CHAINSAW_ALLOW_PRIVATE_UPSTREAMS=1 is the same operator escape hatch
// used in production by anyone proxying an internal registry, and
// SafeDialer reads it at dial time, so setting it here exercises the real
// code path rather than stubbing the dialer out.
//
// This does NOT weaken the guard's own coverage: that lives in
// core/httpclient/ssrfguard_test.go, which asserts the block with the
// variable unset and includes a negative control.
func TestMain(m *testing.M) {
	_ = os.Setenv("CHAINSAW_ALLOW_PRIVATE_UPSTREAMS", "1")
	os.Exit(m.Run())
}
