package provenance

import (
	"os"
	"testing"
)

// TestMain opts this package's tests out of the SSRF dial guard.
//
// NewChecker now builds its client with httpclient.WithSSRFGuard (the
// P8-52 fix): a CheckRequest's UpstreamURL comes from an org admin's
// repository remote, so it is a tenant-influenced egress path and must
// not be able to reach loopback or link-local space.
//
// The Swift checker's tests drive a httptest.NewServer on 127.0.0.1, so
// without this they fail with "refusing to dial private/link-local
// address" — the guard working as intended, not a regression.
//
// CHAINSAW_ALLOW_PRIVATE_UPSTREAMS=1 is the same operator escape hatch
// production uses for an internal registry, and SafeDialer reads it at
// dial time, so the real code path is still exercised.
//
// The guard's own coverage is in core/httpclient/ssrfguard_test.go, with
// the variable unset and a negative control; nothing here weakens it.
func TestMain(m *testing.M) {
	_ = os.Setenv("CHAINSAW_ALLOW_PRIVATE_UPSTREAMS", "1")
	os.Exit(m.Run())
}
