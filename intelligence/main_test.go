package intelligence

import (
	"os"
	"testing"
)

// TestMain opts this package's tests out of the private-range half of the
// SSRF dial guard, as core/provenance and core/upstreamhttp do. The
// registry-metadata client is guarded by default since N-10 (its base URL
// can be an org's repository remote), and these tests drive httptest
// servers on 127.0.0.1. CHAINSAW_ALLOW_PRIVATE_UPSTREAMS=1 is the operator
// escape hatch the dialer reads at dial time, so the real path still runs;
// the metadata literals stay refused. The guard's own coverage is in
// core/httpclient with the variable unset.
func TestMain(m *testing.M) {
	_ = os.Setenv("CHAINSAW_ALLOW_PRIVATE_UPSTREAMS", "1")
	os.Exit(m.Run())
}
