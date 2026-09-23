package intelligence

// Live check against proxy.golang.org, opt-in via CHAINSAW_LIVE_GOPROXY=1.
//
// This is the check that would have caught the original defect and did not
// exist: the unit test above asserts the STRING, and the string was
// self-consistently wrong for 6,093 of 6,139 production coordinates. Only the
// proxy can say whether a path resolves.
//
// Skipped by default — it needs the network and the proxy is rate-limited.

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"
)

func TestGoProxyArtifactPathResolvesLive(t *testing.T) {
	if os.Getenv("CHAINSAW_LIVE_GOPROXY") != "1" {
		t.Skip("set CHAINSAW_LIVE_GOPROXY=1 to run (network, rate-limited upstream)")
	}
	// Real coordinates taken from the production corpus, in the shape the
	// lockfile parsers actually store them: bare.
	for _, c := range []struct{ pkg, ver string }{
		{"rsc.io/sampler", "1.3.0"},
		{"cloud.google.com/go/webrisk", "1.9.6"},
		{"github.com/google/uuid", "1.6.0"},
	} {
		path := GoProxyArtifactPath(c.pkg, c.ver)
		ok := path != ""
		if !ok {
			t.Errorf("%s@%s: refused", c.pkg, c.ver)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		req, _ := http.NewRequestWithContext(ctx, http.MethodHead,
			"https://proxy.golang.org/"+path, nil)
		resp, err := http.DefaultClient.Do(req)
		cancel()
		if err != nil {
			t.Skipf("network unavailable: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s@%s -> /%s returned %d, want 200 — the path this builds "+
				"does not resolve on the real proxy", c.pkg, c.ver, path, resp.StatusCode)
		}
	}
}
