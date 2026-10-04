package intelligence

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/upstreamhttp"
)

type refusingTransport struct{}

func (refusingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, upstreamhttp.ErrRateLimitedLocally
}

// Our own limiter refusing a request is not a transport failure: the
// registry was never asked. It is a cancelled fetch, so the Unknown it
// causes is provisional, not served for 24h.
func TestRegistryLocalRateLimitIsACancellation(t *testing.T) {
	p := &registryMetadataProvider{
		client: &http.Client{Transport: refusingTransport{}},
		now:    func() time.Time { return time.Unix(0, 0).UTC() },
	}
	var out map[string]any
	warn, retryable, _, err := p.fetchOnce(context.Background(), "https://registry.example/json5", "application/json",
		func(r io.Reader) error { return json.NewDecoder(r).Decode(&out) })
	if err == nil || warn == nil {
		t.Fatal("a refused request must not be success")
	}
	if warn.Code != WarnRegistryCancelled {
		t.Fatalf("code = %q, want %q", warn.Code, WarnRegistryCancelled)
	}
	if retryable {
		t.Fatal("retrying a request our own limiter just refused for lack of time only burns the budget")
	}
}

// The background marking is what keeps child scans and warm-up from
// starving foreground scans of registry tokens; both run detached from any
// caller, so this reads the source. It catches a deleted call, not a
// disabled one.
func TestBestEffortScansAreMarkedBackground(t *testing.T) {
	for _, f := range []string{"dep_enqueuer.go", "cache_warm.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "upstreamhttp.WithBackground(") {
			t.Errorf("%s no longer marks its scans as background", f)
		}
	}
}
