package intelligence

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/chain305/chainsaw-core/upstreamhttp"
)

// An artifact fetch our own client declined -- Maven Central inside a 429
// stand-off, or the per-host limiter -- never asked the registry, so the row is
// provisional and rechecked on the backoff rather than standing for the
// staleness window. A real fetch failure keeps its code and is not.
func TestArtifactFetchDeferredIsProvisional(t *testing.T) {
	for _, tc := range []struct {
		name        string
		err         error
		wantCode    string
		provisional bool
	}{
		{"sonatype stand-off", &url.Error{Op: "Get", URL: "https://repo.maven.apache.org/x.jar", Err: upstreamhttp.ErrUpstreamStandoff}, WarnArtifactFetchDeferred, true},
		{"limiter refusal", upstreamhttp.ErrRateLimitedLocally, WarnArtifactFetchDeferred, true},
		{"transport failure", errors.New("connection reset by peer"), WarnArtifactFetchFailed, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			svc := New(Config{})
			defer svc.Close()
			rep, err := svc.Scan(context.Background(), Request{
				Key:              Key{Ecosystem: "maven", Package: "org.example:lib", Version: "1.0.0"},
				ArtifactFetchErr: tc.err,
			})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, w := range rep.Observation.Warnings {
				if w.Provider == "artifact" && w.Code == tc.wantCode {
					found = true
				}
			}
			if !found {
				t.Fatalf("warnings %v, want artifact/%s", rep.Observation.Warnings, tc.wantCode)
			}
			if rep.Provisional() != tc.provisional {
				t.Fatalf("Provisional() = %v, want %v", rep.Provisional(), tc.provisional)
			}
		})
	}
}
