package supplychain

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/provenance"
)

// recordingTransport answers every request with an empty JSON object and
// records the URL it was asked for. Using a RoundTripper rather than an
// httptest.Server keeps the test hermetic in both directions: nothing
// reaches the real internet, AND the unconfigured case can be asserted
// against the public registry host without dialling it.
type recordingTransport struct {
	mu   sync.Mutex
	urls []string
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.urls = append(t.urls, req.URL.String())
	t.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(`{}`)),
		Request:    req,
	}, nil
}

// attestationURL returns the single recorded npm-attestation request, or
// "" when none was made. Other traffic Bootstrap's background goroutines
// may emit (popular-package lists, malware feeds) is ignored.
func (t *recordingTransport) attestationURL() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, u := range t.urls {
		if strings.Contains(u, "/-/npm/v1/attestations/") {
			return u
		}
	}
	return ""
}

// TestBootstrapNPMRegistryURLReachesConfiguredRegistry is the wiring
// proof, not an option unit test. provenance.WithNPMRegistryURL was
// already covered by its own package's tests while NOTHING called it —
// so the public registry was still queried in every deployment, and the
// air-gap defect the option exists to fix was live end to end.
//
// This asserts the property that actually matters: a value set on
// BootstrapConfig — the struct cmd/chainsaw-proxy fills from config —
// changes the host the npm provenance probe talks to.
func TestBootstrapNPMRegistryURLReachesConfiguredRegistry(t *testing.T) {
	const mirror = "https://npm.mirror.internal.example"

	cases := []struct {
		name        string
		configured  string
		wantPrefix  string
		description string
	}{
		{
			name:        "configured mirror is used",
			configured:  mirror,
			wantPrefix:  mirror + "/-/npm/v1/attestations/",
			description: "the configured registry",
		},
		{
			// The fallback is a deliberate, documented decision (see
			// defaultNPMRegistryURL) — pin it so it cannot drift into
			// an accident, and so a future "empty means disabled"
			// change has to be made on purpose.
			name:        "unconfigured falls back to the public registry",
			configured:  "",
			wantPrefix:  "https://registry.npmjs.org/-/npm/v1/attestations/",
			description: "the public-registry fallback",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingTransport{}

			// Pre-cancelled so Bootstrap's background loops exit on
			// their first ctx check; the transport makes any request
			// that still slips out harmless.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			comp := Bootstrap(ctx, BootstrapConfig{
				DataDir:             t.TempDir(),
				PopularPackageLimit: 1,
				MalwareSyncInterval: time.Hour,
				Logger:              discardLogger(),
				EnableGHSAMalware:   false,
				NPMRegistryURL:      tc.configured,
				UpstreamHTTPClient:  &http.Client{Transport: rt},
			})
			if comp == nil || comp.ProvenanceChecker == nil {
				t.Fatal("Bootstrap did not return a provenance checker")
			}

			comp.ProvenanceChecker.Check(context.Background(), "npm", "left-pad", "1.3.0")

			got := rt.attestationURL()
			if got == "" {
				t.Fatalf("the npm provenance probe made no attestation request at all")
			}
			if !strings.HasPrefix(got, tc.wantPrefix) {
				t.Fatalf("npm provenance probe asked %q, want %s (prefix %q).\n"+
					"BootstrapConfig.NPMRegistryURL is not reaching "+
					"provenance.WithNPMRegistryURL — a package resolved from a "+
					"mirror would be reported on using a registry it never came from.",
					got, tc.description, tc.wantPrefix)
			}
		})
	}
}

// TestBootstrapNPMRegistryURLRespectsOfflineMode guards the offline
// guarantee against this wiring: a configured registry must never become
// a reason to dial out when provenance is switched off. WithOfflineMode
// unregisters every checker, so the dispatcher answers UNAVAILABLE
// before the npm probe — and its registry URL — is ever consulted.
func TestBootstrapNPMRegistryURLRespectsOfflineMode(t *testing.T) {
	rt := &recordingTransport{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	comp := Bootstrap(ctx, BootstrapConfig{
		DataDir:             t.TempDir(),
		PopularPackageLimit: 1,
		MalwareSyncInterval: time.Hour,
		Logger:              discardLogger(),
		EnableGHSAMalware:   false,
		NPMRegistryURL:      "https://npm.mirror.internal.example",
		UpstreamHTTPClient:  &http.Client{Transport: rt},
		ProvenanceOptions:   []provenance.CheckerOption{provenance.WithOfflineMode()},
	})
	if comp == nil || comp.ProvenanceChecker == nil {
		t.Fatal("Bootstrap did not return a provenance checker")
	}

	got := comp.ProvenanceChecker.Check(context.Background(), "npm", "left-pad", "1.3.0")
	if got.Status != provenance.StatusUnavailable {
		t.Fatalf("offline npm Check Status = %q, want %q", got.Status, provenance.StatusUnavailable)
	}
	if got.Reason != provenance.ReasonOfflineMode {
		t.Errorf("offline npm Check Reason = %q, want %q", got.Reason, provenance.ReasonOfflineMode)
	}
	if u := rt.attestationURL(); u != "" {
		t.Fatalf("offline mode still dialled the npm registry (%s) — the "+
			"registry wiring bypassed the offline gate", u)
	}
}
