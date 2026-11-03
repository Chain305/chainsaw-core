package intelligence

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"

	"github.com/chain305/chainsaw-core/coverage"
	"github.com/chain305/chainsaw-core/provenance"
	"github.com/chain305/chainsaw-core/upstreamhttp"
)

func discardProvenanceLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestProvenanceProvider_OfflineMarksUnavailable(t *testing.T) {
	// Offline-mode strips every ecosystem checker so every Check call
	// returns StatusUnavailable — deterministic without hitting the net.
	checker := provenance.NewChecker(discardProvenanceLogger(), provenance.WithOfflineMode())
	p := newProvenanceProvider(checker)

	if !p.Supports("npm") {
		t.Fatalf("npm should be a supported provenance ecosystem")
	}
	partial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Provenance == nil {
		t.Fatalf("expected Provenance section populated")
	}
	if partial.Provenance.Status != string(provenance.StatusUnavailable) {
		t.Fatalf("Status: got %q, want %q", partial.Provenance.Status, string(provenance.StatusUnavailable))
	}
	if partial.Provenance.Verified {
		t.Fatalf("unavailable status must not mark Verified")
	}
	if partial.Provenance.Available {
		t.Fatalf("unavailable status must not mark Available")
	}
}

func TestProvenanceProvider_CancelledCtxEmitsWarning(t *testing.T) {
	checker := provenance.NewChecker(discardProvenanceLogger(), provenance.WithOfflineMode())
	p := newProvenanceProvider(checker)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run

	partial, err := p.Run(ctx, Request{
		Key: Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Provenance == nil || partial.Provenance.Status != string(provenance.StatusUnavailable) {
		t.Fatalf("expected unavailable provenance on cancelled ctx, got %+v", partial.Provenance)
	}
	if len(partial.Warnings) == 0 {
		t.Fatalf("expected at least one warning from cancelled ctx")
	}
	w := partial.Warnings[0]
	if w.Code != WarnBreakerOpen && w.Code != WarnTimeout {
		t.Fatalf("unexpected warning code: %q", w.Code)
	}
	if w.Provider != "provenance" {
		t.Fatalf("warning provider: got %q, want provenance", w.Provider)
	}
}

func TestProvenanceProvider_NilCheckerDisables(t *testing.T) {
	p := newProvenanceProvider(nil)
	if p.Supports("npm") {
		t.Fatalf("nil checker must not support any ecosystem")
	}
	partial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Provenance != nil {
		t.Fatalf("nil checker must not populate Provenance, got %+v", partial.Provenance)
	}
}

func TestProvenanceProvider_UnsupportedEcosystem(t *testing.T) {
	checker := provenance.NewChecker(discardProvenanceLogger())
	p := newProvenanceProvider(checker)
	if p.Supports("nonsense-ecosystem") {
		t.Fatalf("unknown ecosystem must not be supported")
	}
}

// A verified attestation is reused for a month instead of verified again on
// every rescan; anything else, or an older result, is checked again (J.4
// I13-2). The checker here is offline, so a fresh check can only answer
// unavailable: a verified answer proves the prior was reused.
func TestProvenanceProvider_ReusesARecentVerifiedResult(t *testing.T) {
	p := newProvenanceProvider(provenance.NewChecker(discardProvenanceLogger(), provenance.WithOfflineMode()))
	req := Request{Key: Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"}}
	prior := func(verified bool, age time.Duration) *Report {
		r := &Report{}
		r.Provenance = ProvenanceSection{Verified: verified, Available: true, Status: string(provenance.StatusVerified), SourceRepo: "https://github.com/lodash/lodash"}
		r.Observation.CollectedAt = time.Now().Add(-age)
		return r
	}
	got, _ := p.Run(context.Background(), req, prior(true, 24*time.Hour))
	if got.Provenance == nil || !got.Provenance.Verified || got.URLs == nil || got.URLs.SourceRepoURL == "" {
		t.Fatalf("recent verified result not reused: %+v", got.Provenance)
	}
	// The way the scanner actually calls a tier-1 provider: prior nil, the
	// stored row on the request.
	got, _ = p.Run(context.Background(), req.WithStoredRowForTest(prior(true, 24*time.Hour)), nil)
	if got.Provenance == nil || !got.Provenance.Verified {
		t.Fatalf("stored row on the request not reused: %+v", got.Provenance)
	}
	for name, pr := range map[string]*Report{
		"not verified": prior(false, time.Hour),
		"too old":      prior(true, 40*24*time.Hour),
	} {
		got, _ := p.Run(context.Background(), req, pr)
		if got.Provenance == nil || got.Provenance.Status != string(provenance.StatusUnavailable) {
			t.Errorf("%s: reused instead of checked again: %+v", name, got.Provenance)
		}
	}
}

type rateLimitedRT struct{}

func (rateLimitedRT) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, upstreamhttp.ErrRateLimitedLocally
}

// A rate-limited maven check is unavailable, not failed, and must still say
// why. Its warning must also not read as an outage to the opt-in fail-closed
// coverage gate: that would be a new block on a provenance rate limit, which
// no owner has decided.
func TestProvenanceProvider_RateLimitedIsUnavailableAndSaysWhy(t *testing.T) {
	checker := provenance.NewChecker(discardProvenanceLogger(),
		provenance.WithHTTPClient(&http.Client{Transport: rateLimitedRT{}}))
	p := newProvenanceProvider(checker)

	partial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "maven", Package: "io.netty:netty-buffer", Version: "4.2.17.Final"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Provenance == nil || partial.Provenance.Status != string(provenance.StatusUnavailable) {
		t.Fatalf("want unavailable provenance, got %+v", partial.Provenance)
	}
	var found bool
	for _, w := range partial.Warnings {
		if w.Code == WarnParseFailed {
			t.Errorf("rate limit recorded as %q: %+v", WarnParseFailed, w)
		}
		if w.Code == WarnProvenanceRateLimited && w.Message != "" {
			found = true
		}
	}
	if !found {
		t.Errorf("no %q warning carrying the error: %+v", WarnProvenanceRateLimited, partial.Warnings)
	}
	if got := coverage.StatusForWarnCode(WarnProvenanceRateLimited); got == coverage.StatusUnavailable {
		t.Errorf("coverage reads %q as %q; that newly blocks closed-mode orgs on a provenance rate limit",
			WarnProvenanceRateLimited, got)
	}
}

// sidecarRT serves a maven .asc and counts .jar downloads; everything else,
// the keyserver included, is a 404.
type sidecarRT struct {
	sig  []byte
	jars int
}

func (rt *sidecarRT) RoundTrip(r *http.Request) (*http.Response, error) {
	resp := &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}
	switch {
	case strings.HasSuffix(r.URL.Path, ".jar.asc"):
		resp.StatusCode, resp.Body = http.StatusOK, io.NopCloser(bytes.NewReader(rt.sig))
	case strings.HasSuffix(r.URL.Path, ".jar"):
		rt.jars++
		resp.StatusCode, resp.Body = http.StatusOK, io.NopCloser(strings.NewReader("jar"))
	}
	return resp, nil
}

// The provider hands the scanner's artifact bytes to the checker, so the
// maven PGP path does not download the jar a second time. Measured
// 2026-11-03: that jar was the heaviest Central request per gradle row.
func TestProvenanceProvider_PassesHeldArtifactToTheChecker(t *testing.T) {
	signer, err := openpgp.NewEntity("Maven Signer", "", "maven@example.com", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	var sig bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&sig, signer, strings.NewReader("jar"), nil); err != nil {
		t.Fatalf("ArmoredDetachSign: %v", err)
	}
	rt := &sidecarRT{sig: sig.Bytes()}
	p := newProvenanceProvider(provenance.NewChecker(discardProvenanceLogger(),
		provenance.WithHTTPClient(&http.Client{Transport: rt})))

	// The keyserver 404s, so the result is decided by the key lookup alone
	// and must not need the jar when bytes are held.
	if _, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "maven", Package: "io.netty:netty-buffer", Version: "4.2.17.Final"},
		Artifact: &ArtifactHandle{Bytes: []byte("jar")},
	}, nil); err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if rt.jars != 0 {
		t.Errorf("jar downloaded %d times with the artifact already held, want 0", rt.jars)
	}
}

// With no upstream hint, a Google-namespace coordinate must be checked on
// Google Maven. Central and the Gradle plugin portal do not host androidx,
// so every such row read as unsigned.
func TestProvenanceProvider_GoogleGroupsAreCheckedOnGoogleMaven(t *testing.T) {
	for _, eco := range []string{"maven", "gradle"} {
		t.Run(eco, func(t *testing.T) {
			rt := &hostRecorderRT{}
			p := newProvenanceProvider(provenance.NewChecker(discardProvenanceLogger(),
				provenance.WithHTTPClient(&http.Client{Transport: rt})))
			if _, err := p.Run(context.Background(), Request{
				Key: Key{Ecosystem: eco, Package: "androidx.activity:activity", Version: "1.9.0"},
			}, nil); err != nil {
				t.Fatalf("Run err: %v", err)
			}
			if len(rt.hosts) == 0 {
				t.Fatal("no request made")
			}
			for _, h := range rt.hosts {
				if h != "dl.google.com" {
					t.Errorf("asked %s for an androidx signature, want dl.google.com", h)
				}
			}
		})
	}
}

type hostRecorderRT struct{ hosts []string }

func (rt *hostRecorderRT) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.hosts = append(rt.hosts, r.URL.Hostname())
	return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}, nil
}
