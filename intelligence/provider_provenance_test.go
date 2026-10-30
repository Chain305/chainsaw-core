package intelligence

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/provenance"
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
