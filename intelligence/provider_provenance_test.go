package intelligence

import (
	"context"
	"io"
	"log/slog"
	"testing"

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
