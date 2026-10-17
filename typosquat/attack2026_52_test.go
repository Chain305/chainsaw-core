package typosquat

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

// TestAttack2026_52_ProcMacro1 replays the name half of the 2026-08-20
// crates.io compromise: arrayref 0.3.10, internment 0.8.7 and
// append-only-vec 0.1.9 were republished from a compromised account with a
// new dependency on proc-macro1 1.0.107 — a typosquat of dtolnay's
// proc-macro2 whose build.rs downloaded and ran a second stage. cargo fetches
// proc-macro1 through the proxy as its own download, so the typosquat
// detector judges it by name.
//
// Corpus: the embedded cargo seed, the same list production falls back to
// when the crates.io top-N fetch is unreachable (fetchCargo). Controls: the
// real proc-macro2, two of the hijacked crates and other popular names are
// not suspected.
func TestAttack2026_52_ProcMacro1(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	seed, err := NewFetcher(logger).fetchSeed(context.Background(), cargoTopSeed, 1000)
	if err != nil || len(seed) == 0 {
		t.Fatalf("cargo seed: %d entries, err %v", len(seed), err)
	}
	d := NewDetector(logger)
	d.LoadEcosystem("cargo", seed)

	got := d.Check(context.Background(), "cargo", "proc-macro1")
	t.Logf("proc-macro1: %+v", got)
	if !got.IsSuspected || got.SimilarTo != "proc-macro2" {
		t.Fatalf("proc-macro1 not suspected as a squat of proc-macro2: %+v", got)
	}
	for _, name := range []string{"proc-macro2", "internment", "append-only-vec", "serde", "syn"} {
		if r := d.Check(context.Background(), "cargo", name); r.IsSuspected {
			t.Errorf("legitimate crate %s suspected: %+v", name, r)
		}
	}
	// Recorded, not a pass condition: against the 196-name seed alone the
	// legitimate arrayref reads as a medium squat of arrayvec (d=2). The
	// name-only detector has no cargo established list; in production the
	// candidate's own weekly downloads clear it
	// (core/intelligence/typosquat_established.go, >=100k/week).
	if r := d.Check(context.Background(), "cargo", "arrayref"); r.IsSuspected {
		t.Logf("seed-only corpus: arrayref suspected as %s (%s, d=%d) -- cleared downstream by the downloads rule", r.SimilarTo, r.Confidence, r.Distance)
	}
}
