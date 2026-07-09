package intelligence

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/chain305/chainsaw-core/typosquat"
)

func discardTyposquatLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestTyposquatProvider_CleanPackageReturnsClean(t *testing.T) {
	det := typosquat.NewDetector(discardTyposquatLogger())
	// Seed a popular-name list so the detector has an index; checking
	// the seeded name itself must return clean (exact popular match).
	det.LoadEcosystem("npm", []typosquat.PopularPackage{
		{Name: "lodash", Rank: 1},
		{Name: "react", Rank: 2},
	})

	p := newTyposquatProvider(det)
	if !p.Supports("npm") {
		t.Fatalf("expected npm to be supported")
	}
	partial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.SupplyChain == nil {
		t.Fatalf("expected SupplyChain section populated")
	}
	if partial.SupplyChain.TyposquatStatus != "clean" {
		t.Fatalf("TyposquatStatus: got %q, want clean", partial.SupplyChain.TyposquatStatus)
	}
}

func TestTyposquatProvider_SuspectedSurfaces(t *testing.T) {
	det := typosquat.NewDetector(discardTyposquatLogger())
	det.LoadEcosystem("npm", []typosquat.PopularPackage{
		{Name: "lodash", Rank: 1},
	})

	p := newTyposquatProvider(det)
	// "lodahs" is edit-distance 2 from "lodash" → detector reports
	// IsSuspected=true.
	partial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "lodahs", Version: "1.0.0"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.SupplyChain == nil {
		t.Fatalf("SupplyChain section should be populated")
	}
	if partial.SupplyChain.TyposquatStatus != "suspected" {
		t.Fatalf("TyposquatStatus: got %q, want suspected", partial.SupplyChain.TyposquatStatus)
	}
	if partial.SupplyChain.TyposquatSimilarTo != "lodash" {
		t.Fatalf("TyposquatSimilarTo: got %q, want lodash", partial.SupplyChain.TyposquatSimilarTo)
	}
	if partial.SupplyChain.TyposquatConfidence == "" {
		t.Fatalf("TyposquatConfidence should be populated")
	}
}

func TestTyposquatProvider_NilDetectorDisables(t *testing.T) {
	p := newTyposquatProvider(nil)
	if p.Supports("npm") {
		t.Fatalf("nil detector must not support any ecosystem")
	}
	partial, err := p.Run(context.Background(), Request{
		Key: Key{Ecosystem: "npm", Package: "lodash", Version: "4.17.21"},
	}, nil)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.SupplyChain != nil {
		t.Fatalf("nil detector must not populate SupplyChain, got %+v", partial.SupplyChain)
	}
}

func TestTyposquatProvider_UnsupportedEcosystem(t *testing.T) {
	det := typosquat.NewDetector(discardTyposquatLogger())
	p := newTyposquatProvider(det)
	// apt / yum / dnf are classified low-risk and explicitly not in the
	// EcosystemsWithTyposquatRisk list.
	if p.Supports("apt") {
		t.Fatalf("apt should not be a supported typosquat ecosystem")
	}
	if p.Supports("nonsense") {
		t.Fatalf("unknown ecosystem should not be supported")
	}
}
