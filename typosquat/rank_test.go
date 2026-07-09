package typosquat

import (
	"context"
	"log/slog"
	"testing"
)

// TestCheckSetsTargetRank verifies rank threading: DetectionResult.TargetRank
// carries the matched popular name's rank (explicit Rank when provided,
// slice position + 1 as the backfill) across the detection methods, so the
// guard's verdict ladder can weight d=1 hits by target popularity.
func TestCheckSetsTargetRank(t *testing.T) {
	d := NewDetector(slog.Default())
	d.LoadEcosystem("npm", []PopularPackage{
		{Name: "alpha-popular", Rank: 7},
		{Name: "beta-popular"}, // Rank 0 → backfilled to position 2
	})
	ctx := context.Background()

	if res := d.Check(ctx, "npm", "alpha-populer"); !res.IsSuspected || res.TargetRank != 7 {
		t.Errorf("edit-distance hit: want TargetRank 7, got %+v", res)
	}
	if res := d.Check(ctx, "npm", "beta-populer"); !res.IsSuspected || res.TargetRank != 2 {
		t.Errorf("rank backfill from position: want TargetRank 2, got %+v", res)
	}
	// Cyrillic а (U+0430) homoglyph of alpha-popular.
	if res := d.Check(ctx, "npm", "аlpha-popular"); !res.IsSuspected || res.Method != "homoglyph" || res.TargetRank != 7 {
		t.Errorf("homoglyph hit: want method=homoglyph TargetRank 7, got %+v", res)
	}
	// Token reorder of alpha-popular.
	if res := d.Check(ctx, "npm", "popular-alpha"); !res.IsSuspected || res.Method != "reorder" || res.TargetRank != 7 {
		t.Errorf("reorder hit: want method=reorder TargetRank 7, got %+v", res)
	}
}
