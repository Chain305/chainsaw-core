package intelligence

import (
	"testing"
	"time"
)

// TestMergeMaintenance_PreservesNewFields pins the regression where
// the merge function dropped FirstPublishedAt / Stars / Forks /
// OpenIssues / Subscribers because those fields were added to
// MaintenanceSection without updating mergeMaintenance. The bug
// surfaced in prod as NULL firstPublishedAt / stars / forks / openIssues
// on every refreshed package despite the registry provider setting
// them on its PartialReport. Whenever a new field lands on the
// MaintenanceSection struct, add a sub-case here.
func TestMergeMaintenance_PreservesNewFields(t *testing.T) {
	earlier := time.Date(2013, 5, 1, 0, 0, 0, 0, time.UTC)
	later := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

	t.Run("firstPublishedAt non-nil wins", func(t *testing.T) {
		dst := MaintenanceSection{}
		mergeMaintenance(&dst, MaintenanceSection{FirstPublishedAt: &earlier})
		if dst.FirstPublishedAt == nil || !dst.FirstPublishedAt.Equal(earlier) {
			t.Fatalf("FirstPublishedAt not merged: got %v", dst.FirstPublishedAt)
		}
	})
	t.Run("firstPublishedAt earlier wins over later", func(t *testing.T) {
		dst := MaintenanceSection{FirstPublishedAt: &later}
		mergeMaintenance(&dst, MaintenanceSection{FirstPublishedAt: &earlier})
		if !dst.FirstPublishedAt.Equal(earlier) {
			t.Fatalf("expected earlier (2013) to win, got %v", dst.FirstPublishedAt)
		}
	})
	t.Run("github fields propagate together", func(t *testing.T) {
		dst := MaintenanceSection{}
		mergeMaintenance(&dst, MaintenanceSection{
			Stars: 1234, Forks: 56, OpenIssues: 7, Subscribers: 89,
		})
		if dst.Stars != 1234 || dst.Forks != 56 || dst.OpenIssues != 7 || dst.Subscribers != 89 {
			t.Fatalf("github fields dropped: stars=%d forks=%d issues=%d subs=%d",
				dst.Stars, dst.Forks, dst.OpenIssues, dst.Subscribers)
		}
	})
	t.Run("github fields skipped when source is all-zero", func(t *testing.T) {
		// A second provider returning a zero-filled Maintenance must NOT
		// wipe the GitHub data the first provider populated.
		dst := MaintenanceSection{Stars: 100, Forks: 10, OpenIssues: 1, Subscribers: 5}
		mergeMaintenance(&dst, MaintenanceSection{})
		if dst.Stars != 100 || dst.Forks != 10 || dst.OpenIssues != 1 || dst.Subscribers != 5 {
			t.Fatalf("github fields wiped by all-zero src: stars=%d forks=%d issues=%d subs=%d",
				dst.Stars, dst.Forks, dst.OpenIssues, dst.Subscribers)
		}
	})
}

// TestMergeRelease_PreservesDeprecated pins the regression where
// ReleaseSection.Deprecated was added but mergeRelease ignored it,
// so a refresher tick wiped the npm deprecation string. Non-empty src
// must overwrite; empty src must preserve a richer prior value.
func TestMergeRelease_PreservesDeprecated(t *testing.T) {
	t.Run("non-empty src overwrites dst", func(t *testing.T) {
		dst := ReleaseSection{Deprecated: "old message"}
		mergeRelease(&dst, ReleaseSection{Deprecated: "Use foo@2.x instead"})
		if dst.Deprecated != "Use foo@2.x instead" {
			t.Fatalf("expected non-empty src to win, got %q", dst.Deprecated)
		}
	})
	t.Run("empty src preserves dst", func(t *testing.T) {
		dst := ReleaseSection{Deprecated: "Use foo@2.x instead"}
		mergeRelease(&dst, ReleaseSection{})
		if dst.Deprecated != "Use foo@2.x instead" {
			t.Fatalf("empty src wiped dst.Deprecated: got %q", dst.Deprecated)
		}
	})
	t.Run("empty src and empty dst stay empty", func(t *testing.T) {
		dst := ReleaseSection{}
		mergeRelease(&dst, ReleaseSection{})
		if dst.Deprecated != "" {
			t.Fatalf("expected empty, got %q", dst.Deprecated)
		}
	})
}

// TestMergeProvenance_PreservesNewFields pins the regression where five
// additive ProvenanceSection fields (BundleFormat, SourceCommit,
// SLSALevel, CacheStale, Warnings) were dropped by mergeProvenance.
// Each sub-case asserts the documented semantics for that field.
func TestMergeProvenance_PreservesNewFields(t *testing.T) {
	t.Run("BundleFormat: non-empty src wins", func(t *testing.T) {
		dst := ProvenanceSection{}
		mergeProvenance(&dst, ProvenanceSection{BundleFormat: "sigstore-bundle"})
		if dst.BundleFormat != "sigstore-bundle" {
			t.Fatalf("BundleFormat dropped: got %q", dst.BundleFormat)
		}
	})
	t.Run("BundleFormat: empty src preserves dst", func(t *testing.T) {
		dst := ProvenanceSection{BundleFormat: "in-toto"}
		mergeProvenance(&dst, ProvenanceSection{})
		if dst.BundleFormat != "in-toto" {
			t.Fatalf("BundleFormat wiped: got %q", dst.BundleFormat)
		}
	})
	t.Run("SourceCommit: non-empty src wins", func(t *testing.T) {
		dst := ProvenanceSection{}
		mergeProvenance(&dst, ProvenanceSection{SourceCommit: "abc123"})
		if dst.SourceCommit != "abc123" {
			t.Fatalf("SourceCommit dropped: got %q", dst.SourceCommit)
		}
	})
	t.Run("SourceCommit: empty src preserves dst", func(t *testing.T) {
		dst := ProvenanceSection{SourceCommit: "abc123"}
		mergeProvenance(&dst, ProvenanceSection{})
		if dst.SourceCommit != "abc123" {
			t.Fatalf("SourceCommit wiped: got %q", dst.SourceCommit)
		}
	})
	t.Run("SLSALevel: max wins (src higher)", func(t *testing.T) {
		dst := ProvenanceSection{SLSALevel: 1}
		mergeProvenance(&dst, ProvenanceSection{SLSALevel: 3})
		if dst.SLSALevel != 3 {
			t.Fatalf("expected max=3, got %d", dst.SLSALevel)
		}
	})
	t.Run("SLSALevel: max wins (dst higher)", func(t *testing.T) {
		dst := ProvenanceSection{SLSALevel: 4}
		mergeProvenance(&dst, ProvenanceSection{SLSALevel: 2})
		if dst.SLSALevel != 4 {
			t.Fatalf("expected dst=4 preserved, got %d", dst.SLSALevel)
		}
	})
	t.Run("CacheStale: OR-merge (src=true sticks)", func(t *testing.T) {
		dst := ProvenanceSection{CacheStale: false}
		mergeProvenance(&dst, ProvenanceSection{CacheStale: true})
		if !dst.CacheStale {
			t.Fatalf("CacheStale=true from src was dropped")
		}
	})
	t.Run("CacheStale: OR-merge (dst=true preserved when src=false)", func(t *testing.T) {
		dst := ProvenanceSection{CacheStale: true}
		mergeProvenance(&dst, ProvenanceSection{CacheStale: false})
		if !dst.CacheStale {
			t.Fatalf("CacheStale=true on dst was cleared by src=false")
		}
	})
	t.Run("Warnings: append and dedupe", func(t *testing.T) {
		dst := ProvenanceSection{Warnings: []string{"a", "b"}}
		mergeProvenance(&dst, ProvenanceSection{Warnings: []string{"b", "c"}})
		if len(dst.Warnings) != 3 {
			t.Fatalf("expected 3 unique warnings, got %d: %v", len(dst.Warnings), dst.Warnings)
		}
		want := map[string]bool{"a": true, "b": true, "c": true}
		for _, w := range dst.Warnings {
			if !want[w] {
				t.Fatalf("unexpected warning %q in %v", w, dst.Warnings)
			}
			delete(want, w)
		}
		if len(want) != 0 {
			t.Fatalf("missing warnings: %v", want)
		}
	})
	t.Run("Warnings: empty src preserves dst", func(t *testing.T) {
		dst := ProvenanceSection{Warnings: []string{"served from stale cache"}}
		mergeProvenance(&dst, ProvenanceSection{})
		if len(dst.Warnings) != 1 || dst.Warnings[0] != "served from stale cache" {
			t.Fatalf("Warnings on dst clobbered by empty src: %v", dst.Warnings)
		}
	})
}

// TestMergeScan_PreservesShrinkwrapSuppressed pins the regression where
// ArtifactScanSection.ShrinkwrapSuppressed was added by the shrinkwrap
// provider but mergeScan ignored it. OR-semantics: once observed, the
// bit stays set across the rest of the fan-in.
func TestMergeScan_PreservesShrinkwrapSuppressed(t *testing.T) {
	t.Run("src=true sets dst", func(t *testing.T) {
		dst := ArtifactScanSection{}
		MergeScan(&dst, ArtifactScanSection{ShrinkwrapSuppressed: true})
		if !dst.ShrinkwrapSuppressed {
			t.Fatalf("ShrinkwrapSuppressed=true from src was dropped")
		}
	})
	t.Run("dst=true + src=false preserves true", func(t *testing.T) {
		dst := ArtifactScanSection{ShrinkwrapSuppressed: true}
		MergeScan(&dst, ArtifactScanSection{ShrinkwrapSuppressed: false})
		if !dst.ShrinkwrapSuppressed {
			t.Fatalf("ShrinkwrapSuppressed=true on dst was cleared by src=false")
		}
	})
	t.Run("both false stays false", func(t *testing.T) {
		dst := ArtifactScanSection{}
		MergeScan(&dst, ArtifactScanSection{})
		if dst.ShrinkwrapSuppressed {
			t.Fatalf("ShrinkwrapSuppressed should remain false")
		}
	})
}
