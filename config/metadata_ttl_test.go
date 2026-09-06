package config

import (
	"testing"
	"time"
)

// TestMetadataTTLPerFormatDefaults pins the builtin positive TTLs. npm
// and pip are the two formats whose documents were measured drifting in
// production (an npm packument 21 days stale, others 45 and 55); every
// other format keeps the previous never-expire behaviour because
// core/proxy has no mutable-document classifier for it.
func TestMetadataTTLPerFormatDefaults(t *testing.T) {
	for _, tc := range []struct {
		format string
		want   time.Duration
	}{
		{"npm", 600 * time.Second},
		{"yarn", 600 * time.Second},
		{"bun", 600 * time.Second},
		{"pip", 600 * time.Second},
		{"NPM", 600 * time.Second}, // case-insensitive
		{"maven", 0},
		{"docker", 0},
		{"cargo", 0},
		{"", 0},
	} {
		got := RepositoryConfig{Format: tc.format}.MetadataTTL()
		if got != tc.want {
			t.Errorf("format %q: MetadataTTL = %s, want %s", tc.format, got, tc.want)
		}
	}
}

// TestMetadataTTLExplicitOverrides pins the operator knob: a positive
// value wins over the builtin, and a NEGATIVE value is the explicit off
// switch (0 cannot be, because 0 is the zero value that means "unset").
func TestMetadataTTLExplicitOverrides(t *testing.T) {
	r := RepositoryConfig{Format: "npm", Cache: CacheConfig{MetadataTTLSeconds: 60}}
	if got := r.MetadataTTL(); got != 60*time.Second {
		t.Errorf("explicit 60s: got %s", got)
	}

	off := RepositoryConfig{Format: "npm", Cache: CacheConfig{MetadataTTLSeconds: -1}}
	if got := off.MetadataTTL(); got != 0 {
		t.Errorf("explicit disable: got %s, want 0", got)
	}

	on := RepositoryConfig{Format: "maven", Cache: CacheConfig{MetadataTTLSeconds: 300}}
	if got := on.MetadataTTL(); got != 300*time.Second {
		t.Errorf("explicit opt-in on a format with no builtin: got %s", got)
	}
}

// TestMetadataTTLResolvesWithoutNormalize is the guard that this fix can
// actually run in production.
//
// normalize() is the YAML load path. Repositories hydrated from the
// database build a RepositoryConfig by hand (store.go fetchRepositories
// / fetchRepository set Cache.NegativeTTLSeconds directly) and never
// call it. A default applied only in normalize would read as 0 —
// disabled — for every DB-backed deployment, which is every production
// deployment, and the whole change would be silently inert.
//
// Verified by deletion: moving the builtin lookup out of MetadataTTL and
// into normalize makes this fail with "TTL = 0s".
func TestMetadataTTLResolvesWithoutNormalize(t *testing.T) {
	// Exactly the shape store.go builds from a DB row: no normalize call.
	dbHydrated := RepositoryConfig{
		Name:   "npmjs",
		Format: "npm",
		Type:   "proxy",
		Cache:  CacheConfig{NegativeTTLSeconds: 600},
	}
	if got := dbHydrated.MetadataTTL(); got != 600*time.Second {
		t.Fatalf("a DB-hydrated npm repository resolved MetadataTTL = %s, want 600s; "+
			"the positive TTL would be disabled in production", got)
	}
}

// TestNegativeTTLUnchanged is the regression control: the new knob must
// not have disturbed the existing one.
func TestNegativeTTLUnchanged(t *testing.T) {
	r := RepositoryConfig{Format: "npm", Cache: CacheConfig{NegativeTTLSeconds: 90}}
	if got := r.NegativeTTL(); got != 90*time.Second {
		t.Errorf("NegativeTTL = %s, want 90s", got)
	}
}

// TestMetadataTTLSurvivesFormatOptionsRoundTrip pins the durable home.
//
// Every proxy deployment is DB-backed, so the config the process runs on
// is read back out of the repositories table. A per-repository override
// with no column and no envelope entry would be dropped on every boot —
// and dropped SILENTLY, because MetadataTTL would quietly fall back to
// the per-format builtin rather than erroring.
//
// Verified by deletion: removing the MetadataTTLSeconds assignment from
// decodeRepoFormatOptions makes this fail with "got 45, want 45 -> 0".
func TestMetadataTTLSurvivesFormatOptionsRoundTrip(t *testing.T) {
	original := RepositoryConfig{
		Name:   "npmjs",
		Format: "npm",
		Cache:  CacheConfig{NegativeTTLSeconds: 600, MetadataTTLSeconds: 45},
	}
	encoded, err := encodeRepoFormatOptions(original)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if encoded == "" {
		t.Fatal("a repository carrying only a metadata TTL encoded to an empty " +
			"format_options blob; the override is dropped on save")
	}

	var restored RepositoryConfig
	restored.Format = "npm"
	decodeRepoFormatOptions(encoded, &restored)
	if restored.Cache.MetadataTTLSeconds != 45 {
		t.Fatalf("MetadataTTLSeconds = %d, want 45", restored.Cache.MetadataTTLSeconds)
	}
	if got := restored.MetadataTTL(); got != 45*time.Second {
		t.Errorf("MetadataTTL after round trip = %s, want 45s", got)
	}
}

// TestUnsetMetadataTTLStillEncodesEmpty is the regression control: a
// repository with no APT/Yum block and no TTL override must keep
// encoding to "" so existing rows are not needlessly rewritten.
func TestUnsetMetadataTTLStillEncodesEmpty(t *testing.T) {
	encoded, err := encodeRepoFormatOptions(RepositoryConfig{Name: "npmjs", Format: "npm"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if encoded != "" {
		t.Errorf("format_options = %q, want empty", encoded)
	}
}
