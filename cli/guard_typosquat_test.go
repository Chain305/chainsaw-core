package cli

// Typosquat corpus + verdict-ladder regression gates for the install guard.
//
// Two opposing tripwires, both required to stay green forever:
//
//   - Famous-packages gate: no popular package may ever block (the 2026-07
//     incident: 742 false-positive blocks on typescript/katex/preact/…).
//   - Squat-recall gate: the historical attack shapes (crossenv, loadash,
//     expresss, Cyrillic homoglyphs) must keep blocking after ANY corpus or
//     threshold change. This is the false-negative backstop for every
//     false-positive fix.

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

// newSeedOnlyGuard builds a localGuard with an empty malware index and no
// bundle, so verdicts come from the embedded seeds + ladder alone. Env knobs
// that could pull in artifact bytes are neutralised per-test.
func newSeedOnlyGuard(t *testing.T) *localGuard {
	t.Helper()
	t.Setenv(guardArtifactDirEnv, "")
	t.Setenv(guardDeepFetchEnv, "")
	return &localGuard{
		detectors: map[string]*typosquat.Detector{},
		malware:   malware.NewIndex(guardLogger),
	}
}

// incidentPackages are the 14 real packages the 2026-07 incident blocked or
// that shipped in the same lockfile. Pinned by name: every one must evaluate
// fully silent (no block, no warn) against the embedded corpus.
var incidentPackages = []string{
	"typescript", "zod", "@types/node", "katex", "preact", "recharts",
	"playwright-core", "jspdf", "mammoth", "jiti", "vaul", "canvg",
	"markdown-table", "character-entities",
}

func TestGuardIncidentPackagesFullySilent(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	for _, name := range incidentPackages {
		v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: name})
		if v.Block || v.Severity != "" {
			t.Errorf("%s: want fully silent, got block=%v severity=%q reason=%q",
				name, v.Block, v.Severity, v.Reason)
		}
	}
}

// TestGuardFamousPackagesNeverBlock is the do-not-embarrass gate: the top
// 1000 npm and top 500 PyPI names from the embedded corpora must produce
// zero blocks and zero warns. Also pins the corpus sizes so a seed
// regression (the original 140-entry root cause) fails loudly.
func TestGuardFamousPackagesNeverBlock(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()

	npm := parsePopularSeed(npmPopularSeed)
	if len(npm) < 4000 {
		t.Fatalf("npm seed has %d entries — the corpus shrank (the 140-entry seed caused the 2026-07 incident); regenerate with tools/popular-corpus-gen", len(npm))
	}
	pypi := parsePopularSeed(pypiPopularSeed)
	if len(pypi) < 2000 {
		t.Fatalf("pypi seed has %d entries — the corpus shrank; regenerate with tools/popular-corpus-gen", len(pypi))
	}

	check := func(eco string, pkgs []typosquat.PopularPackage, n int) {
		for _, p := range pkgs[:n] {
			v := g.evaluate(ctx, packageSpec{Ecosystem: eco, Name: p.Name})
			if v.Block {
				t.Errorf("%s:%s BLOCKED (%s) — famous package must never block", eco, p.Name, v.Reason)
			} else if v.Severity != "" {
				t.Errorf("%s:%s warned (%s) — corpus member must be silent", eco, p.Name, v.Reason)
			}
		}
	}
	check("npm", npm, 1000)
	check("pypi", pypi, 500)
}

// TestGuardSquatRecall is the false-negative tripwire: the canonical attack
// shapes must BLOCK under every future corpus/threshold change.
func TestGuardSquatRecall(t *testing.T) {
	g := newSeedOnlyGuard(t)
	ctx := context.Background()
	cases := []struct {
		eco, name, squatOf string
	}{
		{"npm", "crossenv", "cross-env"}, // the 2017 npm credential stealer
		{"npm", "loadash", "lodash"},     // classic transposition squat
		{"npm", "expresss", "express"},   // trailing-char squat
		{"npm", "еxpress", "express"},    // Cyrillic е (U+0435) homoglyph
		{"pypi", "reqests", "requests"},  // colourama-class PyPI squat
	}
	for _, c := range cases {
		v := g.evaluate(ctx, packageSpec{Ecosystem: c.eco, Name: c.name})
		if !v.Block || v.Severity != "typosquat-high" {
			t.Errorf("%s:%s (squat of %s): want BLOCK typosquat-high, got block=%v severity=%q reason=%q",
				c.eco, c.name, c.squatOf, v.Block, v.Severity, v.Reason)
		}
	}
}

// TestGuardTyposquatLadder exercises the method/rank verdict split directly
// with a synthetic corpus: d=1 vs a top-ranked target blocks, d=1 vs a
// tail-ranked target warns, reorder never blocks.
func TestGuardTyposquatLadder(t *testing.T) {
	g := newSeedOnlyGuard(t)
	d := typosquat.NewDetectorWithConfig(guardLogger, typosquat.ThresholdConfig{
		MaxRelativeDistance: guardMaxRelativeDistance,
	})
	d.LoadEcosystem("npm", []typosquat.PopularPackage{
		{Name: "megapopular-package", Rank: 10},
		{Name: "obscure-tail-package", Rank: guardTyposquatBlockRankCutoff + 500},
		{Name: "react-dom-utils", Rank: 50},
	})
	g.detectors["npm"] = d
	ctx := context.Background()

	if v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "megapopular-packagee"}); !v.Block || v.Severity != "typosquat-high" {
		t.Errorf("d=1 vs rank-10 target: want BLOCK, got %+v", v)
	}
	if v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "obscure-tail-packagee"}); v.Block || v.Severity != "typosquat-medium" {
		t.Errorf("d=1 vs tail-rank target: want WARN typosquat-medium, got %+v", v)
	}
	if v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "utils-react-dom"}); v.Block {
		t.Errorf("reorder hit must never block, got %+v", v)
	} else if v.Severity != "typosquat-medium" {
		t.Errorf("reorder hit should warn, got %+v", v)
	}
}

// --- signed-bundle corpus channel -----------------------------------------

// writeCorpusBundle builds a minimal intel bundle carrying a "typosquat"
// blob, mirroring intelligence.writeTestBundle (unexported there). Returns
// the bundle path; sign=true also writes a digest-binding .sigstore sidecar
// so LoadBundle verifies it, sign=false leaves the `{}` placeholder that
// only loads with SkipSignature.
func writeCorpusBundle(t *testing.T, corpus map[string][]string, sign bool) string {
	t.Helper()
	blob, err := json.Marshal(corpus)
	if err != nil {
		t.Fatal(err)
	}

	files := map[string][]byte{"typosquat/refdata.json": blob}
	h := sha256.Sum256(blob)
	manifest := intelligence.BundleManifest{
		Schema:    intelligence.BundleManifestSchema,
		Version:   "test-corpus-1",
		BuildTime: time.Now().UTC(),
		Contents:  map[string]string{"typosquat": "typosquat/refdata.json"},
		SHA256:    map[string]string{"typosquat/refdata.json": hex.EncodeToString(h[:])},
	}
	mb, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	files["manifest.json"] = mb

	out := filepath.Join(t.TempDir(), "corpus-bundle.tar.gz")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(data)), ModTime: manifest.BuildTime}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if !sign {
		if err := os.WriteFile(out+".sigstore", []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		return out
	}
	// Digest-binding sidecar: load once with SkipSignature to learn the
	// canonical digest, then write the messageDigest sidecar LoadBundle's
	// always-on binding layer accepts.
	probe, err := intelligence.LoadBundle(context.Background(), out, intelligence.BundleVerifyOptions{SkipSignature: true})
	if err != nil {
		t.Fatalf("probe load: %v", err)
	}
	sidecar := fmt.Sprintf(`{"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":"%s"}}}`, probe.Digest())
	if err := os.WriteFile(out+".sigstore", []byte(sidecar), 0o644); err != nil {
		t.Fatal(err)
	}
	return out
}

func syntheticCorpus(n int) map[string][]string {
	names := make([]string, 0, n)
	for i := 0; i < n; i++ {
		names = append(names, fmt.Sprintf("bundlecorpuspkg%04d", i))
	}
	return map[string][]string{"npm": names}
}

// TestGuardBundleCorpusSignedOnly: corpus membership grants the typosquat
// exemption, so the bundle channel is honored only when signature-verified
// and plausibly sized. Unsigned (skip-verify) or undersized corpora fall
// back to the embedded seed.
func TestGuardBundleCorpusSignedOnly(t *testing.T) {
	ctx := context.Background()

	verified, err := intelligence.LoadBundle(ctx, writeCorpusBundle(t, syntheticCorpus(600), true), intelligence.BundleVerifyOptions{})
	if err != nil {
		t.Fatalf("load signed bundle: %v", err)
	}
	if !verified.Verified() {
		t.Fatal("test bundle should be digest-verified")
	}
	g := newSeedOnlyGuard(t)
	g.bundle = verified
	if got := len(g.bundleCorpus("npm")); got != 600 {
		t.Fatalf("verified bundle corpus: want 600 entries, got %d", got)
	}
	// The detector for npm should now be built FROM the bundle corpus: a
	// bundle member is exempt, and its d=1 neighbour blocks (rank ≤ cutoff).
	if v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "bundlecorpuspkg0007"}); v.Block || v.Severity != "" {
		t.Errorf("bundle corpus member must be silent, got %+v", v)
	}
	if v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "bundlecorpuspkg00077"}); !v.Block {
		t.Errorf("d=1 neighbour of bundle corpus member should block, got %+v", v)
	}

	unsigned, err := intelligence.LoadBundle(ctx, writeCorpusBundle(t, syntheticCorpus(600), false), intelligence.BundleVerifyOptions{SkipSignature: true})
	if err != nil {
		t.Fatalf("load unsigned bundle: %v", err)
	}
	g2 := newSeedOnlyGuard(t)
	g2.bundle = unsigned
	if got := g2.bundleCorpus("npm"); got != nil {
		t.Fatalf("unsigned bundle must not feed the corpus (exemption channel), got %d entries", len(got))
	}

	small, err := intelligence.LoadBundle(ctx, writeCorpusBundle(t, syntheticCorpus(10), true), intelligence.BundleVerifyOptions{})
	if err != nil {
		t.Fatalf("load small bundle: %v", err)
	}
	g3 := newSeedOnlyGuard(t)
	g3.bundle = small
	if got := g3.bundleCorpus("npm"); got != nil {
		t.Fatalf("undersized bundle corpus must be rejected (poisoning floor), got %d entries", len(got))
	}
}
