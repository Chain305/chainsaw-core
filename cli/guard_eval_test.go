package cli

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
	"strings"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/intelligence"
	"github.com/chain305/chainsaw-core/malware"
	"github.com/chain305/chainsaw-core/typosquat"
)

func TestParseNpmSpec(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantVer  string
	}{
		{"lodash", "lodash", ""},
		{"lodash@4.17.21", "lodash", "4.17.21"},
		{"@babel/core@7.24.0", "@babel/core", "7.24.0"},
		{"@babel/core", "@babel/core", ""},
	}
	for _, c := range cases {
		got := parseNpmSpec(c.in)
		if got.Name != c.wantName || got.Version != c.wantVer {
			t.Errorf("parseNpmSpec(%q) = {%q,%q}, want {%q,%q}", c.in, got.Name, got.Version, c.wantName, c.wantVer)
		}
		if got.Ecosystem != "npm" {
			t.Errorf("parseNpmSpec(%q) ecosystem = %q, want npm", c.in, got.Ecosystem)
		}
	}
}

func TestParseNpmInstall(t *testing.T) {
	if specs, ok := parseNpmInstall([]string{"run", "build"}); ok || specs != nil {
		t.Errorf("`npm run build` should not be recognized as install; got ok=%v specs=%v", ok, specs)
	}
	specs, ok := parseNpmInstall([]string{"i", "-D", "react@18", "lodash"})
	if !ok {
		t.Fatal("`npm i ...` should be recognized as install")
	}
	if len(specs) != 2 {
		t.Fatalf("want 2 specs (flag skipped), got %d: %v", len(specs), specs)
	}
	if specs[0].Name != "react" || specs[0].Version != "18" || specs[1].Name != "lodash" {
		t.Errorf("unexpected specs: %v", specs)
	}
	// install from lockfile (no named packages) is recognized but yields no specs.
	if specs, ok := parseNpmInstall([]string{"install"}); !ok || len(specs) != 0 {
		t.Errorf("`npm install` (lockfile) want recognized+empty, got ok=%v specs=%v", ok, specs)
	}
}

func TestParsePipInstall(t *testing.T) {
	if _, ok := parsePipInstall([]string{"freeze"}); ok {
		t.Error("`pip freeze` should not be recognized as install")
	}
	specs, ok := parsePipInstall([]string{"install", "-r", "requirements.txt", "requests==2.31.0", "flask[async]>=2"})
	if !ok {
		t.Fatal("`pip install ...` should be recognized")
	}
	// -r + its value skipped; two real specs remain.
	if len(specs) != 2 {
		t.Fatalf("want 2 specs (-r value skipped), got %d: %v", len(specs), specs)
	}
	if specs[0].Name != "requests" || specs[0].Version != "2.31.0" {
		t.Errorf("requests==2.31.0 parsed wrong: %+v", specs[0])
	}
	if specs[1].Name != "flask" || specs[1].Version != "" {
		t.Errorf("flask[async]>=2 should drop extras + leave version empty: %+v", specs[1])
	}
}

func TestParseGoGet(t *testing.T) {
	if _, ok := parseGoGet([]string{"build", "./..."}); ok {
		t.Error("`go build` should not be recognized as get")
	}
	specs, ok := parseGoGet([]string{"get", "-u", "github.com/x/y@v1.2.3"})
	if !ok || len(specs) != 1 {
		t.Fatalf("`go get ...` want recognized+1 spec, got ok=%v specs=%v", ok, specs)
	}
	if specs[0].Name != "github.com/x/y" || specs[0].Version != "v1.2.3" || specs[0].Ecosystem != "go" {
		t.Errorf("unexpected go spec: %v", specs[0])
	}
}

// The offline corpus must load with no network so the wrapper works on the
// install hot path. npm uses the static seed; go uses the embedded seed.
func TestLocalGuardOfflineCorpus(t *testing.T) {
	g := newLocalGuard()
	if d := g.detector("npm"); d == nil {
		t.Error("npm typosquat corpus failed to load offline (detector nil)")
	}
	if d := g.detector("go"); d == nil {
		t.Error("go typosquat corpus failed to load offline (detector nil)")
	}
}

func TestSupplementalInstallAdvisoryPacote(t *testing.T) {
	g := newLocalGuard()
	v := g.evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "pacote", Version: "11.2.7"})
	if !v.Block || v.Severity != "known-vulnerable" {
		t.Fatalf("pacote@11.2.7 should block as known-vulnerable: %+v", v)
	}
	if !strings.Contains(v.Reason, "npm-audit:pacote-transitive-vulnerabilities") {
		t.Fatalf("reason missing advisory id: %q", v.Reason)
	}

	clean := g.evaluate(context.Background(), packageSpec{Ecosystem: "npm", Name: "pacote", Version: "22.0.0"})
	if clean.Block {
		t.Fatalf("pacote@22.0.0 should not block: %+v", clean)
	}
}

func TestGuardUpdateNudgePublicFeedNoAuth(t *testing.T) {
	nudge := guardUpdateNudge()
	if strings.Contains(nudge, "auth login") || strings.Contains(nudge, "sign in") {
		t.Fatalf("guard update nudge should not imply auth is required, got %q", nudge)
	}
	if !strings.Contains(nudge, "chainsaw guard update") {
		t.Fatalf("nudge should mention guard update, got %q", nudge)
	}
}

// The install path no longer prompts-and-downloads the full OpenSSF feed
// inline (it blocked installs for ~2 min); the guard evaluates against the
// offline floor immediately and nudges the user to run `chainsaw guard update`
// on their own schedule. That nudge is covered by TestGuardUpdateNudge above.

// The offline known-malicious floor must block the famous attacks at the exact
// compromised versions, and must NOT block clean versions of the same package.
func TestKnownMaliciousFloor(t *testing.T) {
	ctx := context.Background()
	g := newLocalGuard()
	cases := []struct {
		spec      packageSpec
		wantBlock bool
	}{
		{packageSpec{Ecosystem: "npm", Name: "event-stream", Version: "3.3.6"}, true},
		{packageSpec{Ecosystem: "npm", Name: "event-stream", Version: "4.0.0"}, false}, // clean version
		{packageSpec{Ecosystem: "npm", Name: "ua-parser-js", Version: "0.7.29"}, true},
		{packageSpec{Ecosystem: "npm", Name: "flatmap-stream", Version: ""}, true}, // all-versions malware
		{packageSpec{Ecosystem: "pip", Name: "colourama", Version: ""}, true},      // all-versions malware
		{packageSpec{Ecosystem: "pip", Name: "python3-dateutil", Version: ""}, true},
	}
	for _, c := range cases {
		v := g.evaluate(ctx, c.spec)
		gotMalBlock := v.Block && v.Severity == "malicious"
		if c.wantBlock && !gotMalBlock {
			t.Errorf("%s: want known-malicious BLOCK, got %+v", c.spec, v)
		}
		if !c.wantBlock && gotMalBlock {
			t.Errorf("%s: false known-malicious block: %+v", c.spec, v)
		}
	}
}

// evaluate() must mirror the detector's verdict and apply the block policy:
// high → block, medium → warn (allow), clean → allow.
func TestEvaluatePolicyMirrorsDetector(t *testing.T) {
	ctx := context.Background()
	g := &localGuard{detectors: map[string]*typosquat.Detector{}, malware: malware.NewIndex(nil)}
	d := typosquat.NewDetector(nil)
	d.LoadEcosystem("npm", []typosquat.PopularPackage{
		{Name: "lodash", Rank: 1}, {Name: "react", Rank: 2}, {Name: "express", Rank: 3},
	})
	g.detectors["npm"] = d

	// Exact popular name: never blocked, no typosquat severity.
	clean := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: "lodash"})
	if clean.Block || clean.Severity != "" {
		t.Errorf("exact popular package flagged: %+v", clean)
	}

	// A near-miss: evaluate must mirror whatever the detector decides.
	typo := "lodahs"
	res := d.Check(ctx, "npm", typo)
	v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: typo})
	switch {
	case res.IsSuspected && res.Confidence == "high":
		if !v.Block || v.Severity != "typosquat-high" {
			t.Errorf("high-confidence typo should BLOCK: detector=%+v verdict=%+v", res, v)
		}
	case res.IsSuspected && res.Confidence == "medium":
		if v.Block || v.Severity != "typosquat-medium" {
			t.Errorf("medium-confidence typo should WARN not block: detector=%+v verdict=%+v", res, v)
		}
	default:
		if v.Block {
			t.Errorf("unsuspected name must not block: detector=%+v verdict=%+v", res, v)
		}
	}
}

// --- known-malicious coverage claim (G10) ---------------------------------

// writeMalwareEntriesFile writes n synthetic OSV entries to a temp file and
// returns its path. n controls whether the file clears guardMalwareFeedFloor.
func writeMalwareEntriesFile(t *testing.T, n int) string {
	t.Helper()
	entries := make([]malware.OSVEntry, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, malware.OSVEntry{
			ID: fmt.Sprintf("MAL-TEST-%05d", i),
			Affected: []malware.OSVAffected{{
				Package:  malware.OSVPackage{Name: fmt.Sprintf("synthetic-mal-%05d", i), Ecosystem: "npm"},
				Versions: []string{"1.0.0"},
			}},
		})
	}
	data, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "known_malicious.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestMalwareFeedPlausibilityFloor pins G10: `fullFeed` (which drives
// coverage.SourceMalware in guardLedger, and therefore an operator's
// CHAINSAW_COVERAGE_MODE=closed + CHAINSAW_COVERAGE_REQUIRED=malware gate) was a
// bare presence check — `extra > 0`. A cache file holding ONE dummy entry
// silently flipped that fail-closed gate from refuse to pass, the exact opposite
// of the loud break-glass path. The typosquat corpus has had both a plausibility
// floor and a signature requirement for this same reason.
func TestMalwareFeedPlausibilityFloor(t *testing.T) {
	t.Run("sub-floor file does not claim the full feed", func(t *testing.T) {
		t.Setenv(guardDBEnv, writeMalwareEntriesFile(t, 3))
		idx := malware.NewIndex(guardLogger)
		var floor, extra int
		stderr := captureStderr(t, func() { floor, extra = loadMalwareSources(idx, nil) })
		if extra != 0 {
			t.Fatalf("extra = %d, want 0 (3 entries is not the full OpenSSF set)", extra)
		}
		if floor == 0 {
			t.Fatal("embedded floor should still be loaded")
		}
		// The entries are still MERGED into the index — more known-malicious
		// coordinates can only add blocks; only the coverage CLAIM is gated.
		if res := idx.Lookup(context.Background(), "npm", "synthetic-mal-00001", "1.0.0"); !res.IsKnownMalicious {
			t.Error("sub-floor entries should still be indexed and blockable")
		}
		// And it is LOUD — a silently downgraded security claim is the failure
		// mode this whole check exists to prevent.
		if !strings.Contains(stderr, "WARNING") || !strings.Contains(stderr, guardDBEnv) {
			t.Fatalf("want a loud warning naming %s, got stderr:\n%s", guardDBEnv, stderr)
		}
	})

	t.Run("plausible file claims the full feed", func(t *testing.T) {
		t.Setenv(guardDBEnv, writeMalwareEntriesFile(t, guardMalwareFeedFloor))
		idx := malware.NewIndex(guardLogger)
		var extra int
		stderr := captureStderr(t, func() { _, extra = loadMalwareSources(idx, nil) })
		if extra != guardMalwareFeedFloor {
			t.Fatalf("extra = %d, want %d", extra, guardMalwareFeedFloor)
		}
		if strings.Contains(stderr, "WARNING") {
			t.Fatalf("a plausible feed must not warn, got:\n%s", stderr)
		}
	})

	t.Run("no cache file at all", func(t *testing.T) {
		t.Setenv(guardDBEnv, filepath.Join(t.TempDir(), "absent.json"))
		idx := malware.NewIndex(guardLogger)
		_, extra := loadMalwareSources(idx, nil)
		if extra != 0 {
			t.Fatalf("extra = %d, want 0", extra)
		}
	})
}

// writeMalwareBundle builds a minimal intel bundle carrying an "osv-malware"
// blob. sign=false leaves the `{}` placeholder that only loads with
// SkipSignature (Verified() == false); sign=true writes the digest-binding
// sidecar. Mirrors writeCorpusBundle in guard_typosquat_test.go.
func writeMalwareBundle(t *testing.T, entries int, sign bool) string {
	t.Helper()
	blob, err := os.ReadFile(writeMalwareEntriesFile(t, entries))
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(blob)
	manifest := intelligence.BundleManifest{
		Schema:    intelligence.BundleManifestSchema,
		Version:   "test-malware-1",
		BuildTime: time.Now().UTC(),
		Contents:  map[string]string{"osv-malware": "malware/osv.json"},
		SHA256:    map[string]string{"malware/osv.json": hex.EncodeToString(h[:])},
	}
	mb, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"malware/osv.json": blob, "manifest.json": mb}

	out := filepath.Join(t.TempDir(), "malware-bundle.tar.gz")
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
	for _, closeFn := range []func() error{tw.Close, gz.Close, f.Close} {
		if err := closeFn(); err != nil {
			t.Fatal(err)
		}
	}
	if !sign {
		if err := os.WriteFile(out+".sigstore", []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		return out
	}
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

// An UNVERIFIED bundle's osv-malware blob must not underwrite the full-feed
// coverage claim — the same rule bundleCorpus already applies. Its entries are
// still merged into the index (they can only block more); what a signature gates
// is the CLAIM, not the data.
func TestMalwareBundleMustBeVerifiedToClaimFullFeed(t *testing.T) {
	ctx := context.Background()
	t.Setenv(guardDBEnv, filepath.Join(t.TempDir(), "absent.json"))

	unsigned, err := intelligence.LoadBundle(ctx, writeMalwareBundle(t, guardMalwareFeedFloor, false),
		intelligence.BundleVerifyOptions{SkipSignature: true})
	if err != nil {
		t.Fatalf("load unsigned bundle: %v", err)
	}
	if unsigned.Verified() {
		t.Fatal("skip-verify bundle should report Verified() == false")
	}
	idx := malware.NewIndex(guardLogger)
	if _, extra := loadMalwareSources(idx, unsigned); extra != 0 {
		t.Fatalf("unsigned bundle extra = %d, want 0 (no coverage claim without a signature)", extra)
	}
	if res := idx.Lookup(ctx, "npm", "synthetic-mal-00002", "1.0.0"); !res.IsKnownMalicious {
		t.Error("unsigned bundle entries should still be indexed and blockable")
	}

	verified, err := intelligence.LoadBundle(ctx, writeMalwareBundle(t, guardMalwareFeedFloor, true),
		intelligence.BundleVerifyOptions{})
	if err != nil {
		t.Fatalf("load signed bundle: %v", err)
	}
	if _, extra := loadMalwareSources(malware.NewIndex(guardLogger), verified); extra != guardMalwareFeedFloor {
		t.Fatalf("verified bundle extra = %d, want %d", extra, guardMalwareFeedFloor)
	}
}

// --- combosquat silence (G11) ---------------------------------------------

// TestGuardNeverWarnsOnLowConfidenceCombosquat pins an ABSENCE, deliberately.
//
// checkCombosquat returns IsSuspected with Confidence "low", which matches no
// arm of the verdict ladder — no block, no warn, no telemetry. Measured on this
// repo's own held-out corpora (real, popular packages: npm ranks 2501–5000,
// PyPI 1501–3000) a low-confidence combosquat fires on 274/2500 = 11.0% of npm
// and 184/1500 = 12.3% of PyPI names. Warning on ~1 in 9 real packages would
// recreate the 2026-07 742-false-positive incident in warn form — worse, because
// warnings do not break builds, so they get tuned out and take every real
// warning with them. If this test ever fails because someone "wired up" the
// combosquat branch, re-read that number before changing the assertion.
func TestGuardNeverWarnsOnLowConfidenceCombosquat(t *testing.T) {
	ctx := context.Background()
	g := &localGuard{detectors: map[string]*typosquat.Detector{}, malware: malware.NewIndex(guardLogger)}
	d := typosquat.NewDetector(guardLogger)
	d.LoadEcosystem("npm", []typosquat.PopularPackage{
		{Name: "lodash", Rank: 1}, {Name: "express", Rank: 2}, {Name: "request", Rank: 3},
	})
	g.detectors["npm"] = d

	// Shapes real popular packages take: a popular name with a prefix/suffix.
	for _, name := range []string{"lodash-es", "lodash-utils", "express-session"} {
		res := d.Check(ctx, "npm", name)
		if !res.IsSuspected || res.Method != "combosquat" || res.Confidence != "low" {
			t.Errorf("%q no longer exercises the combosquat branch (%+v) — re-pick the fixture so this pin keeps testing something", name, res)
			continue
		}
		v := g.evaluate(ctx, packageSpec{Ecosystem: "npm", Name: name})
		if v.Block || v.Severity != "" || v.Reason != "" {
			t.Fatalf("%q: low-confidence combosquat must be SILENT (no block, no warn, no reason), got %+v", name, v)
		}
	}
}
