package intelligence

// bundle_test.go — unit tests for the W4 intelligence bundle loader.
// Covers: round-trip build → load, schema rejection, hash mismatch
// detection, freshness logic, fail-mode parsing, and the active-bundle
// hot-swap accessor.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

// writeTestBundle builds a minimal-but-valid bundle to a temp path.
// Returns (bundlePath, sigstorePath). The .sigstore sidecar is the
// dev-mode placeholder our verifier accepts when SkipSignature is set.
func writeTestBundle(t *testing.T, contents map[string]string, buildTime time.Time, schemaOverride string) string {
	t.Helper()
	tmp := t.TempDir()
	out := filepath.Join(tmp, "test-bundle.tar.gz")

	files := map[string][]byte{}
	contentMap := map[string]string{}
	hashes := map[string]string{}
	for key, payload := range contents {
		rel := key + "/data.json"
		data := []byte(payload)
		files[rel] = data
		contentMap[key] = rel
		h := sha256.Sum256(data)
		hashes[rel] = hex.EncodeToString(h[:])
	}

	schema := BundleManifestSchema
	if schemaOverride != "" {
		schema = schemaOverride
	}
	manifest := BundleManifest{
		Schema:    schema,
		Version:   "test-1.0",
		BuildTime: buildTime,
		Contents:  contentMap,
		SHA256:    hashes,
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	files["manifest.json"] = manifestBytes

	f, err := os.Create(out)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, data := range files {
		if err := tw.WriteHeader(&tar.Header{
			Name:    name,
			Mode:    0o644,
			Size:    int64(len(data)),
			ModTime: buildTime,
		}); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("write data: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gz: %v", err)
	}

	// Empty placeholder sidecar — the dev-mode verifier accepts any
	// well-formed JSON file.
	if err := os.WriteFile(out+".sigstore", []byte(`{}`), 0o644); err != nil {
		t.Fatalf("write sigstore: %v", err)
	}
	return out
}

func TestLoadBundle_RoundTrip(t *testing.T) {
	path := writeTestBundle(t,
		map[string]string{
			"kev":         `{"vulnerabilities":[]}`,
			"osv-malware": `[]`,
		},
		time.Now().UTC().Add(-time.Hour),
		"")

	b, err := LoadBundle(context.Background(), path, BundleVerifyOptions{SkipSignature: true})
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if got := b.Manifest().Version; got != "test-1.0" {
		t.Errorf("version: got %q want test-1.0", got)
	}
	if data := b.File("kev"); !bytes.Contains(data, []byte("vulnerabilities")) {
		t.Errorf("kev contents: got %q", data)
	}
	if b.Stale() {
		t.Errorf("fresh bundle reported stale")
	}
}

func TestLoadBundle_StaleWarn(t *testing.T) {
	path := writeTestBundle(t,
		map[string]string{"kev": `{}`},
		time.Now().UTC().Add(-2*BundleStaleAfter),
		"")
	b, err := LoadBundle(context.Background(), path, BundleVerifyOptions{SkipSignature: true})
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	if !b.Stale() {
		t.Errorf("expected stale=true on aged bundle")
	}
}

func TestLoadBundle_RejectsUnknownSchema(t *testing.T) {
	path := writeTestBundle(t,
		map[string]string{"kev": `{}`},
		time.Now().UTC(),
		"chainsaw.intel-bundle/v999")
	_, err := LoadBundle(context.Background(), path, BundleVerifyOptions{SkipSignature: true})
	if err == nil {
		t.Fatalf("expected schema rejection")
	}
}

func TestLoadBundle_DetectsHashMismatch(t *testing.T) {
	// Hand-roll a bundle with a manifest that lies about the contents.
	tmp := t.TempDir()
	out := filepath.Join(tmp, "bad.tar.gz")
	manifest := BundleManifest{
		Schema:    BundleManifestSchema,
		Version:   "bad",
		BuildTime: time.Now().UTC(),
		Contents:  map[string]string{"kev": "kev/data.json"},
		// Hash of literally zero bytes — won't match the actual file.
		SHA256: map[string]string{"kev/data.json": hex.EncodeToString(sha256.New().Sum(nil))},
	}
	mb, _ := json.Marshal(manifest)
	files := map[string][]byte{
		"manifest.json": mb,
		"kev/data.json": []byte("{}"),
	}
	f, _ := os.Create(out)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for n, d := range files {
		_ = tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: int64(len(d))})
		_, _ = tw.Write(d)
	}
	tw.Close()
	gz.Close()
	f.Close()
	_ = os.WriteFile(out+".sigstore", []byte("{}"), 0o644)
	_, err := LoadBundle(context.Background(), out, BundleVerifyOptions{SkipSignature: true})
	if err == nil {
		t.Fatalf("expected hash-mismatch error")
	}
}

func TestParseFailMode(t *testing.T) {
	cases := map[string]FailMode{
		"":                  FailModeConditionDefault,
		"condition-default": FailModeConditionDefault,
		"open":              FailModeOpen,
		"fail-open":         FailModeOpen,
		"closed":            FailModeClosed,
		"fail-closed":       FailModeClosed,
		"BLOCK":             FailModeClosed,
		"  open  ":          FailModeOpen,
		"garbage":           FailModeConditionDefault,
	}
	for in, want := range cases {
		if got := ParseFailMode(in); got != want {
			t.Errorf("ParseFailMode(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestSetActiveBundle_HotSwap(t *testing.T) {
	prev := activeBundle.Load()
	defer activeBundle.Store(prev)

	path := writeTestBundle(t,
		map[string]string{"kev": `{}`},
		time.Now().UTC(),
		"")
	b, err := LoadBundle(context.Background(), path, BundleVerifyOptions{SkipSignature: true})
	if err != nil {
		t.Fatalf("LoadBundle: %v", err)
	}
	SetActiveBundle(b)
	if got := ActiveBundle(); got != b {
		t.Errorf("ActiveBundle did not return the swapped bundle")
	}
}

func TestBundleNilSafety(t *testing.T) {
	var b *Bundle
	if b.Verified() || b.Authenticated() || !b.Stale() || b.Digest() != "" || b.Path() != "" || b.Age() != 0 {
		t.Errorf("nil bundle accessors returned unexpected non-zero values")
	}
	if b.File("kev") != nil || b.FileRaw("x") != nil || len(b.ContentKeys()) != 0 {
		t.Errorf("nil bundle accessors returned non-nil data")
	}
}

// writeSidecar overwrites the .sigstore sidecar next to bundlePath with a
// minimal sigstore-shaped JSON carrying the given digest string.
func writeSidecar(t *testing.T, bundlePath, digestField string) {
	t.Helper()
	body := fmt.Sprintf(`{"messageSignature":{"messageDigest":{"algorithm":"SHA2_256","digest":%q}}}`, digestField)
	if err := os.WriteFile(bundlePath+".sigstore", []byte(body), 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
}

// bundleCanonicalDigest loads the bundle once with verification skipped to
// learn the canonical digest the loader computes over the tarball, so the
// signature tests don't re-derive the canonicalisation.
func bundleCanonicalDigest(t *testing.T, path string) string {
	t.Helper()
	b, err := LoadBundle(context.Background(), path, BundleVerifyOptions{SkipSignature: true})
	if err != nil {
		t.Fatalf("seed load (skip): %v", err)
	}
	return b.Digest() // hex
}

func TestVerifyBundleSignature_MatchingHexDigest(t *testing.T) {
	path := writeTestBundle(t, map[string]string{"kev": `{}`}, time.Now().UTC(), "")
	writeSidecar(t, path, bundleCanonicalDigest(t, path)) // hex form

	b, err := LoadBundle(context.Background(), path, BundleVerifyOptions{})
	if err != nil {
		t.Fatalf("verify with matching hex digest should pass: %v", err)
	}
	if !b.Verified() {
		t.Errorf("Verified() = false after a matching-digest verify")
	}
}

func TestVerifyBundleSignature_MatchingBase64Digest(t *testing.T) {
	path := writeTestBundle(t, map[string]string{"kev": `{}`}, time.Now().UTC(), "")
	raw, err := hex.DecodeString(bundleCanonicalDigest(t, path))
	if err != nil {
		t.Fatalf("decode canonical digest: %v", err)
	}
	writeSidecar(t, path, base64.StdEncoding.EncodeToString(raw)) // base64 form

	b, err := LoadBundle(context.Background(), path, BundleVerifyOptions{})
	if err != nil {
		t.Fatalf("verify with matching base64 digest should pass: %v", err)
	}
	if !b.Verified() {
		t.Errorf("Verified() = false after a matching base64-digest verify")
	}
}

func TestVerifyBundleSignature_RejectsMismatchedDigest(t *testing.T) {
	path := writeTestBundle(t, map[string]string{"kev": `{}`}, time.Now().UTC(), "")
	// 32 zero bytes — well-formed but not this bundle's digest.
	writeSidecar(t, path, hex.EncodeToString(make([]byte, 32)))

	if _, err := LoadBundle(context.Background(), path, BundleVerifyOptions{}); err == nil {
		t.Fatalf("a sidecar digest that does not match the bundle must be rejected")
	}
}

func TestVerifyBundleSignature_RejectsEmptySidecar(t *testing.T) {
	// Regression for the forged-bundle hole: the previous stub returned nil
	// for any well-formed JSON, so the `{}` placeholder loaded as
	// Verified()==true. It must now fail real verification.
	path := writeTestBundle(t, map[string]string{"kev": `{}`}, time.Now().UTC(), "")
	// writeTestBundle already wrote a `{}` sidecar; do not skip signature.
	if _, err := LoadBundle(context.Background(), path, BundleVerifyOptions{}); err == nil {
		t.Fatalf("empty `{}` sidecar must fail signature verify (the forged-bundle hole)")
	}
}

func TestVerifyBundleSignature_RejectsMalformedSidecar(t *testing.T) {
	path := writeTestBundle(t, map[string]string{"kev": `{}`}, time.Now().UTC(), "")
	if err := os.WriteFile(path+".sigstore", []byte("this is not json"), 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
	if _, err := LoadBundle(context.Background(), path, BundleVerifyOptions{}); err == nil {
		t.Fatalf("a malformed (non-JSON) sidecar must be rejected")
	}
}

func TestVerifyBundleSignature_SkipVerifyEnvBypasses(t *testing.T) {
	// The documented dev/test escape hatch still works, and a skipped
	// signature must NOT report Verified()==true.
	t.Setenv(BundleSkipVerifyEnvVar, "1")
	path := writeTestBundle(t, map[string]string{"kev": `{}`}, time.Now().UTC(), "")
	b, err := LoadBundle(context.Background(), path, BundleVerifyOptions{})
	if err != nil {
		t.Fatalf("%s=1 should bypass verification: %v", BundleSkipVerifyEnvVar, err)
	}
	if b.Verified() {
		t.Errorf("Verified() must be false when the signature check was skipped")
	}
}

// --- Strict (full Sigstore authenticity) tests ---------------------------
//
// These cover the second verification layer wired into
// verifyBundleSignature. The full crypto path is delegated to
// provenance/sigstoreverify (the same verifier the OPA policy bundle
// uses), so — exactly as internal/policy/dsl/signing.VerifyBundle's tests
// do — we exercise:
//   - the load-bearing identity-pinning predicate directly (no network),
//   - the offline rejection path via SetDefaultVerifierForTesting, and
//   - the safety invariant that strict mode is genuinely OFF by default.
// Producing a real bot-minted .sigstore would require a live Fulcio/Rekor
// signing flow, which is out of scope for a unit test.

// TestStrictVerify_DefaultStillAcceptsDigestOnlySidecar is the boot-path
// regression guard: with strict mode OFF (the default), today's
// digest-only sidecar must STILL load as Verified()==true. If this ever
// fails, the default flipped to strict and would break offline/airgap
// operators whose bundles are not yet bot-signed.
func TestStrictVerify_DefaultStillAcceptsDigestOnlySidecar(t *testing.T) {
	path := writeTestBundle(t, map[string]string{"kev": `{}`}, time.Now().UTC(), "")
	writeSidecar(t, path, bundleCanonicalDigest(t, path))

	b, err := LoadBundle(context.Background(), path, BundleVerifyOptions{})
	if err != nil {
		t.Fatalf("default (non-strict) load of a digest-bound bundle must pass: %v", err)
	}
	if !b.Verified() {
		t.Errorf("Verified() = false for a digest-bound bundle in default mode")
	}
}

// TestStrictVerify_RejectsDigestOnlySidecar proves strict mode does NOT
// silently fall back to digest binding: a digest-only sidecar (which is
// not a parseable unified Sigstore bundle) must be rejected once
// authenticity is required, both via the option and via the env var.
func TestStrictVerify_RejectsDigestOnlySidecar(t *testing.T) {
	// Offline stub: bundle.UnmarshalJSON inside sigstoreverify.Verify
	// rejects the digest-only JSON before the (nil) trust root is touched.
	restore := sigstoreverify.SetDefaultVerifierForTesting(t, nil)
	t.Cleanup(restore)

	path := writeTestBundle(t, map[string]string{"kev": `{}`}, time.Now().UTC(), "")
	writeSidecar(t, path, bundleCanonicalDigest(t, path)) // valid digest, but not a real sigstore bundle

	if _, err := LoadBundle(context.Background(), path, BundleVerifyOptions{RequireAuthenticity: true}); err == nil {
		t.Fatalf("strict mode must reject a digest-only sidecar (not a unified Sigstore bundle)")
	}

	// Same outcome via the env-var seam.
	t.Setenv(BundleStrictVerifyEnvVar, "1")
	if _, err := LoadBundle(context.Background(), path, BundleVerifyOptions{}); err == nil {
		t.Fatalf("%s=1 must reject a digest-only sidecar", BundleStrictVerifyEnvVar)
	}
}

// TestStrictVerify_RejectsCorruptSidecar is the "attacker swapped the
// sidecar bytes" path under strict mode. With the offline stub installed,
// the corrupt bytes are rejected by bundle.UnmarshalJSON inside
// sigstoreverify.Verify — the bundle-bytes rejection path, not a network
// error. Note: the digest-binding layer (layer 1) rejects this even
// earlier because the bytes are not valid JSON; strict mode is a superset.
func TestStrictVerify_RejectsCorruptSidecar(t *testing.T) {
	restore := sigstoreverify.SetDefaultVerifierForTesting(t, nil)
	t.Cleanup(restore)

	path := writeTestBundle(t, map[string]string{"kev": `{}`}, time.Now().UTC(), "")
	if err := os.WriteFile(path+".sigstore", []byte("not a sigstore bundle, just bytes"), 0o644); err != nil {
		t.Fatalf("write sidecar: %v", err)
	}
	if _, err := LoadBundle(context.Background(), path, BundleVerifyOptions{RequireAuthenticity: true}); err == nil {
		t.Fatalf("strict mode must reject a corrupt sidecar")
	}
}

// TestDefaultIntelSignerIdentityRegexp_AcceptsAndRejects exercises the
// load-bearing identity predicate: the canonical chainsaw-release-signer
// workflow URL must match, and near-miss / wrong-signer URLs (notably the
// policy-signer bot, the inverse of the policy bundle's lateral-movement
// test) must NOT. A regexp too loose silently authenticates the wrong bot.
func TestDefaultIntelSignerIdentityRegexp_AcceptsAndRejects(t *testing.T) {
	re, err := regexp.Compile(DefaultIntelSignerIdentityRegexp)
	if err != nil {
		t.Fatalf("DefaultIntelSignerIdentityRegexp compile: %v", err)
	}

	cases := []struct {
		name     string
		identity string
		want     bool
	}{
		{
			name:     "canonical release tag",
			identity: "https://github.com/chainsaw-releases/chainsaw/.github/workflows/release.yml@refs/tags/v2026.05.01",
			want:     true,
		},
		{
			name:     "canonical release tag (.yaml spelling)",
			identity: "https://github.com/chainsaw-releases/chainsaw/.github/workflows/release.yaml@refs/tags/v1",
			want:     true,
		},
		{
			name:     "branch ref instead of tag ref — must reject (the regexp pins refs/tags/)",
			identity: "https://github.com/chainsaw-releases/chainsaw/.github/workflows/release.yml@refs/heads/main",
			want:     false,
		},
		{
			name:     "policy-signer bot — wrong surface, must reject",
			identity: "https://github.com/chainsaw-policy-signer/chainsaw/.github/workflows/sign-policy-bundle.yml@refs/heads/main",
			want:     false,
		},
		{
			name:     "wrong owner",
			identity: "https://github.com/some-attacker/chainsaw/.github/workflows/release.yml@refs/tags/v1",
			want:     false,
		},
		{
			name:     "subdomain spoof",
			identity: "https://github.com.attacker.tld/chainsaw-releases/chainsaw/.github/workflows/release.yml@refs/tags/v1",
			want:     false,
		},
		{
			name:     "http not https — must reject",
			identity: "http://github.com/chainsaw-releases/chainsaw/.github/workflows/release.yml@refs/tags/v1",
			want:     false,
		},
		{
			name:     "missing ref suffix",
			identity: "https://github.com/chainsaw-releases/chainsaw/.github/workflows/release.yml",
			want:     false,
		},
		{name: "empty", identity: "", want: false},
		{name: "not a url", identity: "not-a-url", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := re.MatchString(tc.identity); got != tc.want {
				t.Errorf("MatchString(%q) = %v, want %v", tc.identity, got, tc.want)
			}
		})
	}
}

// TestIntelSignerIdentityRegexp_OverrideCompiles guards the operator
// override path: a self-publisher supplies their own IdentityRegexp (or
// CHAINSAW_INTEL_BUNDLE_IDENTITY) to authenticate internally-built
// bundles. We assert a representative override compiles and matches a
// self-issued identity, since a malformed override would hard-fail every
// strict-mode load.
func TestIntelSignerIdentityRegexp_OverrideCompiles(t *testing.T) {
	override := `^https://gitlab\.example\.com/security/intel/.+$`
	re, err := regexp.Compile(override)
	if err != nil {
		t.Fatalf("override regexp does not compile: %v", err)
	}
	selfIssued := "https://gitlab.example.com/security/intel/build@v1"
	if !re.MatchString(selfIssued) {
		t.Errorf("override regexp %q did not match self-issued identity %q", override, selfIssued)
	}
	// And the canonical bot URL must NOT match a tightened internal override.
	if re.MatchString("https://github.com/chainsaw-releases/chainsaw/.github/workflows/release.yml@refs/tags/v1") {
		t.Errorf("override regexp unexpectedly matched the canonical bot identity")
	}
}

// TestDefaultIntelSignerOIDCIssuer_Pinned guards against a silent
// broadening of the trusted OIDC issuer — a refactor that changes it
// should fail a test, not weaken authenticity unnoticed.
func TestDefaultIntelSignerOIDCIssuer_Pinned(t *testing.T) {
	if DefaultIntelSignerOIDCIssuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("DefaultIntelSignerOIDCIssuer changed to %q; verify trust-root assumptions", DefaultIntelSignerOIDCIssuer)
	}
}
