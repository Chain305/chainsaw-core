package provenance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

// TestOCICheckFetchesFullReferrerChain sets up a mock registry that responds
// to HEAD manifest, Referrers, referrer-manifest GET, and blob GET. The
// bundle it returns is deliberately malformed so the final sigstore verify
// fails — under the A2 contract a located-but-unverifiable bundle yields
// StatusUnverified, not StatusFailed. We still assert every step of the
// chain was walked, just with the correct post-A2 terminal status.
func TestOCICheckFetchesFullReferrerChain(t *testing.T) {
	var headCalls, referrersCalls, manifestCalls, blobCalls atomic.Int32

	// Canonical image manifest bytes — hashed so the "digest" is a real
	// sha256 of something (not that we validate it on HEAD).
	imageManifest := []byte(`{"schemaVersion":2}`)
	imageDigest := "sha256:" + hex.EncodeToString(sha256.New().Sum(imageManifest)[:0])
	imageDigest = "sha256:" + sha256Hex(imageManifest)

	// Referrer manifest points to the bundle blob.
	referrerDigest := "sha256:" + sha256Hex([]byte("referrer-manifest-bytes"))
	blobDigest := "sha256:" + sha256Hex([]byte("bundle-blob-bytes"))
	referrerManifest := fmt.Sprintf(`{"layers":[{"digest":%q}]}`, blobDigest)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && strings.HasPrefix(r.URL.Path, "/v2/acme/app/manifests/"):
			headCalls.Add(1)
			w.Header().Set("Docker-Content-Digest", imageDigest)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/acme/app/referrers/"):
			referrersCalls.Add(1)
			fmt.Fprintf(w, `{"manifests":[{"digest":%q,"artifactType":%q}]}`, referrerDigest, sigstoreArtifactType)
		case r.Method == http.MethodGet && r.URL.Path == "/v2/acme/app/manifests/"+referrerDigest:
			manifestCalls.Add(1)
			_, _ = w.Write([]byte(referrerManifest))
		case r.Method == http.MethodGet && r.URL.Path == "/v2/acme/app/blobs/"+blobDigest:
			blobCalls.Add(1)
			// Return a malformed bundle — we only care that the chain was walked.
			_, _ = w.Write([]byte("not-a-real-sigstore-bundle"))
		default:
			t.Logf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	registry := stripScheme(srv.URL) // "127.0.0.1:PORT"

	c := newOCIChecker(srv.Client(), nil)
	c.scheme = "http"

	got := c.Check(context.Background(), registry+"/acme/app", "latest")

	// Each step must have been exercised at least once.
	if headCalls.Load() != 1 || referrersCalls.Load() != 1 || manifestCalls.Load() != 1 || blobCalls.Load() != 1 {
		t.Errorf("want one call per step: head=%d referrers=%d manifest=%d blob=%d",
			headCalls.Load(), referrersCalls.Load(), manifestCalls.Load(), blobCalls.Load())
	}

	// The bundle was located but doesn't pass the crypto check; per the
	// A2 contract that's StatusUnverified, not StatusFailed. "Found but
	// didn't verify" and "couldn't fetch at all" are meaningfully different
	// signals for operators triaging a provenance policy violation.
	if got.Status != StatusUnverified {
		t.Errorf("want StatusUnverified from sigstore verify on malformed bundle, got %+v", got)
	}
	if got.AttestationType != "sigstore" {
		t.Errorf("want AttestationType=sigstore, got %q", got.AttestationType)
	}
}

// TestOCICheckMissingReferrerChainIsStatusFailed — if the blob fetch 404s
// mid-chain (referrers promised a bundle but it's gone), we should report
// StatusFailed with a fetch error, not silently StatusUnverified.
func TestOCICheckBlob404IsStatusFailed(t *testing.T) {
	referrerDigest := "sha256:" + sha256Hex([]byte("referrer-manifest"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Docker-Content-Digest", "sha256:"+sha256Hex([]byte("image")))
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/referrers/"):
			fmt.Fprintf(w, `{"manifests":[{"digest":%q,"artifactType":%q}]}`, referrerDigest, sigstoreArtifactType)
		case strings.HasSuffix(r.URL.Path, "/manifests/"+referrerDigest):
			// Return a valid referrer manifest that points at a blob
			// that won't exist.
			_, _ = w.Write([]byte(`{"layers":[{"digest":"sha256:ffff"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newOCIChecker(srv.Client(), nil)
	c.scheme = "http"

	got := c.Check(context.Background(), stripScheme(srv.URL)+"/acme/app", "latest")
	if got.Status != StatusFailed {
		t.Errorf("blob 404 mid-chain: want StatusFailed, got %+v", got)
	}
	if !strings.Contains(got.Error, "fetch bundle") && !strings.Contains(got.Error, "blob") {
		t.Errorf("want error mentioning blob/bundle, got %q", got.Error)
	}
}

// TestResolveDigestFallsBackToGET — when the registry doesn't set
// Docker-Content-Digest on HEAD, we GET the manifest and hash its body.
func TestResolveDigestFallsBackToGET(t *testing.T) {
	manifestBytes := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
	wantDigest := "sha256:" + sha256Hex(manifestBytes)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodHead {
			// Return 200 but omit the header — simulates a CDN that
			// strips it.
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(manifestBytes)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	c := newOCIChecker(srv.Client(), nil)
	c.scheme = "http"
	got, err := c.resolveDigest(context.Background(), stripScheme(srv.URL), "acme/app", "latest")
	if err != nil {
		t.Fatalf("resolveDigest: %v", err)
	}
	if got != wantDigest {
		t.Errorf("want %q, got %q", wantDigest, got)
	}
}

// TestOCICheckAuthFailureIsStatusFailedNotMissing — regression for A3.
// When a registry returns a final 401 (either no challenge, or a challenge
// whose token endpoint refuses the scope) we must surface StatusFailed
// so operators can tell "auth misconfigured / credential missing" apart
// from "no attestation exists." Pre-A3 the anonymous request path
// collapsed both into StatusMissing, masking private-repo auth failures.
func TestOCICheckAuthFailureIsStatusFailedNotMissing(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// HEAD manifest returns a digest (so resolveDigest succeeds) ...
		if r.Method == http.MethodHead {
			w.Header().Set("Docker-Content-Digest", "sha256:"+sha256Hex([]byte("image")))
			w.WriteHeader(http.StatusOK)
			return
		}
		// ... but the referrers endpoint 401s with no recoverable Bearer
		// challenge (e.g. Basic-only, or Bearer pointing at an auth realm
		// that refuses our scope). The transport has nothing to retry
		// with, and the final status is 401 — NOT 404.
		if strings.Contains(r.URL.Path, "/referrers/") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newOCIChecker(srv.Client(), nil)
	c.scheme = "http"

	got := c.Check(context.Background(), stripScheme(srv.URL)+"/acme/app", "latest")
	if got.Status == StatusMissing {
		t.Fatalf("final 401 must not collapse to StatusMissing: %+v", got)
	}
	if got.Status != StatusFailed {
		t.Errorf("want StatusFailed for unrecoverable 401, got %+v", got)
	}
}

// mockSigstoreVerifier is injected into defaultSigstoreVerifier during A2
// tests to exercise the fetch-then-verify chain without building a real
// Sigstore bundle (which would require live TUF network I/O against the
// Sigstore trust root). Each call to Verify records (bundleJSON,
// artifactSHA256) so the test can assert the OCI code handed the right
// bytes to the verifier.
type mockSigstoreVerifier struct {
	// result is returned verbatim from Verify.
	result *sigstoreverify.Identity
	// err is returned verbatim from Verify.
	err error
	// calls captures every (bundleJSON, artifactSHA256) pair. The test
	// uses this to assert the OCI code passed the *image* digest (not the
	// bundle's own digest) and the actual bundle bytes.
	calls []mockVerifyCall
}

type mockVerifyCall struct {
	BundleJSON     []byte
	ArtifactSHA256 []byte
}

func (m *mockSigstoreVerifier) Verify(bundleJSON []byte, artifactSHA256 []byte) (*sigstoreverify.Identity, error) {
	// Copy inputs so later callers mutating their buffers don't race us.
	b := make([]byte, len(bundleJSON))
	copy(b, bundleJSON)
	d := make([]byte, len(artifactSHA256))
	copy(d, artifactSHA256)
	m.calls = append(m.calls, mockVerifyCall{BundleJSON: b, ArtifactSHA256: d})
	return m.result, m.err
}

// withMockVerifier installs m as the process-wide sigstoreVerifier loader
// for the duration of the test and restores the original on cleanup.
func withMockVerifier(t *testing.T, m *mockSigstoreVerifier) {
	t.Helper()
	prev := defaultSigstoreVerifier
	defaultSigstoreVerifier = func(context.Context) (sigstoreVerifier, error) {
		return m, nil
	}
	t.Cleanup(func() { defaultSigstoreVerifier = prev })
}

// TestOCICheckVerifiesSigstoreReferrer exercises the full A2 happy path:
// HEAD manifest -> GET referrers -> GET referrer manifest -> GET bundle blob
// -> call verifier with (bundle bytes, image digest bytes). The mock
// verifier returns a successful identity so we assert StatusVerified AND
// that the verifier was called with the IMAGE digest (not the referrer's
// own digest, which is a common implementation slip).
func TestOCICheckVerifiesSigstoreReferrer(t *testing.T) {
	imageManifestBytes := []byte(`{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}`)
	imageDigestHex := sha256Hex(imageManifestBytes)
	imageDigest := "sha256:" + imageDigestHex
	imageDigestRaw, err := hex.DecodeString(imageDigestHex)
	if err != nil {
		t.Fatalf("decode image digest: %v", err)
	}

	referrerDigest := "sha256:" + sha256Hex([]byte("referrer-manifest"))
	blobDigest := "sha256:" + sha256Hex([]byte("bundle-blob"))
	referrerManifest := fmt.Sprintf(`{"layers":[{"digest":%q}]}`, blobDigest)
	bundleBytes := []byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json"}`)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && strings.HasPrefix(r.URL.Path, "/v2/acme/app/manifests/"):
			w.Header().Set("Docker-Content-Digest", imageDigest)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v2/acme/app/referrers/"):
			fmt.Fprintf(w, `{"manifests":[{"digest":%q,"artifactType":%q}]}`, referrerDigest, sigstoreArtifactType)
		case r.Method == http.MethodGet && r.URL.Path == "/v2/acme/app/manifests/"+referrerDigest:
			_, _ = w.Write([]byte(referrerManifest))
		case r.Method == http.MethodGet && r.URL.Path == "/v2/acme/app/blobs/"+blobDigest:
			_, _ = w.Write(bundleBytes)
		default:
			t.Logf("unexpected %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	mock := &mockSigstoreVerifier{
		result: &sigstoreverify.Identity{
			SourceRepo: "https://github.com/acme/app",
			BuilderID:  "https://github.com/acme/app/.github/workflows/release.yml@refs/tags/v1",
			Issuer:     "https://token.actions.githubusercontent.com",
		},
	}
	withMockVerifier(t, mock)

	c := newOCIChecker(srv.Client(), nil)
	c.scheme = "http"
	got := c.Check(context.Background(), stripScheme(srv.URL)+"/acme/app", "latest")

	if got.Status != StatusVerified {
		t.Fatalf("want StatusVerified, got %+v", got)
	}
	if got.AttestationType != "sigstore" {
		t.Errorf("want AttestationType=sigstore, got %q", got.AttestationType)
	}
	if got.SourceRepo != "https://github.com/acme/app" {
		t.Errorf("want SourceRepo propagated from verifier identity, got %q", got.SourceRepo)
	}
	if got.BuilderID != mock.result.BuilderID {
		t.Errorf("want BuilderID propagated from verifier identity, got %q", got.BuilderID)
	}

	if len(mock.calls) != 1 {
		t.Fatalf("want verifier called exactly once, got %d calls", len(mock.calls))
	}
	call := mock.calls[0]
	if string(call.BundleJSON) != string(bundleBytes) {
		t.Errorf("want verifier called with exact bundle bytes from blob fetch\n got: %q\nwant: %q",
			call.BundleJSON, bundleBytes)
	}
	if string(call.ArtifactSHA256) != string(imageDigestRaw) {
		t.Errorf("verifier must receive the IMAGE digest (raw 32 bytes), not the referrer/bundle digest\n got: %x\nwant: %x",
			call.ArtifactSHA256, imageDigestRaw)
	}
}

// TestOCICheckUnverifiedBundleIsStatusUnverified pins the post-A2 contract
// for the "found but didn't verify" case: if a Sigstore bundle is located
// via the Referrers API but fails the crypto check, the result MUST be
// StatusUnverified — NOT StatusFailed. Operators use StatusFailed to detect
// transport/auth breakage; collapsing an unverified bundle into that bucket
// would hide real policy violations.
func TestOCICheckUnverifiedBundleIsStatusUnverified(t *testing.T) {
	referrerDigest := "sha256:" + sha256Hex([]byte("referrer"))
	blobDigest := "sha256:" + sha256Hex([]byte("blob"))
	referrerManifest := fmt.Sprintf(`{"layers":[{"digest":%q}]}`, blobDigest)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead:
			w.Header().Set("Docker-Content-Digest", "sha256:"+sha256Hex([]byte("image")))
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/referrers/"):
			fmt.Fprintf(w, `{"manifests":[{"digest":%q,"artifactType":%q}]}`, referrerDigest, sigstoreArtifactType)
		case strings.HasSuffix(r.URL.Path, "/manifests/"+referrerDigest):
			_, _ = w.Write([]byte(referrerManifest))
		case strings.HasSuffix(r.URL.Path, "/blobs/"+blobDigest):
			_, _ = w.Write([]byte(`{"irrelevant":"bundle"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	verifyErr := fmt.Errorf("certificate not trusted")
	withMockVerifier(t, &mockSigstoreVerifier{err: verifyErr})

	c := newOCIChecker(srv.Client(), nil)
	c.scheme = "http"
	got := c.Check(context.Background(), stripScheme(srv.URL)+"/acme/app", "latest")

	if got.Status != StatusUnverified {
		t.Fatalf("located-but-failed-crypto bundle must be StatusUnverified, got %+v", got)
	}
	if got.AttestationType != "sigstore" {
		t.Errorf("want AttestationType=sigstore, got %q", got.AttestationType)
	}
	if !strings.Contains(got.Error, "certificate not trusted") {
		t.Errorf("want verifier error propagated, got %q", got.Error)
	}
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func stripScheme(u string) string {
	// httptest.Server.URL is of the form "http://127.0.0.1:PORT"; we want
	// just "127.0.0.1:PORT" so splitOCIName recognizes it as a registry.
	parsed, err := url.Parse(u)
	if err != nil {
		return u
	}
	return parsed.Host
}
