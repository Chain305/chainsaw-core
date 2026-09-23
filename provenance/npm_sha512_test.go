package provenance

// npm in-toto subjects bind sha512 and nothing else. This package hardcoded
// "sha256" into the verification policy, so **0 of 1,857 npm sigstore
// verifications had ever succeeded** in production (measured 2026-09-24):
// 1,852 StatusFailed with "provided artifact digests does not match digests in
// statement", across 439 distinct publishers including radix-ui/primitives.
// A 100% failure rate against legitimate publishers was us, not them.

import (
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

// The digest npm actually binds comes straight from dist.integrity, so the
// common path downloads no tarball at all. Verified against the live registry:
// sigstore@3.0.0 and @sigstore/bundle@3.0.0 both have
// dist.integrity sha512 == attestation subject sha512.
func TestNpmDigestComesFromIntegrityWithoutFetchingTheTarball(t *testing.T) {
	want := sha512.Sum512([]byte("the tarball bytes"))
	integrity := "sha512-" + base64.StdEncoding.EncodeToString(want[:])

	var tarballHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tarball" {
			tarballHits++
			_, _ = w.Write([]byte("the tarball bytes"))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"dist": map[string]any{"integrity": integrity, "tarball": srvURL(r) + "/tarball"},
		})
	}))
	defer srv.Close()

	base := srv.URL
	c := &npmChecker{client: srv.Client(), registryFor: func() string { return base }}
	got, err := c.tarballSHA512(t.Context(), "pkg", "1.0.0")
	if err != nil {
		t.Fatalf("tarballSHA512: %v", err)
	}
	if string(got) != string(want[:]) {
		t.Errorf("digest mismatch: got %x, want %x", got, want[:])
	}
	if len(got) != sha512.Size {
		t.Errorf("digest is %d bytes, want %d — a sha256 here can never match an npm subject",
			len(got), sha512.Size)
	}
	if tarballHits != 0 {
		t.Errorf("the tarball was downloaded %d times; dist.integrity already carries the sha512, "+
			"and every npm coordinate paying for a download is the cost this avoids", tarballHits)
	}
}

// Fallback: metadata without a usable sha512 integrity must still verify, by
// hashing the bytes — a malformed integrity string is not a reason to fail a
// verification we can still do.
func TestNpmDigestFallsBackToHashingTheTarball(t *testing.T) {
	body := []byte("the tarball bytes")
	want := sha512.Sum512(body)

	var tarballHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/tarball" {
			tarballHits++
			_, _ = w.Write(body)
			return
		}
		// sha1 integrity, the shape older packages carry.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"dist": map[string]any{"integrity": "sha1-abcdef", "tarball": srvURL(r) + "/tarball"},
		})
	}))
	defer srv.Close()

	base := srv.URL
	c := &npmChecker{client: srv.Client(), registryFor: func() string { return base }}
	got, err := c.tarballSHA512(t.Context(), "pkg", "1.0.0")
	if err != nil {
		t.Fatalf("tarballSHA512: %v", err)
	}
	if string(got) != string(want[:]) {
		t.Errorf("fallback digest mismatch: got %x, want %x", got, want[:])
	}
	if tarballHits != 1 {
		t.Errorf("tarball fetched %d times, want 1", tarballHits)
	}
}

// The verifier must accept sha512 and reject a digest whose length does not
// match its named algorithm — passing 32 bytes as "sha512" would sail past a
// length check written only for sha256.
func TestVerifyDigestValidatesLengthPerAlgorithm(t *testing.T) {
	v := &sigstoreverify.Verifier{}
	if _, err := v.VerifyDigest(nil, sigstoreverify.DigestSHA512, make([]byte, 32)); err == nil {
		t.Error("a 32-byte digest was accepted as sha512")
	}
	if _, err := v.VerifyDigest(nil, sigstoreverify.DigestSHA256, make([]byte, 64)); err == nil {
		t.Error("a 64-byte digest was accepted as sha256")
	}
	if _, err := v.VerifyDigest(nil, "md5", make([]byte, 16)); err == nil {
		t.Error("an unsupported algorithm was accepted")
	}
}

func srvURL(r *http.Request) string { return "http://" + r.Host }
