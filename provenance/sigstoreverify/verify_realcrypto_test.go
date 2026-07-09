package sigstoreverify_test

// These tests exercise the REAL sigstore-go cryptographic Verify() pipeline
// OFFLINE. They pin a snapshot trusted root and feed a genuinely-signed
// Sigstore bundle (both copied verbatim from the sigstore-go module's own
// Apache-2.0 test corpus — see testdata/PROVENANCE.md). Unlike the stub-seam
// tests, nothing here fakes the verdict: a good bundle must produce a real
// verification success, and a mutated bundle / wrong artifact digest must be
// rejected by the actual Fulcio-cert + Rekor-log + signature checks.
//
// The bundle is a message-signature bundle with an integrated Rekor tlog
// entry. That integrated log timestamp counts as an observer timestamp, so it
// satisfies our Verifier's WithObserverTimestamps(1) + WithTransparencyLog(1)
// policy. Verification is anchored to the log timestamp (not wall-clock), so
// the archived bundle stays verifiable offline indefinitely against the pinned
// root.

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
	"github.com/sigstore/sigstore-go/pkg/root"
)

// artifactSHA256Hex is the SHA-256 of the artifact the othername bundle
// attests to. Taken from the upstream sigstore-go verify test
// (TestEntityWithOthernameSan).
const artifactSHA256Hex = "bc103b4a84971ef6459b294a2b98568a2bfb72cded09d4acd1e16366a401f95b"

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("read testdata %s: %v", name, err)
	}
	return b
}

func pinnedVerifier(t *testing.T) *sigstoreverify.Verifier {
	t.Helper()
	trJSON := readTestdata(t, "scaffolding-trusted-root.json")
	tr, err := root.NewTrustedRootFromJSON(trJSON)
	if err != nil {
		t.Fatalf("parse pinned trusted root: %v", err)
	}
	return sigstoreverify.NewVerifierFromTrustedRootForTesting(t, tr)
}

func artifactDigest(t *testing.T) []byte {
	t.Helper()
	d, err := hex.DecodeString(artifactSHA256Hex)
	if err != nil {
		t.Fatalf("decode artifact digest: %v", err)
	}
	if len(d) != 32 {
		t.Fatalf("artifact digest: want 32 bytes, got %d", len(d))
	}
	return d
}

// TestRealVerifyGoodBundleSucceeds proves the REAL crypto path returns success
// for a genuinely-signed bundle + pinned trusted root + correct artifact
// digest. This is the coverage the stub-seam tests could not provide.
func TestRealVerifyGoodBundleSucceeds(t *testing.T) {
	v := pinnedVerifier(t)
	bundleJSON := readTestdata(t, "othername.sigstore.json")

	id, err := v.Verify(bundleJSON, artifactDigest(t))
	if err != nil {
		t.Fatalf("real Verify of a good bundle failed: %v", err)
	}
	if id == nil {
		t.Fatal("real Verify returned nil identity on success")
	}
	// The othername bundle's Fulcio cert was minted by the scaffolding OIDC
	// issuer. Assert we extracted a real identity from the verified cert,
	// which only happens if the cert chain actually verified.
	if id.Issuer != "http://oidc.local:8080" {
		t.Fatalf("verified identity issuer: want http://oidc.local:8080, got %q", id.Issuer)
	}
}

// TestRealVerifyWrongDigestRejected proves the crypto path rejects a bundle
// whose signed artifact digest does not match the caller-supplied digest.
// The signature itself is valid; the mismatch is a real policy failure.
func TestRealVerifyWrongDigestRejected(t *testing.T) {
	v := pinnedVerifier(t)
	bundleJSON := readTestdata(t, "othername.sigstore.json")

	wrong := artifactDigest(t)
	wrong[0] ^= 0xFF // flip one byte → no longer the attested artifact

	if _, err := v.Verify(bundleJSON, wrong); err == nil {
		t.Fatal("real Verify accepted a bundle for the WRONG artifact digest")
	}
}

// TestRealVerifyTamperedBundleRejected proves the crypto path rejects a bundle
// whose bytes were mutated after signing. We corrupt the message-signature
// bytes so the signature no longer validates against the Fulcio cert.
func TestRealVerifyTamperedBundleRejected(t *testing.T) {
	v := pinnedVerifier(t)
	bundleJSON := readTestdata(t, "othername.sigstore.json")

	// Flip the last base64 char of the messageSignature.signature value.
	// This yields a structurally-valid bundle whose signature is wrong, so
	// rejection comes from the crypto check, not a parse error.
	tampered := tamperMessageSignature(t, bundleJSON)

	if _, err := v.Verify(tampered, artifactDigest(t)); err == nil {
		t.Fatal("real Verify accepted a bundle with a tampered signature")
	}
}

// TestRealVerifyWrongTrustedRootRejected proves that a genuinely-signed bundle
// does NOT verify against a DIFFERENT (mismatched) trusted root — the
// public-good production root cannot vouch for a scaffolding-issued cert.
func TestRealVerifyWrongTrustedRootRejected(t *testing.T) {
	// Pin the public-good root instead of the scaffolding root the bundle was
	// signed under.
	trJSON := readTestdata(t, "public-good-trusted-root.json")
	tr, err := root.NewTrustedRootFromJSON(trJSON)
	if err != nil {
		t.Fatalf("parse public-good trusted root: %v", err)
	}
	v := sigstoreverify.NewVerifierFromTrustedRootForTesting(t, tr)
	bundleJSON := readTestdata(t, "othername.sigstore.json")

	if _, err := v.Verify(bundleJSON, artifactDigest(t)); err == nil {
		t.Fatal("real Verify accepted a scaffolding bundle under the public-good root")
	}
}

// TestRealVerifyRejectsShortDigest confirms the length guard fires before any
// crypto work.
func TestRealVerifyRejectsShortDigest(t *testing.T) {
	v := pinnedVerifier(t)
	bundleJSON := readTestdata(t, "othername.sigstore.json")
	if _, err := v.Verify(bundleJSON, []byte{0x01, 0x02}); err == nil {
		t.Fatal("Verify accepted a non-32-byte artifact digest")
	}
}

// --- DSSE in-toto path (the shape huggingfaceChecker.Check consumes) -------
//
// The tests above exercise the real crypto over a MESSAGE-SIGNATURE bundle.
// But the production model-signing path (provenance.huggingfaceChecker.Check)
// consumes a DSSE in-toto bundle: it calls BundleSubjects to read the signed
// subject list, then Verify() to check the DSSE envelope signature + Fulcio
// cert + Rekor log. The tests below drive the REAL crypto through that DSSE
// envelope path against genuinely-signed bytes so a DSSE-envelope-handling
// regression cannot hide behind the message-signature coverage.
//
// pgVerifier pins the public-good production root, which is the trust root the
// dsse.sigstore.json corpus bundle was actually signed under (its Rekor log id
// matches public-good, not scaffolding).
func pgVerifier(t *testing.T) *sigstoreverify.Verifier {
	t.Helper()
	trJSON := readTestdata(t, "public-good-trusted-root.json")
	tr, err := root.NewTrustedRootFromJSON(trJSON)
	if err != nil {
		t.Fatalf("parse public-good trusted root: %v", err)
	}
	return sigstoreverify.NewVerifierFromTrustedRootForTesting(t, tr)
}

// TestRealDSSEBundleSubjectsParsesGenuineSignedBundle proves the exact parse
// seam Check() uses (BundleSubjects) reads the in-toto subject list off a
// GENUINELY-signed DSSE bundle — not just the synthetic unsigned fixtures the
// stubbed Check() tests use.
func TestRealDSSEBundleSubjectsParsesGenuineSignedBundle(t *testing.T) {
	bundleJSON := readTestdata(t, "dsse.sigstore.json")
	subs, err := sigstoreverify.BundleSubjects(bundleJSON)
	if err != nil {
		t.Fatalf("BundleSubjects on a genuine DSSE bundle: %v", err)
	}
	if len(subs) != 1 || subs[0].Name != "slsa-provenance-0.0.7.tgz" {
		t.Fatalf("want the signed subject slsa-provenance-0.0.7.tgz, got %+v", subs)
	}
	// This corpus subject is bound by sha512, so the sha256 field is empty —
	// this is exactly why the sha256-anchor SUCCESS path below cannot be proven
	// with the available offline fixtures (documented boundary).
	if len(subs[0].SHA256) != 0 {
		t.Fatalf("expected no sha256 digest on a sha512-bound subject, got %x", subs[0].SHA256)
	}
}

// TestRealDSSEVerifyRunsCryptoThenDigestMatch proves the REAL DSSE-envelope
// crypto pipeline (Fulcio cert chain + Rekor tlog inclusion + DSSE signature)
// executes end-to-end against genuinely-signed DSSE bytes. Our Verify() pins
// the artifact-digest policy to sha256; the corpus subject is sha512-bound, so
// verification fails at the FINAL digest-match step — a failure only reachable
// AFTER every crypto check passed. A stub or a broken DSSE-envelope decoder
// could not produce this specific, late failure.
func TestRealDSSEVerifyRunsCryptoThenDigestMatch(t *testing.T) {
	v := pgVerifier(t)
	bundleJSON := readTestdata(t, "dsse.sigstore.json")

	// Any 32-byte value: the point is that the crypto runs and we reach (and
	// fail) the digest-match, not the digest value itself.
	someSHA256 := sha256.Sum256([]byte("unrelated-artifact"))
	_, err := v.Verify(bundleJSON, someSHA256[:])
	if err == nil {
		t.Fatal("expected a digest-mismatch after crypto; got success")
	}
	// The error must be the artifact-digest policy failure — proof the crypto
	// (cert/tlog/signature) validated first. If a crypto step had failed we'd
	// see a cert/log/signature error instead.
	if !strings.Contains(err.Error(), "does not match digests in statement") {
		t.Fatalf("want a post-crypto digest-mismatch on a genuine DSSE bundle, got: %v", err)
	}
}

// TestRealDSSETamperedSignatureRejected proves the DSSE signature itself is
// really checked: flipping one base64 char of the DSSE envelope signature makes
// verification fail in the CRYPTO stage (a transparency-log / signature error),
// distinct from the post-crypto digest-mismatch above. This is the tamper
// coverage for the DSSE shape Check() consumes.
func TestRealDSSETamperedSignatureRejected(t *testing.T) {
	v := pgVerifier(t)
	bundleJSON := readTestdata(t, "dsse.sigstore.json")

	tampered := tamperDSSESignature(t, bundleJSON)
	someSHA256 := sha256.Sum256([]byte("unrelated-artifact"))
	_, err := v.Verify(tampered, someSHA256[:])
	if err == nil {
		t.Fatal("real Verify accepted a DSSE bundle with a tampered envelope signature")
	}
	// A tampered signature must fail in the crypto stage, NOT at the (later)
	// digest-match — that ordering is what proves the signature was actually
	// checked rather than the verdict faked.
	if strings.Contains(err.Error(), "does not match digests in statement") {
		t.Fatalf("tampered DSSE sig reached the digest-match step; crypto was not enforced: %v", err)
	}
}

// tamperDSSESignature returns a copy of bundleJSON with one base64 char of the
// DSSE envelope signature ("sig") flipped — invalidating the signature while
// keeping the bundle parseable so rejection comes from the crypto check, not a
// parse error.
func tamperDSSESignature(t *testing.T, bundleJSON []byte) []byte {
	t.Helper()
	const key = `"sig": "`
	idx := indexOfBytes(bundleJSON, []byte(key))
	if idx < 0 {
		t.Fatalf("could not locate DSSE signature in bundle")
	}
	valStart := idx + len(key)
	out := make([]byte, len(bundleJSON))
	copy(out, bundleJSON)
	if out[valStart] == 'A' {
		out[valStart] = 'B'
	} else {
		out[valStart] = 'A'
	}
	return out
}

func indexOfBytes(haystack, needle []byte) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// tamperMessageSignature returns a copy of bundleJSON with a single character
// of the messageSignature.signature base64 value flipped, invalidating the
// signature while keeping the bundle parseable.
func tamperMessageSignature(t *testing.T, bundleJSON []byte) []byte {
	t.Helper()
	// Locate the "signature" value inside the "messageSignature" object and
	// mutate a byte of its base64 content. We operate on the raw bytes to
	// avoid re-serialising (which could drop fields the parser needs).
	// The testdata is pretty-printed (a space follows the colon). Match that
	// exact key; the messageSignature object is the last "signature" key.
	const key = `"signature": "`
	idx := lastIndex(bundleJSON, []byte(key))
	if idx < 0 {
		t.Fatalf("could not locate messageSignature signature in bundle")
	}
	valStart := idx + len(key)
	// Flip the first base64 char of the value. Map it to a different valid
	// base64 char so the value stays decodable but the bytes differ.
	c := bundleJSON[valStart]
	repl := byte('A')
	if c == 'A' {
		repl = 'B'
	}
	out := make([]byte, len(bundleJSON))
	copy(out, bundleJSON)
	out[valStart] = repl
	return out
}

func lastIndex(haystack, needle []byte) int {
	for i := len(haystack) - len(needle); i >= 0; i-- {
		match := true
		for j := 0; j < len(needle); j++ {
			if haystack[i+j] != needle[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
