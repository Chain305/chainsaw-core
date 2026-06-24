package intelligence

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/blake2b"
)

func TestChecksumProvider_VerifiesMatchingDeclaredHash(t *testing.T) {
	p := newChecksumProvider()
	if !p.Supports("npm") {
		t.Fatalf("npm should be supported")
	}
	if !p.NeedsArtifact() {
		t.Fatalf("checksum provider must NeedArtifact")
	}

	payload := []byte("hello-world")
	sum := sha256.Sum256(payload)
	declared := hex.EncodeToString(sum[:])

	req := Request{
		Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{
			Bytes:  payload,
			SHA256: declared,
		},
	}
	partial, err := p.Run(context.Background(), req, &Report{})
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Artifact == nil {
		t.Fatalf("expected Artifact section")
	}
	if partial.Artifact.Digests.Actual != declared {
		t.Fatalf("Actual: got %q, want %q", partial.Artifact.Digests.Actual, declared)
	}
	if partial.Artifact.Digests.Declared != declared {
		t.Fatalf("Declared: got %q, want %q", partial.Artifact.Digests.Declared, declared)
	}
	if !partial.Artifact.Digests.Verified {
		t.Fatalf("Verified must be true on matching hashes")
	}
	if len(partial.Warnings) != 0 {
		t.Fatalf("expected no warnings, got %+v", partial.Warnings)
	}
}

func TestChecksumProvider_MismatchEmitsWarning(t *testing.T) {
	p := newChecksumProvider()
	payload := []byte("hello-world")

	req := Request{
		Key: Key{Ecosystem: "pypi", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{
			Bytes:  payload,
			SHA256: "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		},
	}
	partial, err := p.Run(context.Background(), req, &Report{})
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Artifact == nil {
		t.Fatalf("expected Artifact section")
	}
	if partial.Artifact.Digests.Verified {
		t.Fatalf("Verified must be false on mismatch")
	}
	if len(partial.Warnings) != 1 {
		t.Fatalf("expected exactly one warning, got %d", len(partial.Warnings))
	}
	if partial.Warnings[0].Code != WarnChecksumMismatch {
		t.Fatalf("warning code: got %q, want %q", partial.Warnings[0].Code, WarnChecksumMismatch)
	}
}

// Switched to rubygems now that swift has its own runSwift early-return
// path (which returns an empty PartialReport when no declared digest is
// available — making rubygems the appropriate placeholder for "supported
// ecosystem with no declared hash on the handle").
func TestChecksumProvider_NoDeclaredHashIsNotAWarning(t *testing.T) {
	p := newChecksumProvider()
	payload := []byte("no-sidecar-ecosystem")

	req := Request{
		Key: Key{Ecosystem: "rubygems", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{
			Bytes: payload,
		},
	}
	partial, err := p.Run(context.Background(), req, &Report{})
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Artifact == nil {
		t.Fatalf("expected Artifact section")
	}
	if partial.Artifact.Digests.Actual == "" {
		t.Fatalf("Actual must be populated even without declared hash")
	}
	if partial.Artifact.Digests.Declared != "" {
		t.Fatalf("Declared should be empty, got %q", partial.Artifact.Digests.Declared)
	}
	if partial.Artifact.Digests.Verified {
		t.Fatalf("Verified must be false when no declared hash is available")
	}
	if len(partial.Warnings) != 0 {
		t.Fatalf("no warnings expected, got %+v", partial.Warnings)
	}
}

func TestChecksumProvider_HashesFromFilePath(t *testing.T) {
	p := newChecksumProvider()

	payload := []byte("from-disk-payload")
	sum := sha256.Sum256(payload)
	declared := hex.EncodeToString(sum[:])

	dir := t.TempDir()
	path := filepath.Join(dir, "artifact.bin")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write tmp: %v", err)
	}

	req := Request{
		Key: Key{Ecosystem: "maven", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{
			Path:   path,
			SHA256: declared,
		},
	}
	partial, err := p.Run(context.Background(), req, &Report{})
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Artifact == nil || partial.Artifact.Digests.Actual != declared {
		t.Fatalf("Actual digest mismatch: %+v", partial.Artifact)
	}
	if !partial.Artifact.Digests.Verified {
		t.Fatalf("Verified must be true on matching file-based hash")
	}
}

func TestChecksumProvider_UnsupportedEcosystem(t *testing.T) {
	p := newChecksumProvider()
	if p.Supports("docker") {
		t.Fatalf("docker should NOT be supported by checksum provider (OCI pipeline handles it)")
	}
	if p.Supports("nonsense") {
		t.Fatalf("nonsense ecosystem must be unsupported")
	}
}

func TestChecksumProvider_PrefersDeclaredFromPriorReport(t *testing.T) {
	p := newChecksumProvider()
	payload := []byte("the-bytes")
	sum := sha256.Sum256(payload)
	declared := hex.EncodeToString(sum[:])

	// Handle carries no declared hash; prior Report has one already
	// stashed by the registry-metadata provider (simulated here).
	prior := &Report{Artifact: ArtifactSection{Digests: ArtifactDigest{Declared: "SHA256:" + declared}}}

	req := Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}
	partial, err := p.Run(context.Background(), req, prior)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if !partial.Artifact.Digests.Verified {
		t.Fatalf("Verified should propagate from prior Report declared hash")
	}
	if partial.Artifact.Digests.Declared != declared {
		t.Fatalf("Declared normalised: got %q want %q", partial.Artifact.Digests.Declared, declared)
	}
}

// Composer ships both a SHA-1 dist.shasum and (newer packages) a
// SHA-256 sidecar via Digests.Integrity. pickDeclared must select the
// stronger SHA-256 even when the SHA-1 is also present on the prior
// report.
func TestChecksumProvider_PreferStrongestComposerSidecar(t *testing.T) {
	p := newChecksumProvider()
	payload := []byte("composer-payload")
	sum256 := sha256.Sum256(payload)
	sha256Hex := hex.EncodeToString(sum256[:])
	sum1 := sha1.Sum(payload)
	sha1Hex := hex.EncodeToString(sum1[:])

	// SRI integrity carries SHA-256; typed SHA-1 is also populated.
	integ := "sha256-" + base64.StdEncoding.EncodeToString(sum256[:])
	prior := &Report{
		Artifact: ArtifactSection{
			Digests: ArtifactDigest{
				Integrity: integ,
				SHA1:      sha1Hex,
			},
		},
	}

	req := Request{
		Key:      Key{Ecosystem: "composer", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}
	partial, err := p.Run(context.Background(), req, prior)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if !partial.Artifact.Digests.Verified {
		t.Fatalf("Verified should be true: SHA-256 sidecar must win over SHA-1")
	}
	if partial.Artifact.Digests.Declared != sha256Hex {
		t.Fatalf("Declared: got %q, want SHA-256 %q", partial.Artifact.Digests.Declared, sha256Hex)
	}
	if partial.Artifact.Digests.Actual != sha256Hex {
		t.Fatalf("Actual should reflect verified algo (SHA-256), got %q", partial.Artifact.Digests.Actual)
	}
}

func TestParseSRI_Single(t *testing.T) {
	payload := []byte("hello")
	sum := sha256.Sum256(payload)
	sri := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	algo, hexHash, ok := parseSRI(sri)
	if !ok {
		t.Fatalf("parseSRI(%q) ok=false", sri)
	}
	if algo != algoSHA256 {
		t.Fatalf("algo: got %v, want SHA256", algo)
	}
	if hexHash != hex.EncodeToString(sum[:]) {
		t.Fatalf("hex: got %q, want %q", hexHash, hex.EncodeToString(sum[:]))
	}
}

func TestParseSRI_MultiAlgoPicksStrongest(t *testing.T) {
	payload := []byte("hello")
	sum256 := sha256.Sum256(payload)
	sum512 := sha512.Sum512(payload)

	// SHA-256 first, SHA-512 second — strongest must win regardless of
	// listing order.
	sri := "sha256-" + base64.StdEncoding.EncodeToString(sum256[:]) +
		" sha512-" + base64.StdEncoding.EncodeToString(sum512[:])
	algo, hexHash, ok := parseSRI(sri)
	if !ok {
		t.Fatalf("parseSRI(%q) ok=false", sri)
	}
	if algo != algoSHA512 {
		t.Fatalf("algo: got %v, want SHA512", algo)
	}
	if hexHash != hex.EncodeToString(sum512[:]) {
		t.Fatalf("hex: got %q, want %q", hexHash, hex.EncodeToString(sum512[:]))
	}
}

func TestParseSRI_GarbageRejected(t *testing.T) {
	for _, s := range []string{
		"",
		"not-an-sri",
		"sha256",
		"sha256-",
		"-payload",
		"sha999-Zm9v",
		"sha256-!!!notbase64!!!",
	} {
		if _, _, ok := parseSRI(s); ok {
			t.Fatalf("parseSRI(%q) accepted garbage", s)
		}
	}
}

func TestChecksumProvider_DispatchMD5(t *testing.T) {
	p := newChecksumProvider()
	payload := []byte("legacy-pypi-bytes")
	sum := md5.Sum(payload)
	hexHash := hex.EncodeToString(sum[:])

	prior := &Report{
		Artifact: ArtifactSection{
			Digests: ArtifactDigest{MD5: hexHash},
		},
	}
	req := Request{
		Key:      Key{Ecosystem: "pypi", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}
	partial, err := p.Run(context.Background(), req, prior)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if !partial.Artifact.Digests.Verified {
		t.Fatalf("MD5 dispatch failed to verify")
	}
	if partial.Artifact.Digests.MD5 != hexHash {
		t.Fatalf("MD5: got %q want %q", partial.Artifact.Digests.MD5, hexHash)
	}
	// SHA-256 must still be populated for downstream cache keys.
	sha256Want := sha256.Sum256(payload)
	if partial.Artifact.Digests.SHA256 != hex.EncodeToString(sha256Want[:]) {
		t.Fatalf("SHA-256 must always be populated even when verified algo is MD5")
	}
}

func TestChecksumProvider_DispatchSHA1(t *testing.T) {
	p := newChecksumProvider()
	payload := []byte("rubygems-shasum-bytes")
	sum := sha1.Sum(payload)
	hexHash := hex.EncodeToString(sum[:])

	prior := &Report{
		Artifact: ArtifactSection{
			Digests: ArtifactDigest{SHA1: hexHash},
		},
	}
	req := Request{
		Key:      Key{Ecosystem: "rubygems", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}
	partial, err := p.Run(context.Background(), req, prior)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if !partial.Artifact.Digests.Verified {
		t.Fatalf("SHA-1 dispatch failed to verify")
	}
	if partial.Artifact.Digests.SHA1 != hexHash {
		t.Fatalf("SHA-1: got %q want %q", partial.Artifact.Digests.SHA1, hexHash)
	}
}

func TestChecksumProvider_DispatchSHA512(t *testing.T) {
	p := newChecksumProvider()
	payload := []byte("npm-sri-sha512-bytes")
	sum := sha512.Sum512(payload)
	sri := "sha512-" + base64.StdEncoding.EncodeToString(sum[:])

	prior := &Report{
		Artifact: ArtifactSection{
			Digests: ArtifactDigest{Integrity: sri},
		},
	}
	req := Request{
		Key:      Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}
	partial, err := p.Run(context.Background(), req, prior)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if !partial.Artifact.Digests.Verified {
		t.Fatalf("SHA-512 dispatch failed to verify")
	}
	if partial.Artifact.Digests.SHA512 != hex.EncodeToString(sum[:]) {
		t.Fatalf("SHA-512: got %q want %q", partial.Artifact.Digests.SHA512, hex.EncodeToString(sum[:]))
	}
}

func TestChecksumProvider_DispatchBlake2b(t *testing.T) {
	p := newChecksumProvider()
	payload := []byte("blake2b-bytes")
	h, err := blake2b.New256(nil)
	if err != nil {
		t.Fatalf("blake2b.New256: %v", err)
	}
	h.Write(payload)
	hexHash := hex.EncodeToString(h.Sum(nil))

	prior := &Report{
		Artifact: ArtifactSection{
			Digests: ArtifactDigest{Blake2b256: hexHash},
		},
	}
	req := Request{
		Key:      Key{Ecosystem: "pypi", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}
	partial, err := p.Run(context.Background(), req, prior)
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if !partial.Artifact.Digests.Verified {
		t.Fatalf("Blake2b-256 dispatch failed to verify")
	}
	if partial.Artifact.Digests.Blake2b256 != hexHash {
		t.Fatalf("Blake2b-256: got %q want %q", partial.Artifact.Digests.Blake2b256, hexHash)
	}
}

func TestChecksumProvider_SwiftHappyPath(t *testing.T) {
	p := newChecksumProvider()
	payload := []byte("swift-package-payload")
	sum := sha256.Sum256(payload)
	declared := hex.EncodeToString(sum[:])

	req := Request{
		Key: Key{Ecosystem: "swift", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{
			Bytes:  payload,
			SHA256: "sha-256=" + declared,
		},
	}
	partial, err := p.Run(context.Background(), req, &Report{})
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Artifact == nil {
		t.Fatalf("expected Artifact section on swift happy path")
	}
	if !partial.Artifact.Digests.Verified {
		t.Fatalf("swift: Verified must be true on matching Digest header")
	}
	if partial.Artifact.Digests.Declared != declared {
		t.Fatalf("swift: Declared got %q want %q", partial.Artifact.Digests.Declared, declared)
	}
	if len(partial.Warnings) != 0 {
		t.Fatalf("swift happy path: no warnings expected, got %+v", partial.Warnings)
	}
}

func TestChecksumProvider_SwiftMissingDigestIsQuiet(t *testing.T) {
	p := newChecksumProvider()
	payload := []byte("swift-without-header")
	req := Request{
		Key:      Key{Ecosystem: "swift", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: payload},
	}
	partial, err := p.Run(context.Background(), req, &Report{})
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	// Swift with no declared digest is graceful: empty PartialReport,
	// no warnings, no Artifact section.
	if partial.Artifact != nil {
		t.Fatalf("swift no-digest: expected nil Artifact section, got %+v", partial.Artifact)
	}
	if len(partial.Warnings) != 0 {
		t.Fatalf("swift no-digest: expected no warnings, got %+v", partial.Warnings)
	}
}

func TestChecksumProvider_SwiftMismatchEmitsWarning(t *testing.T) {
	p := newChecksumProvider()
	payload := []byte("swift-mismatch-payload")
	req := Request{
		Key: Key{Ecosystem: "swift", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{
			Bytes:  payload,
			SHA256: "sha-256=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
		},
	}
	partial, err := p.Run(context.Background(), req, &Report{})
	if err != nil {
		t.Fatalf("Run err: %v", err)
	}
	if partial.Artifact == nil {
		t.Fatalf("swift mismatch: expected Artifact section")
	}
	if partial.Artifact.Digests.Verified {
		t.Fatalf("swift mismatch: Verified must be false")
	}
	if len(partial.Warnings) != 1 {
		t.Fatalf("swift mismatch: expected exactly one warning, got %d", len(partial.Warnings))
	}
	if partial.Warnings[0].Code != WarnChecksumMismatch {
		t.Fatalf("swift mismatch: warning code: got %q want %q", partial.Warnings[0].Code, WarnChecksumMismatch)
	}
}
