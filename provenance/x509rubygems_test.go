package provenance

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

// testGem holds the byte payloads + cert/key used to assemble a
// synthetic .gem tar archive for tests.
type testGem struct {
	cert        *x509.Certificate
	certDER     []byte
	key         *rsa.PrivateKey
	metadataGz  []byte
	dataTarGz   []byte
	checksumsGz []byte
}

func newTestGem(t *testing.T) *testGem {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject: pkix.Name{
			CommonName: "gem-build@example.com",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509 create: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509 parse: %v", err)
	}
	return &testGem{
		cert:        cert,
		certDER:     der,
		key:         key,
		metadataGz:  gzBytes(t, []byte("---\nname: example\nversion: 1.0.0\n")),
		dataTarGz:   gzBytes(t, []byte("fake-tar-contents")),
		checksumsGz: gzBytes(t, []byte("checksums-yaml")),
	}
}

func gzBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write(b); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// signRSA produces a PKCS1v15 RSA signature over payload. hash selects
// the digest algorithm (SHA-256 or SHA-1).
func signRSA(t *testing.T, key *rsa.PrivateKey, payload []byte, hash crypto.Hash) []byte {
	t.Helper()
	var digest []byte
	switch hash {
	case crypto.SHA256:
		s := sha256.Sum256(payload)
		digest = s[:]
	case crypto.SHA1:
		s := sha1.Sum(payload)
		digest = s[:]
	default:
		t.Fatalf("unsupported hash %v", hash)
	}
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
	if err != nil {
		t.Fatalf("rsa sign: %v", err)
	}
	return sig
}

// buildGemTar assembles a tar archive whose entries match what a real
// .gem looks like. Pass nil for any entry to omit it.
func buildGemTar(t *testing.T, entries map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for name, body := range entries {
		if body == nil {
			continue
		}
		if err := tw.WriteHeader(&tar.Header{
			Name:     name,
			Mode:     0644,
			Size:     int64(len(body)),
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("tar header %s: %v", name, err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("tar write %s: %v", name, err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	return buf.Bytes()
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestVerifyGemSignature_HappyPath(t *testing.T) {
	g := newTestGem(t)
	gem := buildGemTar(t, map[string][]byte{
		"metadata.gz":           g.metadataGz,
		"metadata.gz.sig":       signRSA(t, g.key, g.metadataGz, crypto.SHA256),
		"data.tar.gz":           g.dataTarGz,
		"data.tar.gz.sig":       signRSA(t, g.key, g.dataTarGz, crypto.SHA256),
		"checksums.yaml.gz":     g.checksumsGz,
		"checksums.yaml.gz.sig": signRSA(t, g.key, g.checksumsGz, crypto.SHA256),
		"cert.pem":              certPEM(g.certDER),
	})

	res, err := VerifyGemSignature(context.Background(), gem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusVerified {
		t.Fatalf("Status=%q want verified; warnings=%v err=%q", res.Status, res.Warnings, res.Error)
	}
	if res.AttestationType != "x509-gemcert" {
		t.Errorf("AttestationType=%q want x509-gemcert", res.AttestationType)
	}
	if res.BundleFormat != "x509-detached" {
		t.Errorf("BundleFormat=%q want x509-detached", res.BundleFormat)
	}
	wantFP := sha256.Sum256(g.certDER)
	wantFPHex := hex.EncodeToString(wantFP[:])
	if res.SignerID != wantFPHex {
		t.Errorf("SignerID=%q want %q", res.SignerID, wantFPHex)
	}
	if res.BuilderID != "gem-build@example.com" {
		t.Errorf("BuilderID=%q want CN", res.BuilderID)
	}
	// Trust warning must always be present on success.
	found := false
	for _, w := range res.Warnings {
		if strings.Contains(w, "trust not validated") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected trust-not-validated warning; got %v", res.Warnings)
	}
}

func TestVerifyGemSignature_TamperedData(t *testing.T) {
	g := newTestGem(t)
	sig := signRSA(t, g.key, g.dataTarGz, crypto.SHA256)
	tampered := append([]byte(nil), g.dataTarGz...)
	tampered[len(tampered)-1] ^= 0xFF
	gem := buildGemTar(t, map[string][]byte{
		"metadata.gz":     g.metadataGz,
		"metadata.gz.sig": signRSA(t, g.key, g.metadataGz, crypto.SHA256),
		"data.tar.gz":     tampered,
		"data.tar.gz.sig": sig,
		"cert.pem":        certPEM(g.certDER),
	})
	res, err := VerifyGemSignature(context.Background(), gem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusFailed {
		t.Fatalf("Status=%q want failed", res.Status)
	}
	if res.SignerID == "" {
		t.Errorf("SignerID should be populated even on failure")
	}
}

func TestVerifyGemSignature_MissingCert(t *testing.T) {
	g := newTestGem(t)
	gem := buildGemTar(t, map[string][]byte{
		"metadata.gz":     g.metadataGz,
		"metadata.gz.sig": signRSA(t, g.key, g.metadataGz, crypto.SHA256),
		"data.tar.gz":     g.dataTarGz,
		"data.tar.gz.sig": signRSA(t, g.key, g.dataTarGz, crypto.SHA256),
	})
	res, err := VerifyGemSignature(context.Background(), gem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusUnavailable {
		t.Fatalf("Status=%q want unavailable", res.Status)
	}
	if !hasWarningPrefix(res.Warnings, "rubygems_gemcert_no_signing_cert") {
		t.Errorf("expected rubygems_gemcert_no_signing_cert warning; got %v", res.Warnings)
	}
}

func TestVerifyGemSignature_MissingSignatures(t *testing.T) {
	g := newTestGem(t)
	gem := buildGemTar(t, map[string][]byte{
		"metadata.gz": g.metadataGz,
		"data.tar.gz": g.dataTarGz,
		"cert.pem":    certPEM(g.certDER),
	})
	res, err := VerifyGemSignature(context.Background(), gem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusUnavailable {
		t.Fatalf("Status=%q want unavailable", res.Status)
	}
	if !hasWarningPrefix(res.Warnings, "rubygems_gemcert_no_signature") {
		t.Errorf("expected rubygems_gemcert_no_signature warning; got %v", res.Warnings)
	}
}

func TestVerifyGemSignature_LegacySHA1(t *testing.T) {
	g := newTestGem(t)
	gem := buildGemTar(t, map[string][]byte{
		"metadata.gz":     g.metadataGz,
		"metadata.gz.sig": signRSA(t, g.key, g.metadataGz, crypto.SHA1),
		"data.tar.gz":     g.dataTarGz,
		"data.tar.gz.sig": signRSA(t, g.key, g.dataTarGz, crypto.SHA1),
		"cert.pem":        certPEM(g.certDER),
	})
	res, err := VerifyGemSignature(context.Background(), gem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.Status != StatusVerified {
		t.Fatalf("Status=%q want verified (SHA-1 fallback); err=%q", res.Status, res.Error)
	}
}

func TestVerifyGemSignature_SignerIDMatchesDERSHA256(t *testing.T) {
	g := newTestGem(t)
	gem := buildGemTar(t, map[string][]byte{
		"metadata.gz":     g.metadataGz,
		"metadata.gz.sig": signRSA(t, g.key, g.metadataGz, crypto.SHA256),
		"data.tar.gz":     g.dataTarGz,
		"data.tar.gz.sig": signRSA(t, g.key, g.dataTarGz, crypto.SHA256),
		"cert.pem":        certPEM(g.certDER),
	})
	res, err := VerifyGemSignature(context.Background(), gem)
	if err != nil || res.Status != StatusVerified {
		t.Fatalf("unexpected: status=%q err=%v", res.Status, err)
	}
	expected := sha256.Sum256(g.certDER)
	if got, want := res.SignerID, hex.EncodeToString(expected[:]); got != want {
		t.Errorf("SignerID=%q, want SHA-256(DER)=%q", got, want)
	}
	// Lowercase hex, no colons.
	if strings.ContainsAny(res.SignerID, ":ABCDEF") {
		t.Errorf("SignerID should be lowercase hex without colons, got %q", res.SignerID)
	}
}

func TestVerifyGemSignature_UnparseableTar(t *testing.T) {
	res, err := VerifyGemSignature(context.Background(), []byte("not-a-tar-archive-just-junk"))
	if err != nil {
		t.Fatalf("should not return error on garbage input, got %v", err)
	}
	if res.Status != StatusUnavailable {
		t.Errorf("Status=%q want unavailable", res.Status)
	}
}

func hasWarningPrefix(warnings []string, prefix string) bool {
	for _, w := range warnings {
		if strings.HasPrefix(w, prefix) {
			return true
		}
	}
	return false
}
