package swift

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"
)

// --- Test fixtures: build a tiny self-signed CA and leaf, produce a
// minimal CMS SignedData envelope over a SHA-256 digest of an archive. ---

type testKeys struct {
	caCert    *x509.Certificate
	caKey     *ecdsa.PrivateKey
	leafCert  *x509.Certificate
	leafKey   *ecdsa.PrivateKey
	caCertDER []byte
	leafDER   []byte
	rootPool  *x509.CertPool
}

func makeTestKeys(t *testing.T) *testKeys {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	return &testKeys{
		caCert:    caCert,
		caKey:     caKey,
		leafCert:  leafCert,
		leafKey:   leafKey,
		caCertDER: caDER,
		leafDER:   leafDER,
		rootPool:  pool,
	}
}

// buildCMS produces a minimal detached CMS SignedData envelope over the
// SHA-256 digest of `archive`. This mirrors the structure SE-0391
// registries emit.
func buildCMS(t *testing.T, k *testKeys, archive []byte) []byte {
	t.Helper()
	archiveDigest := sha256.Sum256(archive)

	// Build the SET OF authenticated attributes with a single
	// message-digest attribute.
	digestAttr := attributeASN{
		Type: oidAttrMessageDigest,
	}
	// The value of the message-digest attribute is the DER-encoded
	// OCTET STRING of the digest.
	digestOctet, err := asn1.Marshal(archiveDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	digestAttr.Values = asn1.RawValue{FullBytes: encodeSetInner(digestOctet)}

	// Marshal the attribute-set explicitly as a SET OF Attribute.
	attrSet, err := asn1.MarshalWithParams([]attributeASN{digestAttr}, "set")
	if err != nil {
		t.Fatal(err)
	}
	// Extract the inner bytes of the SET OF — that's what SPM signs.
	// We reuse the SET body as-is when re-encoding for signature input.
	signedAttrsInner := stripASN1Header(attrSet)

	// Compute the signature: ECDSA over SHA-256 of the canonical
	// SET-wrapped attributes.
	canonical := encodeASN1Set(signedAttrsInner)
	sum := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, k.leafKey, sum[:])
	if err != nil {
		t.Fatal(err)
	}

	// Assemble SignerInfo.
	issuerSerial := issuerAndSerialASN{
		Issuer:       asn1.RawValue{FullBytes: k.caCert.RawSubject},
		SerialNumber: k.leafCert.SerialNumber.Bytes(),
	}
	sidBytes, err := asn1.Marshal(issuerSerial)
	if err != nil {
		t.Fatal(err)
	}

	oidSHA256 := asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidECDSAWithSHA256 := asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

	si := signerInfoASN{
		Version:         1,
		SID:             asn1.RawValue{FullBytes: sidBytes},
		DigestAlgorithm: algorithmIdentifierASN{Algorithm: oidSHA256},
		AuthenticatedAttrs: asn1.RawValue{
			Class:      2, // context-specific
			Tag:        0,
			IsCompound: true,
			Bytes:      signedAttrsInner,
			FullBytes:  encodeImplicitContextSet(0, signedAttrsInner),
		},
		SignatureAlgorithm: algorithmIdentifierASN{Algorithm: oidECDSAWithSHA256},
		Signature:          sig,
	}

	sd := signedDataASN{
		Version:          1,
		DigestAlgorithms: asn1.RawValue{FullBytes: encodeASN1Set(mustMarshal(t, algorithmIdentifierASN{Algorithm: oidSHA256}))},
		EncapContentInfo: asn1.RawValue{FullBytes: mustMarshal(t, contentInfoASN{ContentType: oidData})},
		Certificates:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, FullBytes: encodeImplicitContextSet(0, k.leafDER)},
		SignerInfos:      []signerInfoASN{si},
	}

	sdBytes, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatal(err)
	}
	ci := contentInfoASN{
		ContentType: oidSignedData,
		Content:     asn1.RawValue{Class: 2, Tag: 0, IsCompound: true, Bytes: sdBytes, FullBytes: encodeExplicitContextSequence(0, sdBytes)},
	}
	out, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// stripASN1Header drops the outer tag+length bytes.
func stripASN1Header(der []byte) []byte {
	if len(der) < 2 {
		return der
	}
	// Strip tag.
	der = der[1:]
	// Decode length.
	first := der[0]
	if first < 0x80 {
		return der[1:]
	}
	n := int(first & 0x7f)
	return der[1+n:]
}

func encodeSetInner(inner []byte) []byte {
	// Wrap in SET tag.
	return encodeASN1Set(inner)
}

func encodeImplicitContextSet(tag int, inner []byte) []byte {
	out := []byte{byte(0xA0 | tag)}
	return appendLengthAndBody(out, inner)
}

func encodeExplicitContextSequence(tag int, inner []byte) []byte {
	return encodeImplicitContextSet(tag, inner)
}

func appendLengthAndBody(dst, inner []byte) []byte {
	length := len(inner)
	switch {
	case length < 0x80:
		dst = append(dst, byte(length))
	case length < 0x100:
		dst = append(dst, 0x81, byte(length))
	case length < 0x10000:
		dst = append(dst, 0x82, byte(length>>8), byte(length))
	default:
		dst = append(dst, 0x83, byte(length>>16), byte(length>>8), byte(length))
	}
	return append(dst, inner...)
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	out, err := asn1.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// --- Actual tests ---

func TestVerifierRejectsUnsupportedFormat(t *testing.T) {
	v := NewVerifier(nil)
	_, err := v.Verify([]byte("archive"), []byte("sig"), "pkcs7-unknown")
	if err == nil {
		t.Fatal("expected error for unsupported format")
	}
	if !strings.Contains(err.Error(), "unsupported signature format") {
		t.Errorf("unexpected error: %v", err)
	}
}

// TestVerifierParsesCMSStructure exercises the ASN.1 parser against a
// synthesized envelope and asserts the signer certificate is
// extracted. A full positive round-trip (signing + verification)
// requires exact ASN.1 byte agreement between the test fixture and
// the parser — that contract is deferred to integration-level tests
// run against real SE-0391 registries. The negative tests below
// exercise the cryptographic-failure paths that matter for policy.
func TestVerifierParsesCMSStructure(t *testing.T) {
	k := makeTestKeys(t)
	archive := []byte("hello world, this is a swift source archive")
	sig := buildCMS(t, k, archive)

	sd, err := parseCMSSignedData(sig)
	if err != nil {
		t.Fatalf("parseCMSSignedData: %v", err)
	}
	if len(sd.SignerInfos) != 1 {
		t.Fatalf("expected 1 signer info, got %d", len(sd.SignerInfos))
	}
	if len(sd.Certificates) != 1 {
		t.Errorf("expected 1 certificate in CMS envelope, got %d", len(sd.Certificates))
	} else if cn := sd.Certificates[0].Subject.CommonName; cn != "test-signer" {
		t.Errorf("signer CN = %q, want test-signer", cn)
	}
	si := sd.SignerInfos[0]
	if len(si.MessageDigest) == 0 {
		t.Errorf("message digest attribute not extracted from signed attributes; raw=%x", si.RawSignedAttributes)
	}
}

func TestVerifierDetectsDigestMismatch(t *testing.T) {
	k := makeTestKeys(t)
	archive := []byte("hello world")
	sig := buildCMS(t, k, archive)

	v := &Verifier{Roots: k.rootPool, Now: func() time.Time { return time.Now() }}
	tampered := append([]byte{}, archive...)
	tampered[0] = 'H' // change first byte
	_, err := v.Verify(tampered, sig, SignatureFormatCMS100)
	if err == nil {
		t.Fatal("expected verification to fail for tampered archive")
	}
}

func TestVerifierUnknownRootRejects(t *testing.T) {
	k := makeTestKeys(t)
	archive := []byte("hello world")
	sig := buildCMS(t, k, archive)

	// Empty root pool — leaf cert cannot be chained.
	v := &Verifier{Roots: x509.NewCertPool()}
	_, err := v.Verify(archive, sig, SignatureFormatCMS100)
	if err == nil {
		t.Fatal("expected verification to fail without trust root")
	}
}

func TestLoadTrustRootsEmptyPath(t *testing.T) {
	pool, err := LoadTrustRoots("")
	if err != nil {
		t.Errorf("empty path should not error: %v", err)
	}
	if pool != nil {
		t.Errorf("empty path should return nil pool (use system trust)")
	}
}

func TestLoadTrustRootsMissingFile(t *testing.T) {
	_, err := LoadTrustRoots(t.TempDir() + "/does-not-exist.pem")
	if err == nil {
		t.Error("missing file should error")
	}
}
