package provenance

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/digitorus/pkcs7"
)

// realNuGetSignatureFixture is the verbatim `.signature.p7s` entry lifted
// from Newtonsoft.Json 13.0.3 on nuget.org — a package that is both
// author- and repository-signed. Provenance:
//
//	https://api.nuget.org/v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg
//	nupkg  sha256 872fc189e638ab1056555b03aaa38f68bcb54286e221aa646eb1129babf63c77
//	p7s    sha256 da08c8f31750053099f514e4faeeb6a4f4eb3004b38388e851b86df644583aff
//
// It is checked in because the defect it pins (P8-46) is a wire-format
// gap: a synthetic PKCS#7 blob produced by the same Go library that fails
// to read it could not reproduce the bug, and a network-fetched fixture
// would make the regression test skip exactly when it matters.
const realNuGetSignatureFixture = "testdata/nuget/newtonsoft.json.13.0.3.signature.p7s"

func loadNuGetSignatureFixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(realNuGetSignatureFixture)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return b
}

// TestDigitorusPkcs7CannotWalkRealNuGetSignature pins the upstream
// behaviour the fix is built on, so that if digitorus/pkcs7 ever learns
// the CMS SignerIdentifier CHOICE this test fails loudly and the
// StatusUnverified branch can be replaced with real verification rather
// than quietly masking a now-working parser.
func TestDigitorusPkcs7CannotWalkRealNuGetSignature(t *testing.T) {
	sig := loadNuGetSignatureFixture(t)

	p7, err := pkcs7.Parse(sig)
	if err != nil {
		t.Fatalf("pkcs7.Parse unexpectedly errored: %v "+
			"(the defect is that it SUCCEEDS with zero signers)", err)
	}
	if len(p7.Certificates) == 0 {
		t.Fatalf("expected the certificate set to decode; got 0 certificates")
	}
	if len(p7.Signers) != 0 {
		t.Fatalf("digitorus/pkcs7 now decodes %d signer(s) from a real nuget.org "+
			"signature — the CMS gap is closed upstream. Replace the "+
			"StatusUnverified branch in nuget.go with real verification and "+
			"reconcile claim C-073.", len(p7.Signers))
	}
	if err := p7.Verify(); err == nil || !strings.Contains(err.Error(), "no signers") {
		t.Fatalf("Verify() = %v, want a 'no signers' error", err)
	}
}

// TestCmsSignerInfoCountSeesTheDroppedSigners is the fact the fix turns
// on: the DER genuinely declares SignerInfo entries, so "zero signers" is
// provably a parser gap and not a signer-less blob.
func TestCmsSignerInfoCountSeesTheDroppedSigners(t *testing.T) {
	sig := loadNuGetSignatureFixture(t)

	n, err := cmsSignerInfoCount(sig)
	if err != nil {
		t.Fatalf("cmsSignerInfoCount: %v", err)
	}
	if n == 0 {
		t.Fatalf("cmsSignerInfoCount = 0; the whole discrimination rests on this being > 0")
	}
	t.Logf("real nuget.org .signature.p7s declares %d SignerInfo entr(ies) "+
		"that digitorus/pkcs7 drops", n)
}

func TestCmsSignerInfoCountRejectsNonSignedData(t *testing.T) {
	for name, in := range map[string][]byte{
		"empty":     nil,
		"garbage":   []byte("not der at all"),
		"truncated": loadNuGetSignatureFixture(t)[:32],
	} {
		if _, err := cmsSignerInfoCount(in); err == nil {
			t.Errorf("%s: want an error, got nil", name)
		}
	}
}

// nupkgWithSignature builds the minimum .nupkg the checker reads: a zip
// carrying a `.signature.p7s` entry.
func nupkgWithSignature(t *testing.T, sig []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create(".signature.p7s")
	if err != nil {
		t.Fatalf("zip create: %v", err)
	}
	if _, err := w.Write(sig); err != nil {
		t.Fatalf("zip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

// nupkgTransport serves the flatcontainer .nupkg URL from memory and
// fails everything else, so the test can never silently reach the real
// api.nuget.org.
type nupkgTransport struct {
	nupkg []byte
	t     *testing.T
}

func (tr *nupkgTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.Contains(req.URL.Path, ".nupkg") {
		tr.t.Fatalf("unexpected outbound request to %s — the test must not "+
			"reach the network past the artifact fetch", req.URL)
	}
	h := http.Header{}
	h.Set("Content-Length", itoa(len(tr.nupkg)))
	body := io.NopCloser(bytes.NewReader(tr.nupkg))
	if req.Method == http.MethodHead {
		body = io.NopCloser(bytes.NewReader(nil))
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		Header:        h,
		Body:          body,
		ContentLength: int64(len(tr.nupkg)),
		Request:       req,
	}, nil
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestNuGetRealSignedNupkgIsNotReportedAsFailed is the P8-46 regression.
//
// The assertion is deliberately `!= StatusFailed` first and
// `== StatusUnverified` second, per the plan's own caveat: chainsaw does
// not yet implement CMS SignerIdentifier, so asserting StatusVerified
// here would assert something the shipped fix does not do. What must
// never regress is that a correctly-signed package shares a status with a
// tampered one.
func TestNuGetRealSignedNupkgIsNotReportedAsFailed(t *testing.T) {
	sig := loadNuGetSignatureFixture(t)
	client := &http.Client{Transport: &nupkgTransport{nupkg: nupkgWithSignature(t, sig), t: t}}
	c := newNuGetChecker(client, nil)
	// Supply trust roots locally so the parse-gap branch is the only thing
	// under test: without this, removing the fix would fail this test on a
	// blocked trust-index fetch rather than on the status it is about.
	c.trustCache.loader = func(context.Context) (*x509.CertPool, error) {
		return x509.NewCertPool(), nil
	}

	got := c.Check(context.Background(), "Newtonsoft.Json", "13.0.3")

	if got.Status == StatusFailed {
		t.Fatalf("a genuinely author- and repository-signed package reported as "+
			"FAILED — the same status a tampered package gets. Result: %+v", got)
	}
	if got.Status != StatusUnverified {
		t.Fatalf("Status = %q, want %q", got.Status, StatusUnverified)
	}
	if got.Reason != ReasonAttestationUnparseable {
		t.Errorf("Reason = %q, want %q", got.Reason, ReasonAttestationUnparseable)
	}
	if got.AttestationType != "x509" {
		t.Errorf("AttestationType = %q, want %q", got.AttestationType, "x509")
	}
	if !strings.Contains(got.Error, "coverage gap") {
		t.Errorf("Error must say the gap is chainsaw's, got %q", got.Error)
	}
	if strings.Contains(strings.ToLower(got.Error), "message has no signers") {
		t.Errorf("Error still leaks the raw library message: %q", got.Error)
	}
}

// TestNuGetUnsignedNupkgIsMissing keeps the StatusMissing branch honest:
// the fix must not turn "no signature at all" into "unparseable".
func TestNuGetUnsignedNupkgIsMissing(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("lib/net6.0/Thing.dll")
	_, _ = w.Write([]byte("not a signature"))
	_ = zw.Close()

	client := &http.Client{Transport: &nupkgTransport{nupkg: buf.Bytes(), t: t}}
	c := newNuGetChecker(client, nil)

	got := c.Check(context.Background(), "Unsigned.Thing", "1.0.0")
	if got.Status != StatusMissing {
		t.Fatalf("Status = %q, want %q (%+v)", got.Status, StatusMissing, got)
	}
	if got.Reason != ReasonNoAttestationFound {
		t.Errorf("Reason = %q, want %q", got.Reason, ReasonNoAttestationFound)
	}
}

// TestNuGetGenuineVerificationFailureStaysFailed is the control in the
// other direction: the P8-46 fix must not blanket-downgrade FAILED. A
// blob digitorus/pkcs7 CAN walk (issuerAndSerialNumber SignerIdentifier,
// which is what its own signer emits) whose chain does not reach the
// trust roots must still be FAILED.
func TestNuGetGenuineVerificationFailureStaysFailed(t *testing.T) {
	sig := selfSignedPKCS7(t, []byte("package bytes"))

	// Sanity: this blob is the shape the library understands, otherwise
	// the test would pass for the wrong reason.
	p7, err := pkcs7.Parse(sig)
	if err != nil {
		t.Fatalf("fixture parse: %v", err)
	}
	if len(p7.Signers) == 0 {
		t.Fatalf("fixture has no readable signers; it cannot exercise the FAILED path")
	}

	client := &http.Client{Transport: &nupkgTransport{nupkg: nupkgWithSignature(t, sig), t: t}}
	c := newNuGetChecker(client, nil)
	// Empty, non-nil trust pool → the self-signed chain cannot validate.
	c.trustCache.loader = func(context.Context) (*x509.CertPool, error) {
		return x509.NewCertPool(), nil
	}

	got := c.Check(context.Background(), "Rogue.Package", "1.0.0")
	if got.Status != StatusFailed {
		t.Fatalf("Status = %q, want %q — a signature that WAS walked and did not "+
			"validate must stay FAILED (%+v)", got.Status, StatusFailed, got)
	}
}

func selfSignedPKCS7(t *testing.T, content []byte) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "chainsaw-test-signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	sd, err := pkcs7.NewSignedData(content)
	if err != nil {
		t.Fatalf("NewSignedData: %v", err)
	}
	if err := sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatalf("AddSigner: %v", err)
	}
	out, err := sd.Finish()
	if err != nil {
		t.Fatalf("Finish: %v", err)
	}
	return out
}
