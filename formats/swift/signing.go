package swift

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// SE-0391 defines a single signature format for SPM v1 registries:
// `cms-1.0.0`. The signature envelope is a CMS SignedData structure
// (RFC 5652) with a detached signature over the source archive.
const SignatureFormatCMS100 = "cms-1.0.0"

// Errors returned by Verify.
var (
	ErrUnsupportedSignatureFormat = errors.New("swift signing: unsupported signature format")
	ErrMissingSigner              = errors.New("swift signing: CMS envelope has no signer info")
	ErrDigestMismatch             = errors.New("swift signing: archive digest does not match signature")
	ErrInvalidSignature           = errors.New("swift signing: signature verification failed")
	ErrInvalidCertChain           = errors.New("swift signing: certificate chain invalid")
)

// VerifyResult captures the outcome of a CMS signature verification.
type VerifyResult struct {
	// Verified is true when the signature is cryptographically valid
	// and the digest of the archive matches.
	Verified bool
	// Signer is the certificate subject Common Name of the first
	// signer whose signature verified, or empty if none verified.
	Signer string
	// SourceRepo is the URI-form SubjectAlternativeName (if any) — a
	// convention used by Apple's signing tooling to link a signed
	// package back to its canonical source repository.
	SourceRepo string
	// SerialNumber is the hex-encoded serial of the signer certificate.
	SerialNumber string
}

// Verifier knows how to verify SE-0391 CMS signatures against a
// configurable trust pool.
type Verifier struct {
	// Roots is the pool of trusted CA certificates. When nil the
	// system trust pool is used at verification time.
	Roots *x509.CertPool
	// Now returns the verification time. Exposed for tests; when nil
	// time.Now is used.
	Now func() time.Time
}

// NewVerifier constructs a Verifier with the given trust roots. Pass
// nil to use the system trust store.
func NewVerifier(roots *x509.CertPool) *Verifier {
	return &Verifier{Roots: roots}
}

// LoadTrustRoots reads a PEM file of CA certificates and returns a
// CertPool suitable for NewVerifier. An empty path returns (nil, nil)
// so the system trust pool is used.
func LoadTrustRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return nil, fmt.Errorf("swift signing: no certificates found in %s", path)
	}
	return pool, nil
}

// Verify validates a SE-0391 signature over an archive.
//
//   - archive is the zip bytes the signature is over.
//   - signature is the detached CMS SignedData envelope.
//   - format is the signature format advertised in
//     X-Swift-Package-Signature-Format (must be "cms-1.0.0").
func (v *Verifier) Verify(archive, signature []byte, format string) (VerifyResult, error) {
	if format != SignatureFormatCMS100 {
		return VerifyResult{}, fmt.Errorf("%w: %q", ErrUnsupportedSignatureFormat, format)
	}
	cms, err := parseCMSSignedData(signature)
	if err != nil {
		return VerifyResult{}, err
	}
	if len(cms.SignerInfos) == 0 {
		return VerifyResult{}, ErrMissingSigner
	}
	// Build a trust pool for chain verification.
	opts := x509.VerifyOptions{
		Roots:     v.Roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning, x509.ExtKeyUsageAny},
	}
	if v.Now != nil {
		opts.CurrentTime = v.Now()
	}

	// Archive digest must match — SE-0391 signatures are detached and
	// cover SHA-256(archive). CMS SignedData may embed a different
	// digest alg in SignerInfo, but we require SHA-256 here.
	archiveDigest := sha256.Sum256(archive)

	for _, si := range cms.SignerInfos {
		cert, err := cms.findSigner(si)
		if err != nil {
			continue
		}
		if _, err := cert.Verify(opts); err != nil {
			continue
		}
		if !bytes.Equal(si.MessageDigest, archiveDigest[:]) {
			continue
		}
		if err := verifySignature(cert, si); err != nil {
			continue
		}
		return VerifyResult{
			Verified:     true,
			Signer:       cert.Subject.CommonName,
			SourceRepo:   firstURISAN(cert),
			SerialNumber: fmt.Sprintf("%x", cert.SerialNumber),
		}, nil
	}
	return VerifyResult{}, ErrInvalidSignature
}

// --- minimal CMS SignedData parser (RFC 5652) ---

// This is a deliberately small subset — enough to extract the signer
// certificate, digest, and signature bytes for SE-0391. For a full CMS
// implementation use a dedicated pkcs7 library.

type cmsSignedData struct {
	Certificates []*x509.Certificate
	SignerInfos  []cmsSignerInfo
}

type cmsSignerInfo struct {
	// IssuerAndSerial identifies the signing certificate.
	Issuer       asn1.RawValue
	SerialNumber []byte
	// DigestAlgorithm is the OID of the hash algorithm.
	DigestAlgorithmOID asn1.ObjectIdentifier
	// MessageDigest is the raw digest bytes from the signed attribute.
	MessageDigest []byte
	// SignatureAlgorithm is the OID of the signing algorithm.
	SignatureAlgorithmOID asn1.ObjectIdentifier
	// Signature is the raw signature bytes.
	Signature []byte
	// RawSignedAttributes is the DER-encoded SET OF signed attributes
	// used for signature verification. Present when the CMS signature
	// is made over attributes rather than content directly.
	RawSignedAttributes []byte
}

var (
	oidData              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

// contentInfo is the outermost ASN.1 structure (RFC 5652 §3).
type contentInfoASN struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// signedDataASN matches RFC 5652 §5.1.
type signedDataASN struct {
	Version          int
	DigestAlgorithms asn1.RawValue `asn1:"set"`
	EncapContentInfo asn1.RawValue
	Certificates     asn1.RawValue   `asn1:"optional,tag:0,implicit"`
	CRLs             asn1.RawValue   `asn1:"optional,tag:1,implicit"`
	SignerInfos      []signerInfoASN `asn1:"set"`
}

type signerInfoASN struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    algorithmIdentifierASN
	AuthenticatedAttrs asn1.RawValue `asn1:"optional,tag:0,implicit,set"`
	SignatureAlgorithm algorithmIdentifierASN
	Signature          []byte
	UnauthAttrs        asn1.RawValue `asn1:"optional,tag:1,implicit,set"`
}

type algorithmIdentifierASN struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type issuerAndSerialASN struct {
	Issuer       asn1.RawValue
	SerialNumber []byte
}

// parseCMSSignedData decodes the subset of the CMS SignedData structure
// we care about.
func parseCMSSignedData(raw []byte) (*cmsSignedData, error) {
	// Tolerate PEM-wrapped input (used in tests).
	if block, _ := pem.Decode(raw); block != nil {
		raw = block.Bytes
	}
	var ci contentInfoASN
	if _, err := asn1.Unmarshal(raw, &ci); err != nil {
		return nil, fmt.Errorf("swift signing: parse ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("swift signing: outer content-type is not SignedData (got %v)", ci.ContentType)
	}
	var sd signedDataASN
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("swift signing: parse SignedData: %w", err)
	}
	out := &cmsSignedData{}

	if len(sd.Certificates.Bytes) > 0 {
		certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
		if err != nil {
			return nil, fmt.Errorf("swift signing: parse certs: %w", err)
		}
		out.Certificates = certs
	}

	for _, si := range sd.SignerInfos {
		info := cmsSignerInfo{
			DigestAlgorithmOID:    si.DigestAlgorithm.Algorithm,
			SignatureAlgorithmOID: si.SignatureAlgorithm.Algorithm,
			Signature:             si.Signature,
		}
		// SID is either IssuerAndSerialNumber (tag) or
		// SubjectKeyIdentifier (context 0). We only decode the common
		// IssuerAndSerialNumber form.
		if len(si.SID.FullBytes) > 0 {
			var is issuerAndSerialASN
			if _, err := asn1.Unmarshal(si.SID.FullBytes, &is); err == nil {
				info.Issuer = is.Issuer
				info.SerialNumber = is.SerialNumber
			}
		}
		if len(si.AuthenticatedAttrs.Bytes) > 0 {
			// AuthenticatedAttrs is IMPLICIT [0] SET OF Attribute. The
			// .Bytes field holds the SET content without the outer
			// context tag — wrap it in a SET tag before unmarshaling.
			setWrapped := encodeASN1Set(si.AuthenticatedAttrs.Bytes)
			var attrs []attributeASN
			if _, err := asn1.UnmarshalWithParams(setWrapped, &attrs, "set"); err == nil {
				for _, a := range attrs {
					if !a.Type.Equal(oidAttrMessageDigest) {
						continue
					}
					// a.Values is the SET OF AttributeValue. We expect
					// a single OCTET STRING containing the digest.
					var digest []byte
					if _, err := asn1.Unmarshal(a.Values.Bytes, &digest); err == nil {
						info.MessageDigest = digest
					}
				}
			}
			// The signature is computed over the DER encoding of the
			// authenticated attributes — capture them for verification.
			// SE-0391 signs over the AuthenticatedAttributes so we need
			// to reconstruct the SET OF form (not the IMPLICIT [0]).
			info.RawSignedAttributes = setWrapped
		}
		out.SignerInfos = append(out.SignerInfos, info)
	}
	return out, nil
}

type attributeASN struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// reencodeAttributesSet wraps the inner bytes of an IMPLICIT [0] SET in
// an explicit SET OF tag so signature verification can compute the hash
// over the canonical attribute encoding.
func reencodeAttributesSet(inner []byte) []byte {
	// Prepend an ASN.1 SET header (tag 0x31).
	return encodeASN1Set(inner)
}

func encodeASN1Set(inner []byte) []byte {
	// SET tag = 0x31, length encoded per DER rules.
	length := len(inner)
	var out []byte
	out = append(out, 0x31)
	switch {
	case length < 0x80:
		out = append(out, byte(length))
	case length < 0x100:
		out = append(out, 0x81, byte(length))
	case length < 0x10000:
		out = append(out, 0x82, byte(length>>8), byte(length))
	default:
		out = append(out, 0x83, byte(length>>16), byte(length>>8), byte(length))
	}
	return append(out, inner...)
}

// findSigner returns the x509 cert that matches a SignerInfo.
func (sd *cmsSignedData) findSigner(si cmsSignerInfo) (*x509.Certificate, error) {
	for _, cert := range sd.Certificates {
		if cert.SerialNumber != nil && bytes.Equal(cert.SerialNumber.Bytes(), si.SerialNumber) {
			return cert, nil
		}
		if len(si.SerialNumber) > 0 && bytes.Equal([]byte(cert.SerialNumber.String()), si.SerialNumber) {
			return cert, nil
		}
	}
	if len(sd.Certificates) == 1 {
		return sd.Certificates[0], nil
	}
	return nil, ErrMissingSigner
}

// verifySignature verifies the signature bytes against the cert's
// public key. When RawSignedAttributes is present the signature is over
// the hash of those attributes; otherwise it's over the archive digest.
func verifySignature(cert *x509.Certificate, si cmsSignerInfo) error {
	var hashed []byte
	if len(si.RawSignedAttributes) > 0 {
		sum := sha256.Sum256(si.RawSignedAttributes)
		hashed = sum[:]
	} else {
		// SE-0391 always has authenticated attributes; this branch is
		// defensive against malformed input.
		return ErrInvalidSignature
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed, si.Signature)
	case *ecdsa.PublicKey:
		if ecdsa.VerifyASN1(pub, hashed, si.Signature) {
			return nil
		}
		return ErrInvalidSignature
	default:
		return fmt.Errorf("swift signing: unsupported signer key type %T", pub)
	}
}

// firstURISAN returns the first URI subject-alternative-name on a cert,
// or "" if none. Apple's SPM signing tooling embeds the canonical repo
// URL here so we surface it as VerifyResult.SourceRepo.
func firstURISAN(cert *x509.Certificate) string {
	for _, u := range cert.URIs {
		if u != nil {
			return u.String()
		}
	}
	return ""
}
