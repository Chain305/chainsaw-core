package provenance

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
)

// This file exists to answer one narrow question that
// github.com/digitorus/pkcs7 cannot: "does this blob contain SignerInfo
// entries that the PKCS#7 parser silently dropped?"
//
// Background (P8-46). digitorus/pkcs7 models SignerIdentifier as the
// PKCS#7 `issuerAndSerialNumber SEQUENCE` only. RFC 5652 CMS widened it
// to a CHOICE that also admits `subjectKeyIdentifier [0] IMPLICIT OCTET
// STRING`, and that is the form nuget.org's `.signature.p7s` uses
// (SignedData version 3). The SET OF SignerInfo therefore fails to
// decode — and `parseSignedData` throws the asn1.Unmarshal error away, so
// Parse returns a PKCS7 with the certificates populated and Signers
// empty. Verification then fails with "pkcs7: Message has no signers".
//
// Without this file the checker cannot tell that outcome apart from a
// genuinely signer-less blob, and both would have to share a status with
// a tampered package. With it, "the parser dropped N signers" is a fact
// we can assert, so the gap reports as StatusUnverified +
// ReasonAttestationUnparseable and StatusFailed stays reserved for real
// verification failures.
//
// This deliberately does NOT verify anything. Counting entries is not
// validating them, and a caller must never treat a non-zero count as
// evidence about the package.

// errNotSignedData is returned when the blob is well-formed DER but is
// not a CMS/PKCS#7 SignedData ContentInfo.
var errNotSignedData = errors.New("provenance: not a CMS SignedData ContentInfo")

// oidSignedData is 1.2.840.113549.1.7.2.
var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

// cmsContentInfo mirrors RFC 5652 ContentInfo.
type cmsContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// cmsSignedDataShape is RFC 5652 SignedData with everything after the
// certificate set left opaque. SignerInfos is []asn1.RawValue rather than
// a modelled struct precisely so the SignerIdentifier CHOICE cannot make
// the decode fail — the whole point is to count entries the strict
// decoder could not read.
type cmsSignedDataShape struct {
	Version                    int                        `asn1:"default:1"`
	DigestAlgorithmIdentifiers []pkix.AlgorithmIdentifier `asn1:"set"`
	ContentInfo                asn1.RawValue
	Certificates               asn1.RawValue   `asn1:"optional,tag:0"`
	CRLs                       asn1.RawValue   `asn1:"optional,tag:1"`
	SignerInfos                []asn1.RawValue `asn1:"set"`
}

// cmsSignerInfoCount reports how many SignerInfo entries a CMS SignedData
// blob declares, without interpreting them.
//
// Returns an error when the blob is not parseable as a SignedData
// ContentInfo at all; callers treat that as "we learned nothing", never
// as evidence about the artifact.
func cmsSignerInfoCount(der []byte) (int, error) {
	if len(der) == 0 {
		return 0, errNotSignedData
	}
	var ci cmsContentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return 0, err
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return 0, errNotSignedData
	}
	var sd cmsSignedDataShape
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return 0, err
	}
	return len(sd.SignerInfos), nil
}
