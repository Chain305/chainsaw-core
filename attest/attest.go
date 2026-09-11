// SLSA Verification Summary Attestation (VSA) construction (plan A1/A4/A8).
//
// The threat this package exists to answer is TRUST LAUNDERING. A bare
// `cosign sign` from a proxy asserts only "someone holding this key saw
// this digest" — signing an unsigned upstream artifact with the
// customer's key converts UNKNOWN PROVENANCE into VOUCHED BY US, and a
// sophisticated buyer will say so. The SLSA VSA exists for exactly this
// case: it lets a VERIFIER vouch for an artifact it did not produce, and
// it says so on its face — verifier, policy, policy version, time. The
// consumer trusts the verdict, not the artifact.
//
// Two consequences are load-bearing and are enforced here rather than
// left to callers (docs/plan_attestation_and_recall.md A8):
//
//   - The predicate is ALWAYS https://slsa.dev/verification_summary/v1.
//     Never emit anything that could be mistaken for SLSA Provenance
//     ("we built this"). There is no knob for the predicate type.
//   - An attestation with no policy binding and no timestamp is the
//     laundering machine the objection describes. BuildStatement rejects
//     an empty Verifier, ResourceURI, PolicyURI, PolicyVersion,
//     VerificationResult, or a zero TimeVerified. A signature is not
//     evidence quality; the reader needs to know reviewed under WHICH
//     policy at WHAT time, so those are not optional fields.
//
// What this package deliberately does NOT do (A3, A5):
//
//   - Key management. The private key lives in the customer's KMS and
//     never here; Signer is the seam an enterprise package in internal/
//     wires to awskms:// / gcpkms:// / azurekms:// / hashivault:// /
//     PKCS#11. Nothing in this package holds, derives, or persists key
//     material.
//   - Storage, HTTP, Rekor, COSIGN_REPOSITORY. No network call is
//     reachable from here, and nothing under internal/ is imported.
//   - Verification. We ship the verification recipe (Kyverno /
//     policy-controller / Connaisseur config via `chainsaw harden`), not
//     a verifier.
//
// We sign the DIGEST, never the bytes (A4). Subject carries an
// algorithm->hex map and nothing else; the artifact is never pulled,
// possessed, or rebuilt, which is why the 256 MiB checksum cap in
// internal/server/checksum_enforce.go is irrelevant to this path — for
// OCI the registry manifest digest IS the identity.
//
// Byte-for-byte determinism is a requirement, not a nicety: the same
// verdict must produce the same statement bytes on every host, or a
// re-mint looks like a different claim. See BuildStatement for the
// canonicalisation rules.
package attest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// StatementType is the in-toto Statement version this package emits.
const StatementType = "https://in-toto.io/Statement/v1"

// PredicateTypeVSA is the ONLY predicate type this package will emit.
// It is a constant, not a parameter, on purpose — see the package doc.
const PredicateTypeVSA = "https://slsa.dev/verification_summary/v1"

// PayloadType is the DSSE payloadType for an in-toto Statement. It is
// also the `type` half of the PAE encoding the signature covers.
const PayloadType = "application/vnd.in-toto+json"

// paePrefix is the DSSE v1 Pre-Authentication Encoding header.
const paePrefix = "DSSEv1"

// Subject identifies what is being attested: a digest, never bytes.
//
// Digest maps an algorithm name to a LOWERCASE HEX value with no
// algorithm prefix — the key already carries the algorithm, so
// {"sha256": "ab12..."}, never {"sha256": "sha256:ab12..."}.
type Subject struct {
	// Name is the artifact identity, typically a purl:
	// "pkg:oci/nginx" or "pkg:npm/lodash@4.17.21".
	Name string
	// Digest is algorithm -> lowercase hex. At least one entry is
	// required; see validateDigest for the length rules.
	Digest map[string]string
}

// Result is the VSA verificationResult. SLSA defines exactly two values.
type Result string

const (
	// ResultPassed means the policy evaluated and allowed the artifact.
	ResultPassed Result = "PASSED"
	// ResultFailed means the policy evaluated and refused it. A FAILED
	// VSA is still worth minting — it is a portable refusal.
	ResultFailed Result = "FAILED"
)

// VSA carries the fields SLSA v1 defines for verification_summary/v1.
//
// Every field that is not marked optional is required; BuildStatement
// refuses to mint an attestation missing any of them, because an
// attestation that cannot say who verified it, against what policy, and
// when, is indistinguishable from a bare signature.
type VSA struct {
	// Verifier is a URI identifying us plus our version, e.g.
	// "https://chain305.com/chainsaw@v0.21.23". Required.
	Verifier string
	// TimeVerified is when the verdict was reached. Serialised as
	// RFC3339 in UTC at SECOND precision (sub-second is dropped, not
	// rounded). Required; the zero value is rejected.
	TimeVerified time.Time
	// ResourceURI is the subject in purl/URI form. Required.
	ResourceURI string
	// PolicyURI identifies the policy that produced the verdict.
	// Required — see the A8 note in the package doc.
	PolicyURI string
	// PolicyVersion is an opaque version or digest of that policy.
	// Required. A 64-character lowercase-hex value is emitted as the
	// policy descriptor's sha256 digest; anything else is emitted as
	// the annotation "chainsaw.dev/policyVersion".
	PolicyVersion string
	// VerificationResult is PASSED or FAILED. Required; empty and any
	// other value are rejected.
	VerificationResult Result
	// VerifiedLevels are SLSA track levels the verifier established,
	// e.g. ["SLSA_BUILD_LEVEL_0"]. May be empty; emitted as [] rather
	// than null so the field is always present and parseable.
	VerifiedLevels []string
	// InputAttestations are upstream attestations we consumed to reach
	// the verdict. Optional. Each is validated like a subject.
	InputAttestations []Subject
	// DependencyLevels counts dependencies at each SLSA level.
	// Optional.
	DependencyLevels map[string]int
}

// Signer abstracts the crypto so KMS/local/HSM live elsewhere. The
// payload handed to Sign is the PAE-encoded bytes, NOT the raw
// statement — implementations must sign exactly what they are given.
type Signer interface {
	// Sign returns a signature over the PAE-encoded payload, plus the
	// key identifier that produced it (may be empty).
	Sign(ctx context.Context, payload []byte) (sig []byte, keyID string, err error)
}

// Envelope is the DSSE envelope shape.
type Envelope struct {
	PayloadType string      `json:"payloadType"`
	Payload     string      `json:"payload"` // base64(statement)
	Signatures  []Signature `json:"signatures"`
}

// Signature is one DSSE signature over the PAE of the payload.
type Signature struct {
	KeyID string `json:"keyid,omitempty"`
	Sig   string `json:"sig"` // base64
}

// resourceDescriptor is the in-toto ResourceDescriptor. Subjects use
// name+digest; the policy and input attestations use uri+digest. One
// struct with omitempty covers both and keeps field order fixed.
type resourceDescriptor struct {
	Name        string            `json:"name,omitempty"`
	URI         string            `json:"uri,omitempty"`
	Digest      map[string]string `json:"digest,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

// statement is the in-toto Statement wrapping a VSA predicate. Field
// order here IS the serialised order — see BuildStatement.
type statement struct {
	Type          string               `json:"_type"`
	Subject       []resourceDescriptor `json:"subject"`
	PredicateType string               `json:"predicateType"`
	Predicate     vsaPredicate         `json:"predicate"`
}

// vsaPredicate is the verification_summary/v1 predicate body. Field
// order follows the SLSA v1 spec's own field order.
type vsaPredicate struct {
	Verifier           verifierID           `json:"verifier"`
	TimeVerified       string               `json:"timeVerified"`
	ResourceURI        string               `json:"resourceUri"`
	Policy             resourceDescriptor   `json:"policy"`
	InputAttestations  []resourceDescriptor `json:"inputAttestations,omitempty"`
	VerificationResult string               `json:"verificationResult"`
	VerifiedLevels     []string             `json:"verifiedLevels"`
	DependencyLevels   map[string]int       `json:"dependencyLevels,omitempty"`
}

type verifierID struct {
	ID string `json:"id"`
}

// digestHexLen pins the expected hex length for the algorithms we know.
// An algorithm absent from this table is accepted with any non-empty
// lowercase-hex value of even length — we would rather carry a digest we
// cannot length-check than refuse a future algorithm outright, but a
// KNOWN algorithm at the WRONG length is a truncated or mangled digest
// and must never be signed.
var digestHexLen = map[string]int{
	"sha224":    56,
	"sha256":    64,
	"sha384":    96,
	"sha512":    128,
	"sha512224": 56,
	"sha512256": 64,
}

// strongDigests are the algorithms a subject may be bound by. At least
// one entry must come from this set.
//
// md5 and sha1 are deliberately absent from BOTH tables. A VSA whose
// only binding is an md5 is forgeable for the cost of a chosen-prefix
// collision — seconds of compute — which would let the same signed
// attestation cover an artifact we never evaluated. sha1 is the same
// shape at higher cost. Refusing them outright beats length-checking
// them.
var strongDigests = map[string]bool{
	"sha256": true, "sha384": true, "sha512": true,
	"sha224": true, "sha512224": true, "sha512256": true,
}

// validVerifiedLevels is the SLSA build-level vocabulary.
var validVerifiedLevels = map[string]bool{
	"SLSA_BUILD_LEVEL_0": true,
	"SLSA_BUILD_LEVEL_1": true,
	"SLSA_BUILD_LEVEL_2": true,
	"SLSA_BUILD_LEVEL_3": true,
}

// BuildStatement produces the canonical JSON bytes of an in-toto
// Statement carrying a VSA predicate for subj.
//
// Canonicalisation rules (mirroring the discipline in
// internal/policy/dsl/signing/verify.go's bundleContentHash — the same
// bytes on every host, or the signature means nothing):
//
//   - Struct field order is the serialised order, fixed by the type
//     declarations above; encoding/json never reorders struct fields.
//   - Map keys (Digest, Annotations, DependencyLevels) are emitted in
//     sorted order; encoding/json sorts map keys by definition.
//   - TimeVerified is RFC3339 in UTC at SECOND precision. Sub-second
//     components are dropped by the format, so two verdicts 10ms apart
//     produce the same timestamp — that is deliberate, an attestation
//     is not a trace.
//   - VerifiedLevels nil is normalised to [] so the field is always
//     present with the same shape.
//   - No trailing newline; json.Marshal (not Encoder) is used.
//
// ponytail: canonicalisation is encoding/json's ordering, not RFC 8785
// JCS. It is deterministic for every shape this package emits (no
// floats, no interface{}, no unicode escaping differences) and needs no
// new dependency. If we ever have to agree byte-for-byte with a
// non-Go canonicaliser, swap in github.com/cyberphone/json-canonicalization
// (already in the module graph as an indirect dep).
//
// Returns an error and no bytes if anything required is missing; there
// is no partial output, because a half-built attestation is worse than
// none.
func BuildStatement(subj Subject, v VSA) ([]byte, error) {
	// 1. Validate the subject. A digest is the whole binding — an
	//    unvalidated one signs a claim about nothing.
	subjDesc, err := subjectDescriptor(subj, "subject")
	if err != nil {
		return nil, err
	}

	// 2. Validate the predicate's required fields.
	// TrimSpace, not == "". A single space satisfies a bare emptiness
	// check, and the whole point of requiring PolicyURI and
	// PolicyVersion is that an attestation which cannot name the policy
	// behind it is the bare signature this package refuses to be. A
	// binding of " " is not a binding.
	if strings.TrimSpace(v.Verifier) == "" {
		return nil, errors.New("build statement: empty verifier")
	}
	if strings.TrimSpace(v.ResourceURI) == "" {
		return nil, errors.New("build statement: empty resource uri")
	}
	if strings.TrimSpace(v.PolicyURI) == "" {
		return nil, errors.New("build statement: empty policy uri")
	}
	if strings.TrimSpace(v.PolicyVersion) == "" {
		return nil, errors.New("build statement: empty policy version")
	}
	// SLSA defines the vocabulary; an attestation asserting a level that
	// is not one of them is over-claiming, which is the thing this
	// package exists to prevent. Enforced here rather than trusted to
	// callers, because "the caller only passes LEVEL_0 today" is a fact
	// about today.
	for _, lvl := range v.VerifiedLevels {
		if !validVerifiedLevels[lvl] {
			return nil, fmt.Errorf("build statement: verified level %q is not a SLSA build level", lvl)
		}
	}
	switch v.VerificationResult {
	case ResultPassed, ResultFailed:
	case "":
		return nil, errors.New("build statement: empty verification result")
	default:
		return nil, fmt.Errorf("build statement: verification result %q is not PASSED or FAILED", v.VerificationResult)
	}
	if v.TimeVerified.IsZero() {
		return nil, errors.New("build statement: zero time verified")
	}

	// 3. Validate every input attestation the same way as the subject.
	//    These are digests we are about to vouch for having consumed.
	inputs := make([]resourceDescriptor, 0, len(v.InputAttestations))
	for i, in := range v.InputAttestations {
		desc, err := subjectDescriptor(in, fmt.Sprintf("input attestation %d", i))
		if err != nil {
			return nil, err
		}
		// Input attestations are referenced by uri, not name.
		desc.URI, desc.Name = desc.Name, ""
		inputs = append(inputs, desc)
	}
	if len(inputs) == 0 {
		inputs = nil
	}

	// 4. Bind the policy. A 64-char lowercase-hex version is a digest
	//    and belongs in the digest field; anything else is an opaque
	//    version string and goes in an annotation, because a
	//    ResourceDescriptor digest value that is not a digest would
	//    mislead a generic in-toto reader.
	policy := resourceDescriptor{URI: v.PolicyURI}
	if isLowerHex(v.PolicyVersion) && len(v.PolicyVersion) == digestHexLen["sha256"] {
		policy.Digest = map[string]string{"sha256": v.PolicyVersion}
	} else {
		policy.Annotations = map[string]string{"chainsaw.dev/policyVersion": v.PolicyVersion}
	}

	levels := v.VerifiedLevels
	if levels == nil {
		levels = []string{}
	}

	// 5. Marshal. Predicate type is a constant; there is no path here
	//    that can emit SLSA Provenance.
	stmt := statement{
		Type:          StatementType,
		Subject:       []resourceDescriptor{subjDesc},
		PredicateType: PredicateTypeVSA,
		Predicate: vsaPredicate{
			Verifier:           verifierID{ID: v.Verifier},
			TimeVerified:       v.TimeVerified.UTC().Format(time.RFC3339),
			ResourceURI:        v.ResourceURI,
			Policy:             policy,
			InputAttestations:  inputs,
			VerificationResult: string(v.VerificationResult),
			VerifiedLevels:     levels,
			DependencyLevels:   v.DependencyLevels,
		},
	}
	out, err := json.Marshal(stmt)
	if err != nil {
		return nil, fmt.Errorf("marshal statement: %w", err)
	}
	return out, nil
}

// Sign builds the statement, PAE-encodes it, hands the PAE bytes to s,
// and returns the DSSE envelope.
//
// The signature covers the PAE, NOT the raw statement and NOT the
// base64 payload. Getting that wrong produces signatures no DSSE
// verifier can check, so PAE lives in one place (see pae) and nothing
// else in the tree may re-derive it.
func Sign(ctx context.Context, s Signer, subj Subject, v VSA) (*Envelope, error) {
	if s == nil {
		return nil, errors.New("sign: nil signer")
	}

	// 1. Build (and validate) the statement. An invalid VSA never
	//    reaches the signer — no "sign anyway" path exists (A8).
	payload, err := BuildStatement(subj, v)
	if err != nil {
		return nil, err
	}

	// 2. PAE-encode and sign.
	sig, keyID, err := s.Sign(ctx, pae(PayloadType, payload))
	if err != nil {
		return nil, fmt.Errorf("sign payload: %w", err)
	}
	if len(sig) == 0 {
		return nil, errors.New("sign: signer returned an empty signature")
	}

	// 3. Wrap. base64 is standard encoding WITH padding, per DSSE.
	return &Envelope{
		PayloadType: PayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payload),
		Signatures: []Signature{{
			KeyID: keyID,
			Sig:   base64.StdEncoding.EncodeToString(sig),
		}},
	}, nil
}

// pae is the DSSE v1 Pre-Authentication Encoding:
//
//	PAE(type, body) = "DSSEv1" SP len(type) SP type SP len(body) SP body
//
// SP is a single ASCII space and len() is the ASCII decimal BYTE length
// (not rune count). The separators are exactly one space each and there
// is no trailing separator after body.
func pae(payloadType string, body []byte) []byte {
	out := make([]byte, 0, len(paePrefix)+len(payloadType)+len(body)+32)
	out = append(out, paePrefix...)
	out = append(out, ' ')
	out = append(out, strconv.Itoa(len(payloadType))...)
	out = append(out, ' ')
	out = append(out, payloadType...)
	out = append(out, ' ')
	out = append(out, strconv.Itoa(len(body))...)
	out = append(out, ' ')
	out = append(out, body...)
	return out
}

// subjectDescriptor validates a Subject and converts it to a
// ResourceDescriptor. `what` names the field for the error message so a
// bad input attestation is distinguishable from a bad subject.
func subjectDescriptor(s Subject, what string) (resourceDescriptor, error) {
	if len(s.Digest) == 0 {
		return resourceDescriptor{}, fmt.Errorf("build statement: %s has an empty digest map", what)
	}
	strong := false
	for algo, hexVal := range s.Digest {
		if err := validateDigest(algo, hexVal); err != nil {
			return resourceDescriptor{}, fmt.Errorf("build statement: %s: %w", what, err)
		}
		if strongDigests[algo] {
			strong = true
		}
	}
	// A subject bound only by a weak or unrecognised algorithm is a
	// subject we cannot honestly claim to have identified. See
	// strongDigests.
	if !strong {
		return resourceDescriptor{}, fmt.Errorf(
			"build statement: %s carries no strong digest; need at least one of sha256/sha384/sha512/sha224/sha512224/sha512256", what)
	}
	// Copy so a later caller mutation cannot change what we validated.
	digest := make(map[string]string, len(s.Digest))
	for k, val := range s.Digest {
		digest[k] = val
	}
	return resourceDescriptor{Name: s.Name, Digest: digest}, nil
}

// validateDigest enforces the A4 shape: lowercase hex, no algorithm
// prefix, correct length for a known algorithm.
func validateDigest(algo, hexVal string) error {
	if algo == "" {
		return errors.New("digest has an empty algorithm key")
	}
	if hexVal == "" {
		return fmt.Errorf("digest %q is empty", algo)
	}
	// The algorithm key carries the algorithm; a ":" in either half
	// means someone passed "sha256:ab12..." and the digest would not
	// match what a verifier computes.
	if strings.Contains(algo, ":") || strings.Contains(hexVal, ":") {
		return fmt.Errorf("digest %q value %q carries an algorithm prefix; the map key already names the algorithm", algo, hexVal)
	}
	if !isLowerHex(hexVal) {
		return fmt.Errorf("digest %q value %q is not lowercase hex", algo, hexVal)
	}
	// The length table is keyed on an exact lowercase name, so a variant
	// key ("SHA256", "sha-256", "sha256 ") would miss it and fall
	// through to the permissive unknown-algorithm branch below — signing
	// a truncated digest as if it were valid. Refuse anything that is
	// not plain lowercase alphanumeric rather than trying to normalise
	// it, since a normalised key would also have to be written back into
	// the signed map.
	if !isLowerAlnum(algo) {
		return fmt.Errorf("digest algorithm %q must be lowercase alphanumeric", algo)
	}
	if want, known := digestHexLen[algo]; known {
		if len(hexVal) != want {
			return fmt.Errorf("digest %q has %d hex chars, want %d", algo, len(hexVal), want)
		}
		return nil
	}
	if len(hexVal)%2 != 0 {
		return fmt.Errorf("digest %q has an odd hex length %d", algo, len(hexVal))
	}
	return nil
}

func isLowerAlnum(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

func isLowerHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}
