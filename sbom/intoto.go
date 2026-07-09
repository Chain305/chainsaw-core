package sbom

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// CycloneDXPredicateType is the URI used in the in-toto Statement that
// wraps a CycloneDX SBOM. Matches the convention CycloneDX publishes for
// embedding BOMs in in-toto attestations; the version suffix matches our
// Generate() output (CycloneDX 1.6).
const CycloneDXPredicateType = "https://cyclonedx.org/bom/v1.6"

// InTotoStatement is the SLSA-style in-toto v1 envelope wrapping a SBOM
// (or any other predicate). Subject digest binds the attestation to the
// specific SBOM bytes; predicateType identifies what the predicate is;
// predicate is the BOM document itself, embedded inline.
//
// This is the structure that goes into a DSSE envelope's payload field
// before signing. The signing step (Sigstore keyless OIDC, key-based
// cosign, etc.) happens in the release pipeline (Phase 9) — chainsaw at
// runtime produces unsigned in-toto Statements and verifies signed
// envelopes when a verifier is wired.
type InTotoStatement struct {
	Type          string          `json:"_type"`
	Subject       []InTotoSubject `json:"subject"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
}

// InTotoSubject is a single (name, digest) pair the attestation binds to.
// CycloneDX SBOM attestations carry exactly one subject — the SBOM
// document itself. Multi-subject attestations are valid in the spec but
// not emitted by this wrapper.
type InTotoSubject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// WrapSBOMAsInToto produces an in-toto v1 Statement whose subject is the
// SHA-256 of the canonicalised SBOM bytes and whose predicate is the SBOM
// document itself. The returned bytes are ready to be base64-encoded and
// stuffed into a DSSE envelope's payload field.
//
// `subjectName` is a human-readable identifier (typically the artifact
// reference: "pkg:npm/lodash@4.17.21" or "chainsaw-1.2.0.tgz") that
// downstream tools surface when listing attestations. Empty is allowed
// — verifiers key off the digest, not the name.
//
// `bom` MUST be the CycloneDX 1.6 document produced by Generate. Other
// predicate types (SPDX, etc.) get their own wrapper.
func WrapSBOMAsInToto(bom *CycloneDXBOM, subjectName string) (*InTotoStatement, []byte, error) {
	if bom == nil {
		return nil, nil, errors.New("sbom: nil BOM")
	}
	bomJSON, err := json.Marshal(bom)
	if err != nil {
		return nil, nil, fmt.Errorf("sbom: marshal BOM: %w", err)
	}
	digest := sha256.Sum256(bomJSON)
	stmt := &InTotoStatement{
		Type: "https://in-toto.io/Statement/v1",
		Subject: []InTotoSubject{{
			Name:   subjectName,
			Digest: map[string]string{"sha256": hex.EncodeToString(digest[:])},
		}},
		PredicateType: CycloneDXPredicateType,
		Predicate:     bomJSON,
	}
	stmtJSON, err := json.Marshal(stmt)
	if err != nil {
		return nil, nil, fmt.Errorf("sbom: marshal statement: %w", err)
	}
	return stmt, stmtJSON, nil
}

// SBOMSubjectDigest returns the SHA-256 of canonicalised SBOM bytes. Same
// digest WrapSBOMAsInToto uses — exposed separately so callers (the
// `chainsaw sbom verify` CLI, the release pipeline) can re-derive it
// without re-marshalling the full statement.
func SBOMSubjectDigest(bom *CycloneDXBOM) ([32]byte, error) {
	if bom == nil {
		return [32]byte{}, errors.New("sbom: nil BOM")
	}
	bomJSON, err := json.Marshal(bom)
	if err != nil {
		return [32]byte{}, fmt.Errorf("sbom: marshal BOM: %w", err)
	}
	return sha256.Sum256(bomJSON), nil
}
