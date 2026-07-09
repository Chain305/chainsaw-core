package sigstoreverify

import (
	"encoding/hex"
	"fmt"

	"github.com/sigstore/sigstore-go/pkg/bundle"
)

// parseBundle unmarshals a Sigstore bundle's JSON form. Shared by Verify,
// InspectBundleIdentity, and BundleSubjects so the parse-error message is
// consistent across the package.
func parseBundle(bundleJSON []byte) (*bundle.Bundle, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return nil, fmt.Errorf("parse sigstore bundle: %w", err)
	}
	return &b, nil
}

// Subject is one entry from an in-toto statement's subject list: a named
// artifact and its expected SHA-256 digest. OpenSSF model-signing v1
// bundles carry one subject per file in the signed repository.
type Subject struct {
	// Name is the subject name — for model-signing this is the repo-relative
	// file path (e.g. "model.safetensors", "config.json").
	Name string
	// SHA256 is the 32-byte SHA-256 digest the statement binds to Name.
	// Empty (nil) when the subject carries no sha256 digest.
	SHA256 []byte
}

// BundleSubjects parses a Sigstore bundle's DSSE envelope and returns the
// in-toto statement subjects it attests, WITHOUT running the cryptographic
// verify pipeline. This is the inline-statement path used by OpenSSF
// model-signing v1: the DSSE envelope payload IS the in-toto statement, so
// there is no separate manifest file to fetch. The returned subjects are
// INFORMATIONAL until a caller runs Verify against the trust root — parsing
// the payload proves nothing about authenticity on its own.
//
// A non-DSSE (message-signature) bundle, or a DSSE envelope that is not an
// in-toto statement, returns an error so callers can distinguish "wrong
// bundle shape" from "no subjects".
func BundleSubjects(bundleJSON []byte) ([]Subject, error) {
	b, err := parseBundle(bundleJSON)
	if err != nil {
		return nil, err
	}
	env, err := b.Envelope()
	if err != nil {
		return nil, fmt.Errorf("bundle envelope: %w", err)
	}
	stmt, err := env.Statement()
	if err != nil {
		return nil, fmt.Errorf("decode in-toto statement: %w", err)
	}
	subs := stmt.GetSubject()
	out := make([]Subject, 0, len(subs))
	for _, s := range subs {
		sub := Subject{Name: s.GetName()}
		if hexDigest, ok := s.GetDigest()["sha256"]; ok {
			raw, decErr := hex.DecodeString(hexDigest)
			if decErr == nil && len(raw) == 32 {
				sub.SHA256 = raw
			}
		}
		out = append(out, sub)
	}
	return out, nil
}
