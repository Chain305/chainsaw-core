package intelligence

// signatureVerifyProvider is a Tier-3 post-merge enricher that projects
// the upstream-signature verdict produced by the Tier-1 Provenance
// provider (internal/provenance.CheckWithSource) onto three new fields
// on ArtifactSection:
//
//   - SignatureVerified *bool — three-state. nil = no signature was
//     available for this ecosystem / version (don't penalise; very
//     common today). true = signature present and verified against an
//     independent trust root. false = signature present but failed.
//   - SignatureKind string — "sigstore" | "pgp" | "" (unknown).
//   - SignatureKeyID string — verifying identity when known
//     (sigstore SignerID / BuilderID; PGP fingerprint when wired).
//
// Why this lives in Tier-3, not Tier-2:
//
// The legacy Checksum provider (provider_checksum.go) is Tier-2 — it
// runs in parallel with Tier-1 Provenance and therefore cannot read
// the merged ProvenanceSection. The whole point of this enricher is
// to surface what Provenance already verified, so it must run after
// the merge. Tier-3 is exactly that vantage point.
//
// Why this is "real" verification (vs. the digest comparison):
//
// provider_checksum.go compares declared digest against actual digest.
// Both halves come from data the attacker controls (registry response
// + tarball bytes), so the check is a bit-flip canary, not a security
// boundary. By contrast, internal/provenance verifies a signature
// against an independent trust root (Sigstore Fulcio / Rekor; in the
// future, PGP keyservers). The verdict it produces is the real
// cryptographic boundary for the artifact, and this enricher exposes
// it on Artifact so policy rules and TrustScore can reference it
// uniformly.
//
// Coverage matrix (today):
//
//   - npm:        sigstore (npm attestations endpoint).
//   - pypi/pip:   sigstore via PEP 740 — covered by Provenance when
//                 the registry response includes a bundle. Where it
//                 doesn't, SignatureVerified stays nil (correct).
//   - maven:      sigstore (.sigstore.json sidecar, opt-in) AND PGP
//                 detached (.asc, mandatory on Central) — both wired
//                 via internal/provenance/maven.go +
//                 internal/provenance/pgpverify. AttestationType
//                 "pgp-detached" lands on the "pgp" trust story below.
//   - gradle:     same checker as maven (registered as both ecosystems).
//   - rubygems:   sigstore where present; legacy `gem cert` X.509
//                 detached-signature flow (RSA-SHA256/SHA1 over
//                 metadata.gz / data.tar.gz / checksums.yaml.gz)
//                 wired via internal/provenance/x509rubygems.go.
//                 AttestationType "x509-gemcert" maps to the "x509"
//                 trust story below.
//   - cargo / composer / cocoapods / swift: presence-only formats or
//                 no standardised attestation channel; Provenance
//                 returns StatusUnavailable and SignatureVerified
//                 stays nil — correct three-state behaviour.
//
// Trust note for "x509" (rubygems gem-cert): the cert is gem-bundled
// and self-issued — verification proves the bytes match the cert that
// shipped with the gem, NOT that the cert is endorsed by any external
// authority. Operators who want continuity-of-identity must pin
// SignerID (the SHA-256 of the cert's DER) across versions.
//
// TODO(rubygems-cert-registry): validate the gem-cert chain against
// rubygems.org's known signing keys when that registry exists. Today
// it does not, which is why we surface a Warning on every successful
// gem-cert verification.
//
// Pure post-merge composition: no network, no crypto, no external
// lookups. Degrades to a no-op when Provenance is unavailable.

import (
	"context"
)

type signatureVerifyProvider struct{}

func newSignatureVerifyProvider() *signatureVerifyProvider {
	return &signatureVerifyProvider{}
}

func (p *signatureVerifyProvider) Name() string { return "signature_verify" }

// Reuse SignalChecksum: the closure-of-the-circular-verification gap is
// directly adjacent to the Checksum signal — operators who toggle
// "checksum" expect to see the upstream-signature projection alongside
// it. Adding a new bit would force every existing policy to opt in.
func (p *signatureVerifyProvider) Signal() SignalMask { return SignalChecksum }

func (p *signatureVerifyProvider) Tier() int { return 3 }

func (p *signatureVerifyProvider) NeedsArtifact() bool { return false }

// Supports returns true universally — for ecosystems where Provenance
// returns StatusUnavailable, the enricher emits no patch (the new
// fields stay nil) and the caller cannot tell it ran. This avoids a
// "supported list" that has to track the Provenance package's coverage.
func (p *signatureVerifyProvider) Supports(ecosystem string) bool {
	return true
}

// Run reads the merged ProvenanceSection and emits an Artifact patch
// with the three signature fields populated.
//
// Mapping:
//
//   - Status == "verified"  → SignatureVerified = &true
//   - Status == "failed"    → SignatureVerified = &false
//   - Status == "unverified" with Available == true and Kind != ""
//     → SignatureVerified = &false (a signature
//     was present but not validated; treat as
//     "present-but-failed" for the three-state)
//   - anything else (unavailable, missing, empty, no-Kind)
//     → no patch, fields stay nil
//
// SignatureKind is normalised to the user-facing taxonomy ("sigstore"
// or "pgp") because internal/provenance ships several finer-grained
// labels ("pgp-commit", "gpg-commit", "gpg-detached", future
// "pgp-detached") that all collapse to the same trust story for policy
// authors.
func (p *signatureVerifyProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if prior == nil {
		return PartialReport{}, nil
	}
	prov := prior.Provenance

	// "Unavailable" / "missing" / empty Kind: no signature data exists
	// for this ecosystem+version. Three-state contract: leave nil.
	if prov.Kind == "" {
		return PartialReport{}, nil
	}
	switch prov.Status {
	case "unavailable", "missing", "":
		return PartialReport{}, nil
	}

	kind := normaliseSignatureKind(prov.Kind)
	if kind == "" {
		// Unknown taxonomy entry (e.g. a presence-only format we don't
		// model as a "real" signature). Stay nil rather than lie.
		return PartialReport{}, nil
	}

	var verified bool
	switch prov.Status {
	case "verified":
		verified = true
	case "failed":
		verified = false
	case "unverified":
		// Signature was observed but not validated — surface as
		// failed for the three-state. Distinguishing "unverified" from
		// "failed" is a Provenance-section concern; for the Artifact
		// projection both mean "don't trust this".
		verified = false
	default:
		// Forward-compatible: any new Status string the Provenance
		// package introduces falls through to "don't project".
		return PartialReport{}, nil
	}

	keyID := prov.SignerID
	if keyID == "" {
		// Builder identity is the next-best handle for sigstore
		// attestations produced by GitHub Actions / GitLab CI —
		// SignerID is sometimes empty in those bundles.
		keyID = prov.BuilderID
	}

	patch := &ArtifactSection{
		SignatureVerified: &verified,
		SignatureKind:     kind,
		SignatureKeyID:    keyID,
	}
	return PartialReport{Artifact: patch}, nil
}

// normaliseSignatureKind collapses internal/provenance's fine-grained
// AttestationType labels into the trust stories policy authors care
// about: sigstore (Fulcio + Rekor + Cosign-style bundles), pgp (any
// GPG-keyring-rooted signature), and x509 (RubyGems gem-cert — a
// gem-bundled self-issued cert with detached RSA signatures; a
// separate trust story because it has no external root). Returns ""
// for kinds that are presence-only or not yet a "real" signature
// (sumdb is a transparency log, not a signature; cms-se0391 is
// Swift's CMS shape — verification semantics differ enough that we
// leave it unmapped for now and let policy reference Provenance.Kind
// directly when it cares).
func normaliseSignatureKind(provKind string) string {
	switch provKind {
	case "sigstore":
		return "sigstore"
	case "pgp", "pgp-commit", "pgp-detached", "gpg", "gpg-commit", "gpg-detached":
		return "pgp"
	case "x509-gemcert", "x509-gem-cert", "x509":
		return "x509"
	default:
		return ""
	}
}

var _ Provider = (*signatureVerifyProvider)(nil)
