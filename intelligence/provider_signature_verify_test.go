package intelligence

import (
	"context"
	"testing"
)

// TestSignatureVerifyProjectsVerifiedSigstore confirms the basic happy
// path: a Tier-1 Provenance verdict of Verified=true, Kind="sigstore"
// projects to Artifact.SignatureVerified=&true with Kind="sigstore"
// and a non-empty KeyID surfaced from BuilderID.
func TestSignatureVerifyProjectsVerifiedSigstore(t *testing.T) {
	prior := &Report{
		Provenance: ProvenanceSection{
			Kind:      "sigstore",
			Status:    "verified",
			Verified:  true,
			Available: true,
			BuilderID: "https://github.com/actions/runner",
		},
	}
	req := Request{Key: Key{Ecosystem: "npm", Package: "@x/y", Version: "1.0.0"}}
	out, err := newSignatureVerifyProvider().Run(context.Background(), req, prior)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Artifact == nil {
		t.Fatal("expected Artifact patch")
	}
	if out.Artifact.SignatureVerified == nil {
		t.Fatal("SignatureVerified must be non-nil for verified sigstore prior")
	}
	if !*out.Artifact.SignatureVerified {
		t.Fatal("SignatureVerified should be true")
	}
	if out.Artifact.SignatureKind != "sigstore" {
		t.Errorf("SignatureKind = %q, want sigstore", out.Artifact.SignatureKind)
	}
	if out.Artifact.SignatureKeyID == "" {
		t.Error("SignatureKeyID should be populated from BuilderID")
	}

	// Merge round-trip: confirm mergeArtifact correctly applies the
	// pointer field so downstream consumers see the projected verdict.
	merged := *prior
	mergeArtifact(&merged.Artifact, *out.Artifact)
	if merged.Artifact.SignatureVerified == nil || !*merged.Artifact.SignatureVerified {
		t.Fatal("post-merge SignatureVerified must be &true")
	}
	if merged.Artifact.SignatureKind != "sigstore" {
		t.Errorf("post-merge SignatureKind = %q", merged.Artifact.SignatureKind)
	}
}

// TestSignatureVerifyProjectsFailedSigstore covers the second leg of
// the three-state contract: a Provenance verdict that found a bundle
// but failed verification produces SignatureVerified=&false (not nil).
func TestSignatureVerifyProjectsFailedSigstore(t *testing.T) {
	prior := &Report{
		Provenance: ProvenanceSection{
			Kind:      "sigstore",
			Status:    "failed",
			Verified:  false,
			Available: true,
		},
	}
	req := Request{Key: Key{Ecosystem: "npm", Package: "@x/y", Version: "1.0.0"}}
	out, err := newSignatureVerifyProvider().Run(context.Background(), req, prior)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Artifact == nil {
		t.Fatal("expected Artifact patch even for failed verification")
	}
	if out.Artifact.SignatureVerified == nil {
		t.Fatal("SignatureVerified must be &false (not nil) when a sig was present but failed")
	}
	if *out.Artifact.SignatureVerified {
		t.Fatal("SignatureVerified should be false for a failed verification")
	}
}

// TestSignatureVerifyLeavesNilWhenUnavailable confirms the
// "no signature available" leg: ecosystems / versions where Provenance
// returned StatusUnavailable produce no Artifact patch and the new
// fields stay nil end-to-end. This is the common case for cargo /
// composer / cocoapods today.
func TestSignatureVerifyLeavesNilWhenUnavailable(t *testing.T) {
	cases := []struct {
		name string
		prov ProvenanceSection
	}{
		{"unavailable", ProvenanceSection{Kind: "sigstore", Status: "unavailable"}},
		{"missing", ProvenanceSection{Kind: "sigstore", Status: "missing"}},
		{"empty-kind", ProvenanceSection{Status: "verified"}},
		{"completely-empty", ProvenanceSection{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prior := &Report{Provenance: tc.prov}
			req := Request{Key: Key{Ecosystem: "cargo", Package: "x", Version: "1.0.0"}}
			out, err := newSignatureVerifyProvider().Run(context.Background(), req, prior)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if out.Artifact != nil {
				t.Fatalf("expected nil Artifact patch, got %+v", out.Artifact)
			}
			// Three-state contract: the nil pointer is the load-bearing
			// signal that "we don't know whether a signature exists".
			if prior.Artifact.SignatureVerified != nil {
				t.Fatal("prior SignatureVerified must remain nil when Provenance is unavailable")
			}
		})
	}
}

// TestSignatureVerifyMapsPGPKinds confirms the pgp-family normalisation:
// any of pgp-commit / gpg-detached / pgp etc. all project to "pgp" so
// policy authors don't have to switch on the fine-grained taxonomy.
func TestSignatureVerifyMapsPGPKinds(t *testing.T) {
	for _, kind := range []string{"pgp-commit", "gpg-commit", "pgp-detached", "gpg-detached", "pgp", "gpg"} {
		prior := &Report{
			Provenance: ProvenanceSection{
				Kind:     kind,
				Status:   "verified",
				Verified: true,
				SignerID: "0xDEADBEEF",
			},
		}
		req := Request{Key: Key{Ecosystem: "rubygems", Package: "x", Version: "1.0.0"}}
		out, err := newSignatureVerifyProvider().Run(context.Background(), req, prior)
		if err != nil {
			t.Fatalf("Run(%q): %v", kind, err)
		}
		if out.Artifact == nil || out.Artifact.SignatureKind != "pgp" {
			t.Errorf("kind %q: want SignatureKind=pgp, got %+v", kind, out.Artifact)
		}
	}
}

// TestSignatureVerifyNoOpOnNilPrior is the standard defence — no prior
// means we have nothing to project and the enricher must not panic.
func TestSignatureVerifyNoOpOnNilPrior(t *testing.T) {
	out, err := newSignatureVerifyProvider().Run(context.Background(), Request{}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if out.Artifact != nil {
		t.Fatal("nil prior must short-circuit to empty patch")
	}
}

// TestSignatureVerifyTier locks the placement at Tier-3 — the whole
// design depends on running after the merge so prior.Provenance is
// populated by Tier-1.
func TestSignatureVerifyTier(t *testing.T) {
	if got := newSignatureVerifyProvider().Tier(); got != 3 {
		t.Fatalf("Tier() = %d, want 3 (post-merge enricher)", got)
	}
}
