package provenance

// Every docker attestation failure in the production corpus on 2026-09-24 — 76
// of them — was `resolve digest: HEAD manifest: HTTP 404`, because the stored
// version is the DASH spelling of the digest and the checker only recognised
// the colon one. It asked the registry for a tag literally named
// "sha256-8e37...", which does not exist. Verified against Docker Hub:
//
//	/v2/library/alpine/manifests/sha256-8e37848f...  404
//	/v2/library/alpine/manifests/sha256:8e37848f...  200

import (
	"context"
	"testing"
)

const alpineDigestHex = "8e37848f7b78cc19b37c74c616d919d8e50eb72f74dbc5f2c1f400debc97fae6"

// A dash digest must resolve WITHOUT a network call. The colon form already
// short-circuits; this proves the dash form does too, which is the fix.
func TestResolveDigestAcceptsTheDashSpelling(t *testing.T) {
	// NIL transport, deliberately. ociChecker.transport is a concrete
	// *OCITransport so it cannot be stubbed, but nil is the stronger
	// assertion anyway: if the short-circuit fails and this reaches the
	// network, it nil-panics and the test fails loudly rather than quietly
	// passing against a fake registry.
	c := &ociChecker{}

	got, err := c.resolveDigest(context.Background(), "", "library/alpine", "sha256-"+alpineDigestHex)
	if err != nil {
		t.Fatalf("dash digest did not resolve: %v", err)
	}
	if want := "sha256:" + alpineDigestHex; got != want {
		t.Errorf("got %q, want %q", got, want)
	}

	// Control: the colon form is unchanged.
	got, err = c.resolveDigest(context.Background(), "", "library/alpine", "sha256:"+alpineDigestHex)
	if err != nil || got != "sha256:"+alpineDigestHex {
		t.Errorf("colon digest regressed: %q, %v", got, err)
	}
}

// The pattern must be STRICT. cosign publishes its signature and attestation
// bundles at tags like "sha256-<digest>.sig" — those are real tags that must
// still be resolved over the network, not silently rewritten into a malformed
// digest reference.
func TestResolveDigestRejectsNonDigestTags(t *testing.T) {
	for _, ver := range []string{
		"sha256-" + alpineDigestHex + ".sig",
		"sha256-" + alpineDigestHex + ".att",
		"sha256-deadbeef",                     // too short
		"sha256-" + alpineDigestHex + "extra", // too long
		"sha256-" + "A" + alpineDigestHex[1:], // uppercase is not the canonical hex
		"latest",
		"3.19",
	} {
		if ociDigestTagRe.MatchString(ver) {
			t.Errorf("%q was treated as a digest; it is a tag and must be resolved over the "+
				"network, not rewritten", ver)
		}
	}
}
