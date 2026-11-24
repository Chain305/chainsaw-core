package intelligence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// TestSecurityGuard_ChecksumNotVerifiedFromOwnHash pins pentest #13's
// tautology: every caller fills ArtifactHandle.ComputedSHA256 with our own
// hash of the same bytes, so a checksum "verified" against it compared our
// hash with our hash and any bytes at all read as verified. Only a
// registry-declared digest may be the declared side.
func TestSecurityGuard_ChecksumNotVerifiedFromOwnHash(t *testing.T) {
	payload := []byte("attacker-controlled bytes")
	sum := sha256.Sum256(payload)
	own := hex.EncodeToString(sum[:])
	handle := func() *ArtifactHandle {
		return &ArtifactHandle{Bytes: payload, ComputedSHA256: own, Source: ArtifactSourcePublicRegistry}
	}

	for _, eco := range []string{"npm", "maven", "swift"} {
		t.Run(eco+": own hash is not a declaration", func(t *testing.T) {
			partial, err := newChecksumProvider().Run(context.Background(),
				Request{Key: Key{Ecosystem: eco, Package: "x", Version: "1.0.0"}, Artifact: handle()}, nil)
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if partial.Artifact != nil && (partial.Artifact.Digests.Verified || partial.Artifact.Digests.Declared != "") {
				t.Fatalf("checksum verified against our own hash: %+v", partial.Artifact.Digests)
			}
		})
	}

	// Positive control: a digest the REGISTRY declared still verifies, and a
	// wrong one is still a mismatch.
	registry := func(sha string) *Report {
		return &Report{Artifact: ArtifactSection{Digests: ArtifactDigest{SHA256: sha}}}
	}
	partial, err := newChecksumProvider().Run(context.Background(),
		Request{Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"}, Artifact: handle()}, registry(own))
	if err != nil || partial.Artifact == nil || !partial.Artifact.Digests.Verified {
		t.Fatalf("registry-declared matching digest must verify: %+v err=%v", partial.Artifact, err)
	}
	partial, err = newChecksumProvider().Run(context.Background(),
		Request{Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"}, Artifact: handle()},
		registry("00"+own[2:]))
	if err != nil || partial.Artifact == nil || partial.Artifact.Digests.Verified || len(partial.Warnings) != 1 {
		t.Fatalf("registry-declared wrong digest must be a mismatch: %+v warnings=%v err=%v",
			partial.Artifact, partial.Warnings, err)
	}
}
