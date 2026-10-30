package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Put records the digest of the bytes it stored (J.2 B3), and a metadata
// update that does not carry one keeps it: the bytes did not change.
func TestPutRecordsSHA256AndUpdateKeepsIt(t *testing.T) {
	s, _, _ := newHitStorage(t)
	ctx := context.Background()
	body := []byte("tarball bytes")
	sum := sha256.Sum256(body)
	want := hex.EncodeToString(sum[:])

	c, err := s.Put(ctx, "a/-/a-1.0.0.tgz", bytes.NewReader(body), ContentMetadata{SHA256: "caller-supplied-is-ignored"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Metadata.SHA256 != want {
		t.Fatalf("Put SHA256 = %q, want the stored bytes' digest %q", c.Metadata.SHA256, want)
	}
	if _, err := s.UpdateMetadata(ctx, "a/-/a-1.0.0.tgz", ContentMetadata{ContentType: "application/gzip"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, "a/-/a-1.0.0.tgz")
	if err != nil {
		t.Fatal(err)
	}
	if got.Metadata.SHA256 != want {
		t.Fatalf("after UpdateMetadata SHA256 = %q, want it kept (%q)", got.Metadata.SHA256, want)
	}
}
