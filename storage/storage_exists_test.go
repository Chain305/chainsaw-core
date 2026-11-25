package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"testing"
)

// Exists asks the blob store, not the metadata: a row whose blob is gone
// (a GC that removed bytes while a push wrote them, or a crash between the
// two removes) answers false and drops the row, so the next lookup misses.
func TestExistsDropsTheRowOfAMissingBlob(t *testing.T) {
	ls, _, _ := newHitStorage(t)
	ctx := WithOrg(context.Background(), "org-a")
	const p = "v2/team/app/blobs/sha256:abc"
	c, err := ls.Put(ctx, p, bytes.NewReader([]byte("layer")), ContentMetadata{Uploaded: true})
	if err != nil {
		t.Fatal(err)
	}
	if ok, err := c.Exists(); !ok || err != nil {
		t.Fatalf("positive control: Exists = %v, %v", ok, err)
	}
	if err := os.Remove(c.path); err != nil {
		t.Fatal(err)
	}
	c, err = ls.Get(ctx, p)
	if err != nil {
		t.Fatalf("test premise: the row is still there: %v", err)
	}
	if ok, err := c.Exists(); ok || err != nil {
		t.Fatalf("Exists of a missing blob = %v, %v; want false", ok, err)
	}
	if _, err := ls.Get(ctx, p); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after Exists found the blob gone: %v, want ErrNotFound", err)
	}
}
