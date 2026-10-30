package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// Get decides existence from metadata, so purging must evict the in-memory
// metadata cache too; a cached row would make purged bytes look present.
func TestPurgeAllEvictsCachedMetadata(t *testing.T) {
	ls, _, _ := newHitStorage(t)
	ctx := WithOrg(context.Background(), "org-a")
	if _, err := ls.Put(ctx, "pkg/-/pkg-1.0.0.tgz", bytes.NewReader([]byte("x")), ContentMetadata{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ls.Get(ctx, "pkg/-/pkg-1.0.0.tgz"); err != nil {
		t.Fatal(err)
	}
	if _, err := ls.PurgeAll(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := ls.Get(ctx, "pkg/-/pkg-1.0.0.tgz"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after PurgeAll: %v, want ErrNotFound", err)
	}
}
