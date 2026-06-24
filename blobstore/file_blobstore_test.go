package blobstore

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestFileBlobStoreRoundTrip(t *testing.T) {
	store, err := NewFileBlobStore(t.TempDir())
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer store.Close()

	blob, err := store.Write("npm-proxy", "lodash/-/lodash-4.17.21.tgz", strings.NewReader("hello"))
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if blob.Size != 5 {
		t.Fatalf("expected size 5, got %d", blob.Size)
	}

	rc, err := store.Open(blob.Path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer rc.Close()
	body, _ := io.ReadAll(rc)
	if string(body) != "hello" {
		t.Fatalf("unexpected body: %q", body)
	}

	if _, err := store.Stat(blob.Path); err != nil {
		t.Fatalf("stat: %v", err)
	}

	if err := store.RemoveCtx(context.Background(), blob.Path); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := store.Stat(blob.Path); !errors.Is(err, ErrBlobNotFound) {
		t.Fatalf("expected ErrBlobNotFound after remove, got %v", err)
	}
	// Idempotent remove.
	if err := store.RemoveCtx(context.Background(), blob.Path); err != nil {
		t.Fatalf("idempotent remove: %v", err)
	}
}

func TestFileBlobStoreOrgScoped(t *testing.T) {
	store, _ := NewFileBlobStore(t.TempDir())
	defer store.Close()
	a, _ := store.WriteForOrg("orgA", "npm", "x.tgz", strings.NewReader("A"))
	b, _ := store.WriteForOrg("orgB", "npm", "x.tgz", strings.NewReader("B"))
	if a.Path == b.Path {
		t.Fatalf("org-scoped paths collided: %s", a.Path)
	}
}

func TestFileBlobStoreFactory(t *testing.T) {
	bs, err := New(Config{File: FileConfig{Root: t.TempDir()}}, nil)
	if err != nil {
		t.Fatalf("factory file: %v", err)
	}
	if _, ok := bs.(*FileBlobStore); !ok {
		t.Fatalf("default factory must return *FileBlobStore, got %T", bs)
	}
}

func TestFactoryRejectsUnknownType(t *testing.T) {
	if _, err := New(Config{Type: "magnetictape"}, nil); err == nil {
		t.Fatal("expected error for unknown backend type")
	}
}
