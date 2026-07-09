// Package blobstore defines the BlobStore abstraction used to persist
// cached package artifacts. The current implementation is a local
// filesystem store ([FileBlobStore]); alternative backends (S3,
// MinIO, Cloudflare R2, Backblaze B2, GCS S3-compat) plug in via the
// [BlobStore] interface and are selected at startup by [New].
//
// Default behaviour is unchanged: when no `CHAINSAW_BLOBSTORE_TYPE` env
// var is set the file backend is constructed and atomic tmp+rename
// writes are used exactly as before.
package blobstore

import (
	"context"
	"io"
	"os"
)

// BlobStore is the abstraction over physical blob storage. Every
// backend (file, S3, …) satisfies this interface. The methods that
// already exist on [FileBlobStore] keep their original signatures so
// the Phase 1 interface extraction is a pure refactor — no caller
// behaviour changes.
//
// Backends that don't naturally provide filesystem-style paths (S3
// returns object keys, not paths) treat the returned string as an
// opaque key. Consumers must NOT pass these strings to os.Open or
// other filesystem APIs directly — go through [BlobStore.Open] /
// [BlobStore.Stat] / [BlobStore.Remove] instead.
type BlobStore interface {
	// BlobPath returns the canonical key/path of a logical artifact.
	// File backend: absolute filesystem path. S3 backend: object key.
	BlobPath(repo, logicalPath string) (string, error)
	// BlobPathForOrg returns the org-scoped variant of [BlobPath].
	BlobPathForOrg(orgID, repo, logicalPath string) (string, error)

	// RepoRoot returns the repository's root key/prefix.
	RepoRoot(repo string) (string, error)
	// RepoRootForOrg returns the org-scoped variant of [RepoRoot].
	RepoRootForOrg(orgID, repo string) (string, error)

	// Write streams content to the canonical (non-org) key for backwards
	// compatibility with seed data.
	Write(repo, logicalPath string, src io.Reader) (*Blob, error)
	// WriteForOrg streams content to the org-scoped key. Atomic on the
	// file backend (tmp+rename); atomic per-object on S3.
	WriteForOrg(orgID, repo, logicalPath string, src io.Reader) (*Blob, error)

	// Open returns a reader for the blob at the given key/path.
	// Returns [ErrBlobNotFound] when the object is missing.
	Open(path string) (io.ReadCloser, error)
	// Stat returns metadata for the blob at the given key/path.
	// Returns [ErrBlobNotFound] when the object is missing.
	Stat(path string) (os.FileInfo, error)
}

// ContextStore is an optional extension implemented by backends that
// support cancellable I/O (S3 in particular). The file backend ignores
// the context; the S3 backend honours it. Consumers should prefer
// these methods when a request context is available.
type ContextStore interface {
	BlobStore

	// RemoveCtx deletes the blob at the given key/path. Idempotent —
	// returns nil if the object is already gone.
	RemoveCtx(ctx context.Context, path string) error

	// ListCtx walks every blob under the given key/prefix, invoking fn
	// for each entry. Returning a non-nil error from fn aborts the walk.
	// Backends paginate internally; the caller never sees the page boundary.
	ListCtx(ctx context.Context, prefix string, fn func(BlobInfo) error) error
}

// BlobInfo is the metadata returned by [ContextStore.ListCtx]. It is
// deliberately small — full attributes require a Stat call.
type BlobInfo struct {
	// Key is the opaque storage key (filesystem path or S3 key).
	Key string
	// Size is the object size in bytes.
	Size int64
}

// Observer receives per-operation telemetry from blob-store backends
// that support it. Passing nil disables observation (the S3 backend
// checks for nil before every call).
//
// Implementations typically live in the observability package and
// record to Prometheus counters / histograms.
type Observer interface {
	// ObserveOp is called once per completed blob-store operation.
	// op is one of "get", "put", "delete", "stat", "list".
	// outcome is one of "ok", "not_found", "error".
	ObserveOp(op, outcome string, duration float64)
}
