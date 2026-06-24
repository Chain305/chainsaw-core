package blobstore

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var (
	// ErrBlobNotFound indicates the requested blob is missing.
	ErrBlobNotFound = errors.New("blob not found")
)

// FileBlobStore is a simple file-backed blob store analogous to Nexus' FileBlobStore.
type FileBlobStore struct {
	root string
}

// NewFileBlobStore creates (and ensures) the blob root directory.
func NewFileBlobStore(root string) (*FileBlobStore, error) {
	if root == "" {
		return nil, errors.New("blob store root is empty")
	}
	if err := os.MkdirAll(root, 0o755); err != nil {
		return nil, fmt.Errorf("ensure blob root: %w", err)
	}
	return &FileBlobStore{root: root}, nil
}

// BlobPath returns the absolute path of a logical artifact inside the blobstore.
func (b *FileBlobStore) BlobPath(repo, logicalPath string) (string, error) {
	repo = sanitizeRepoName(repo)
	if repo == "" {
		return "", errors.New("invalid repository name")
	}
	logicalPath = normalizeLogicalPath(logicalPath)
	if logicalPath == "" {
		return "", errors.New("invalid logical path")
	}
	shard := hashShard(logicalPath)
	return filepath.Join(b.root, repo, shard, filepath.FromSlash(logicalPath)), nil
}

// BlobPathForOrg returns the blob path scoped to an org identifier.
func (b *FileBlobStore) BlobPathForOrg(orgID, repo, logicalPath string) (string, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return b.BlobPath(repo, logicalPath)
	}
	repo = sanitizeRepoName(repo)
	if repo == "" {
		return "", errors.New("invalid repository name")
	}
	orgID = sanitizeRepoName(orgID)
	if orgID == "" {
		return "", errors.New("invalid org identifier")
	}
	logicalPath = normalizeLogicalPath(logicalPath)
	if logicalPath == "" {
		return "", errors.New("invalid logical path")
	}
	shard := hashShard(logicalPath)
	return filepath.Join(b.root, orgID, repo, shard, filepath.FromSlash(logicalPath)), nil
}

// RepoRoot returns the on-disk directory for a repository inside the blob store.
func (b *FileBlobStore) RepoRoot(repo string) (string, error) {
	repo = sanitizeRepoName(repo)
	if repo == "" {
		return "", errors.New("invalid repository name")
	}
	return filepath.Join(b.root, repo), nil
}

// RepoRootForOrg returns the on-disk directory for a repository scoped to an org.
func (b *FileBlobStore) RepoRootForOrg(orgID, repo string) (string, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return b.RepoRoot(repo)
	}
	repo = sanitizeRepoName(repo)
	if repo == "" {
		return "", errors.New("invalid repository name")
	}
	orgID = sanitizeRepoName(orgID)
	if orgID == "" {
		return "", errors.New("invalid org identifier")
	}
	return filepath.Join(b.root, orgID, repo), nil
}

// Write persists the content under the calculated blob path.
func (b *FileBlobStore) Write(repo, logicalPath string, src io.Reader) (*Blob, error) {
	return b.WriteForOrg("", repo, logicalPath, src)
}

// WriteForOrg persists content under the org-scoped blob path.
func (b *FileBlobStore) WriteForOrg(orgID, repo, logicalPath string, src io.Reader) (*Blob, error) {
	target, err := b.BlobPathForOrg(orgID, repo, logicalPath)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return nil, fmt.Errorf("ensure blob directories: %w", err)
	}
	tmp := target + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open temp blob: %w", err)
	}
	n, copyErr := io.Copy(f, src)
	closeErr := f.Close()
	if copyErr != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("write blob: %w", copyErr)
	}
	if closeErr != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("close temp blob: %w", closeErr)
	}
	if err := os.Rename(tmp, target); err != nil {
		os.Remove(tmp)
		return nil, fmt.Errorf("rename blob: %w", err)
	}
	return &Blob{Path: target, Size: n}, nil
}

// Open opens a blob for reading.
func (b *FileBlobStore) Open(path string) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrBlobNotFound
	}
	if err != nil {
		return nil, err
	}
	return f, nil
}

// Stat returns os.FileInfo for the provided blob path.
func (b *FileBlobStore) Stat(p string) (os.FileInfo, error) {
	info, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrBlobNotFound
	}
	return info, err
}

// RemoveCtx deletes the blob at the given filesystem path. Missing
// files are not an error — matches the cache-style semantics callers
// expect (idempotent removes).
func (b *FileBlobStore) RemoveCtx(_ context.Context, path string) error {
	if path == "" {
		return nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// ListCtx walks every regular file under the given filesystem prefix
// invoking fn for each entry. Hidden directories and metadata sidecar
// files (`.meta` suffix) are surfaced as-is; consumers filter as needed.
func (b *FileBlobStore) ListCtx(ctx context.Context, prefix string, fn func(BlobInfo) error) error {
	if prefix == "" {
		return errors.New("blobstore: empty list prefix")
	}
	if _, err := os.Stat(prefix); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	return filepath.WalkDir(prefix, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if errors.Is(walkErr, os.ErrNotExist) {
				return nil
			}
			return walkErr
		}
		if ctx != nil {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		if d == nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		return fn(BlobInfo{Key: path, Size: info.Size()})
	})
}

// Close releases backend resources. The file backend has none.
func (b *FileBlobStore) Close() error { return nil }

// Compile-time interface assertion.
var (
	_ BlobStore    = (*FileBlobStore)(nil)
	_ ContextStore = (*FileBlobStore)(nil)
)

// Blob describes a stored object.
type Blob struct {
	Path string
	Size int64
}

func hashShard(logicalPath string) string {
	sum := sha1.Sum([]byte(logicalPath))
	return filepath.Join(hex.EncodeToString(sum[:1]), hex.EncodeToString(sum[1:2]))
}

func sanitizeRepoName(name string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r
		case r >= 'A' && r <= 'Z':
			return r
		case r >= '0' && r <= '9':
			return r
		case r == '-' || r == '_':
			return r
		default:
			return '_'
		}
	}, name)
}

func normalizeLogicalPath(p string) string {
	if p == "" {
		return ""
	}
	p = path.Clean("/" + p)
	return strings.TrimPrefix(p, "/")
}
