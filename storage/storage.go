package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/blobstore"
	"github.com/chain305/chainsaw-core/tenancy"
)

// ErrNotFound is returned when an asset is not present locally.
var ErrNotFound = errors.New("cached content not found")

// ContentMetadata stores HTTP + package metadata for cached assets.
type ContentMetadata struct {
	LogicalPath     string `json:"logical_path"`
	ContentType     string `json:"content_type"`
	ContentEncoding string `json:"content_encoding"`
	ETag            string `json:"etag"`
	OriginURL       string `json:"origin_url"`
	PackageName     string `json:"package_name"`
	PackageVersion  string `json:"package_version"`
	// PackageSubtype mirrors common.PackageCoordinate.Subtype. Stable
	// values: "model", "dataset", "space", "agent-tool", "mcp-server",
	// "prompt-template". Empty for traditional ecosystems. Set by the
	// proxy facet from the resolver's coordinate output.
	PackageSubtype  string            `json:"package_subtype,omitempty"`
	ReleasedAt      time.Time         `json:"released_at"`
	CachedAt        time.Time         `json:"cached_at"`
	LastVerified    time.Time         `json:"last_verified"`
	Size            int64             `json:"size"`
	ClamAVScannedAt time.Time         `json:"clamav_scanned_at,omitempty"`
	ClamAVDBVersion string            `json:"clamav_db_version,omitempty"`
	ClamAVSHA256    string            `json:"clamav_sha256,omitempty"`
	ExtraHeaders    map[string]string `json:"extra_headers,omitempty"`
}

// CachedContent wraps a blob and its metadata.
type CachedContent struct {
	Metadata ContentMetadata
	path     string
	store    blobstore.BlobStore
}

// Open opens the underlying blob for reading.
func (c *CachedContent) Open() (io.ReadCloser, error) {
	return c.store.Open(c.path)
}

// NewCachedContentForTest returns a CachedContent wired to an
// arbitrary BlobStore implementation. Provided for external-package
// tests (e.g. internal/server/checksum_enforce_test.go) that need to
// stand up a CachedContent without mounting a full LocalStorage. The
// name deliberately carries the _for_test suffix so production code
// never reaches for it — the review rubric will flag it.
func NewCachedContentForTest(path string, meta ContentMetadata, store blobstore.BlobStore) *CachedContent {
	return &CachedContent{Metadata: meta, path: path, store: store}
}

// StorageFacet is the abstraction similar to Nexus StorageFacet.
type StorageFacet interface {
	Get(ctx context.Context, logicalPath string) (*CachedContent, error)
	Put(ctx context.Context, logicalPath string, src io.Reader, meta ContentMetadata) (*CachedContent, error)
	UpdateMetadata(ctx context.Context, logicalPath string, meta ContentMetadata) (*CachedContent, error)
	Remove(ctx context.Context, logicalPath string) error
	FindPathsByCoordinate(ctx context.Context, packageName, version string) ([]string, error)
}

// LocalStorage is a blobstore-backed StorageFacet implementation.
type LocalStorage struct {
	repo      string
	blobStore blobstore.BlobStore
	db        *sql.DB
	metaCache *MetadataCache
	metaStore MetaStore
}

// NewLocalStorage returns a storage facet for a repository. The
// metadata store defaults to the sidecar implementation, preserving
// the prior behaviour for file-backend deployments. Callers running
// against S3 (or that explicitly want Postgres-backed metadata)
// invoke [LocalStorage.SetMetaStore] before first use.
func NewLocalStorage(repo string, store blobstore.BlobStore, db ...*sql.DB) *LocalStorage {
	ls := &LocalStorage{
		repo:      repo,
		blobStore: store,
		metaCache: NewMetadataCache(defaultMetaCacheSize),
		metaStore: NewSidecarMetaStore(),
	}
	if len(db) > 0 && db[0] != nil {
		ls.db = db[0]
	}
	return ls
}

// SetMetaStore overrides the metadata backend. Pass nil to fall back
// to the sidecar default.
func (s *LocalStorage) SetMetaStore(ms MetaStore) {
	if s == nil {
		return
	}
	if ms == nil {
		s.metaStore = NewSidecarMetaStore()
		return
	}
	s.metaStore = ms
}

// Get loads a cached asset.
func (s *LocalStorage) Get(ctx context.Context, logicalPath string) (*CachedContent, error) {
	orgID := OrgFromContext(ctx)
	blobPath, err := s.blobStore.BlobPathForOrg(orgID, s.repo, logicalPath)
	if err != nil {
		return nil, err
	}
	if _, err := s.blobStore.Stat(blobPath); err != nil {
		if (errors.Is(err, blobstore.ErrBlobNotFound) || errors.Is(err, os.ErrNotExist)) && orgID == tenancy.DefaultOrgID {
			legacyPath, legacyErr := s.blobStore.BlobPath(s.repo, logicalPath)
			if legacyErr != nil {
				return nil, legacyErr
			}
			if _, legacyErr = s.blobStore.Stat(legacyPath); legacyErr == nil {
				blobPath = legacyPath
			} else if errors.Is(legacyErr, blobstore.ErrBlobNotFound) || errors.Is(legacyErr, os.ErrNotExist) {
				return nil, ErrNotFound
			} else {
				return nil, legacyErr
			}
		} else if errors.Is(err, blobstore.ErrBlobNotFound) || errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		} else {
			return nil, err
		}
	}
	// Check in-memory metadata cache before reading from the meta store.
	if s.metaCache != nil {
		if cached, ok := s.metaCache.Get(blobPath); ok {
			return &CachedContent{
				Metadata: cached,
				path:     blobPath,
				store:    s.blobStore,
			}, nil
		}
	}
	meta, ok, err := s.metaStore.Get(ctx, blobPath)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, ErrNotFound
	}
	if s.metaCache != nil {
		s.metaCache.Put(blobPath, meta)
	}
	return &CachedContent{
		Metadata: meta,
		path:     blobPath,
		store:    s.blobStore,
	}, nil
}

// Put persists a new blob + metadata.
func (s *LocalStorage) Put(ctx context.Context, logicalPath string, src io.Reader, meta ContentMetadata) (*CachedContent, error) {
	orgID := OrgFromContext(ctx)
	blob, err := s.blobStore.WriteForOrg(orgID, s.repo, logicalPath, src)
	if err != nil {
		return nil, err
	}
	meta.LogicalPath = logicalPath
	meta.Size = blob.Size
	if meta.CachedAt.IsZero() {
		meta.CachedAt = time.Now()
	}
	if err := s.metaStore.Put(ctx, blob.Path, orgID, s.repo, meta); err != nil {
		return nil, err
	}
	if s.metaCache != nil {
		s.metaCache.Put(blob.Path, meta)
	}
	return &CachedContent{
		Metadata: meta,
		path:     blob.Path,
		store:    s.blobStore,
	}, nil
}

// UpdateMetadata replaces the metadata sidecar for an existing cached blob.
func (s *LocalStorage) UpdateMetadata(ctx context.Context, logicalPath string, meta ContentMetadata) (*CachedContent, error) {
	orgID := OrgFromContext(ctx)
	blobPath, err := s.blobStore.BlobPathForOrg(orgID, s.repo, logicalPath)
	if err != nil {
		return nil, err
	}
	if _, err := s.blobStore.Stat(blobPath); err != nil {
		if (errors.Is(err, blobstore.ErrBlobNotFound) || errors.Is(err, os.ErrNotExist)) && orgID == tenancy.DefaultOrgID {
			legacyPath, legacyErr := s.blobStore.BlobPath(s.repo, logicalPath)
			if legacyErr != nil {
				return nil, legacyErr
			}
			if _, legacyErr = s.blobStore.Stat(legacyPath); legacyErr == nil {
				blobPath = legacyPath
			} else if errors.Is(legacyErr, blobstore.ErrBlobNotFound) || errors.Is(legacyErr, os.ErrNotExist) {
				return nil, ErrNotFound
			} else {
				return nil, legacyErr
			}
		} else if errors.Is(err, blobstore.ErrBlobNotFound) || errors.Is(err, os.ErrNotExist) {
			return nil, ErrNotFound
		} else {
			return nil, err
		}
	}
	meta.LogicalPath = logicalPath
	if meta.CachedAt.IsZero() {
		meta.CachedAt = time.Now()
	}
	if err := s.metaStore.Put(ctx, blobPath, orgID, s.repo, meta); err != nil {
		return nil, err
	}
	if s.metaCache != nil {
		s.metaCache.Put(blobPath, meta)
	}
	return &CachedContent{
		Metadata: meta,
		path:     blobPath,
		store:    s.blobStore,
	}, nil
}

// Remove deletes a cached artifact and its metadata if present.
func (s *LocalStorage) Remove(ctx context.Context, logicalPath string) error {
	orgID := OrgFromContext(ctx)
	blobPath, err := s.blobStore.BlobPathForOrg(orgID, s.repo, logicalPath)
	if err != nil {
		return err
	}
	if s.metaCache != nil {
		s.metaCache.Invalidate(blobPath)
	}
	if cs, ok := s.blobStore.(blobstore.ContextStore); ok {
		if err := cs.RemoveCtx(ctx, blobPath); err != nil {
			return fmt.Errorf("remove blob: %w", err)
		}
	} else if err := os.Remove(blobPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove blob: %w", err)
	}
	if err := s.metaStore.Delete(ctx, blobPath); err != nil {
		return fmt.Errorf("remove metadata: %w", err)
	}
	if orgID == tenancy.DefaultOrgID {
		legacyPath, legacyErr := s.blobStore.BlobPath(s.repo, logicalPath)
		if legacyErr != nil {
			return nil
		}
		if cs, ok := s.blobStore.(blobstore.ContextStore); ok {
			if err := cs.RemoveCtx(ctx, legacyPath); err != nil {
				return fmt.Errorf("remove legacy blob: %w", err)
			}
		} else if err := os.Remove(legacyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove legacy blob: %w", err)
		}
		if err := s.metaStore.Delete(ctx, legacyPath); err != nil {
			return fmt.Errorf("remove legacy metadata: %w", err)
		}
	}
	return nil
}

// FindPathsByCoordinate scans repository metadata for cached logical paths matching the package/version.
func (s *LocalStorage) FindPathsByCoordinate(ctx context.Context, packageName, version string) ([]string, error) {
	packageName = strings.TrimSpace(packageName)
	version = strings.TrimSpace(version)
	if packageName == "" || version == "" {
		return nil, errors.New("package name and version are required")
	}
	orgID := OrgFromContext(ctx)

	if s.db != nil {
		rows, err := s.db.QueryContext(ctx,
			`SELECT logical_paths FROM index_entries
			 WHERE org_id = ? AND repository = ?
			   AND LOWER(package) = LOWER(?) AND version = ?`,
			orgID, s.repo, packageName, version,
		)
		if err != nil {
			return nil, fmt.Errorf("query index_entries: %w", err)
		}
		defer rows.Close()
		var paths []string
		for rows.Next() {
			var lp string
			if err := rows.Scan(&lp); err != nil {
				return nil, fmt.Errorf("scan index_entries: %w", err)
			}
			for _, p := range strings.Split(lp, ",") {
				if t := strings.TrimSpace(p); t != "" {
					paths = append(paths, t)
				}
			}
		}
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("iterate index_entries: %w", err)
		}
		return uniqueStrings(paths), nil
	}

	// Without the index_entries DB row we fall back to scanning the
	// blob store. The local file backend supports this cheaply via
	// filepath.WalkDir; S3 backends can technically List but it's
	// expensive — operators running on S3 should always have an
	// index_entries DB row. We surface that requirement explicitly
	// when we detect an S3-style backend.
	if _, isContext := s.blobStore.(blobstore.ContextStore); isContext {
		if _, isFile := s.blobStore.(*blobstore.FileBlobStore); !isFile {
			return nil, errors.New("FindPathsByCoordinate without an index requires the file blob backend; populate index_entries for non-local backends")
		}
	}

	root, err := s.blobStore.RepoRootForOrg(orgID, s.repo)
	if err != nil {
		return nil, err
	}
	var matches []string
	scanRoot := func(target string) error {
		if _, err := os.Stat(target); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("stat repo root: %w", err)
		}
		return filepath.WalkDir(target, func(path string, d fs.DirEntry, walkErr error) error {
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
			if d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".meta") {
				return nil
			}
			metaPath := strings.TrimSuffix(path, ".meta")
			meta, err := readMetadata(metaPath)
			if err != nil {
				return nil
			}
			if meta.PackageName == "" || meta.PackageVersion == "" {
				return nil
			}
			if !strings.EqualFold(meta.PackageName, packageName) {
				return nil
			}
			if meta.PackageVersion != version {
				return nil
			}
			if meta.LogicalPath == "" {
				return nil
			}
			matches = append(matches, meta.LogicalPath)
			return nil
		})
	}
	if err := scanRoot(root); err != nil {
		return nil, fmt.Errorf("scan metadata: %w", err)
	}
	if orgID == tenancy.DefaultOrgID {
		if legacyRoot, legacyErr := s.blobStore.RepoRoot(s.repo); legacyErr == nil {
			if err := scanRoot(legacyRoot); err != nil {
				return nil, fmt.Errorf("scan legacy metadata: %w", err)
			}
		}
	}
	return uniqueStrings(matches), nil
}

// PurgeAll removes all cached blobs and metadata for this repository.
// It returns the count of removed files. Supports both file and S3
// backends — non-file backends route through ContextStore.ListCtx /
// RemoveCtx.
func (s *LocalStorage) PurgeAll(ctx context.Context) (int, error) {
	orgID := OrgFromContext(ctx)
	removed := 0

	purgeFile := func(root string) error {
		if _, err := os.Stat(root); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return fmt.Errorf("stat repo root: %w", err)
		}
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, _ error) error {
			if d != nil && !d.IsDir() && !strings.HasSuffix(d.Name(), ".meta") {
				removed++
				_ = s.metaStore.Delete(ctx, p)
			}
			return nil
		})
		if err := os.RemoveAll(root); err != nil {
			return fmt.Errorf("remove repo root: %w", err)
		}
		return os.MkdirAll(root, 0o755)
	}
	purgeRemote := func(prefix string, cs blobstore.ContextStore) error {
		var keys []string
		if err := cs.ListCtx(ctx, prefix, func(info blobstore.BlobInfo) error {
			if !strings.HasSuffix(info.Key, ".meta") {
				removed++
			}
			keys = append(keys, info.Key)
			return nil
		}); err != nil {
			return fmt.Errorf("list repo prefix: %w", err)
		}
		for _, k := range keys {
			if err := cs.RemoveCtx(ctx, k); err != nil {
				return fmt.Errorf("remove %s: %w", k, err)
			}
			_ = s.metaStore.Delete(ctx, k)
		}
		return nil
	}

	purge := func(root string) error {
		if cs, ok := s.blobStore.(blobstore.ContextStore); ok {
			if _, isFile := s.blobStore.(*blobstore.FileBlobStore); isFile {
				return purgeFile(root)
			}
			return purgeRemote(root, cs)
		}
		return purgeFile(root)
	}

	root, err := s.blobStore.RepoRootForOrg(orgID, s.repo)
	if err != nil {
		return 0, err
	}
	if err := purge(root); err != nil {
		return removed, err
	}

	if orgID == tenancy.DefaultOrgID {
		if legacyRoot, legacyErr := s.blobStore.RepoRoot(s.repo); legacyErr == nil {
			if err := purge(legacyRoot); err != nil {
				return removed, err
			}
		}
	}

	return removed, nil
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, exists := seen[v]; exists {
			continue
		}
		seen[v] = struct{}{}
		result = append(result, v)
	}
	return result
}

func metadataPath(blobPath string) string {
	return blobPath + ".meta"
}

func writeMetadata(blobPath string, meta ContentMetadata) error {
	payload, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("marshal metadata: %w", err)
	}
	metaPath := metadataPath(blobPath)
	if err := os.MkdirAll(filepath.Dir(metaPath), 0o755); err != nil {
		return fmt.Errorf("ensure metadata dir: %w", err)
	}
	return os.WriteFile(metaPath, payload, 0o644)
}

func readMetadata(blobPath string) (ContentMetadata, error) {
	metaPath := metadataPath(blobPath)
	b, err := os.ReadFile(metaPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return ContentMetadata{}, fmt.Errorf("metadata missing for %s: %w", blobPath, ErrNotFound)
		}
		return ContentMetadata{}, fmt.Errorf("read metadata: %w", err)
	}
	var meta ContentMetadata
	if err := json.Unmarshal(b, &meta); err != nil {
		return ContentMetadata{}, fmt.Errorf("parse metadata: %w", err)
	}
	return meta, nil
}
