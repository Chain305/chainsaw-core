package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
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
	PackageSubtype string    `json:"package_subtype,omitempty"`
	ReleasedAt     time.Time `json:"released_at"`
	CachedAt       time.Time `json:"cached_at"`
	LastVerified   time.Time `json:"last_verified"`
	Size           int64     `json:"size"`
	// SHA256 is the hex digest of the stored bytes, computed as Put writes
	// them. Empty on rows written before it existed.
	SHA256          string            `json:"sha256,omitempty"`
	ClamAVScannedAt time.Time         `json:"clamav_scanned_at,omitempty"`
	ClamAVDBVersion string            `json:"clamav_db_version,omitempty"`
	ClamAVSHA256    string            `json:"clamav_sha256,omitempty"`
	ExtraHeaders    map[string]string `json:"extra_headers,omitempty"`
	// Unverified marks an artifact the proxy facet stored from upstream
	// that no request has verified yet (checksum). The facet answers a
	// cache hit on it as not-from-cache, so the request verifies it
	// rather than taking the cache-hit shortcut; the server clears the
	// mark once verification passes. Without it a request arriving
	// while the first one was still verifying was served the bytes.
	Unverified bool `json:"unverified,omitempty"`
}

// CachedContent wraps a blob and its metadata.
type CachedContent struct {
	Metadata ContentMetadata
	path     string
	store    blobstore.BlobStore
	// onMissing, when set, is called once Open finds the blob gone.
	onMissing func()
	// data, when non-nil, is served instead of the blob (NewInMemoryContent).
	data []byte
	// tier, when set and Metadata.SHA256 is known, is read before the blob
	// store and filled from it.
	tier *DiskTier
	// file, when set, is a local spool served instead of the blob
	// (LocalStorage.PutOrSpool).
	file string
	// ops counts this content's blob-store reads for the request that
	// looked it up (nil: not counted).
	ops *BlobOps
	// learnSHA, when set, records the digest of a legacy entry (no
	// Metadata.SHA256) after its first full read, so the tier can hold it.
	learnSHA func(sha string)
}

// NewInMemoryContent returns content served from data rather than a stored
// blob. Used for a per-request transform of a cached response, which used to
// be written back to the blob store on every cache hit.
func NewInMemoryContent(meta ContentMetadata, data []byte) *CachedContent {
	meta.Size = int64(len(data))
	return &CachedContent{Metadata: meta, data: data}
}

// Open opens the underlying blob for reading.
func (c *CachedContent) Open() (io.ReadCloser, error) {
	if c.data != nil {
		return io.NopCloser(bytes.NewReader(c.data)), nil
	}
	if c.file != "" {
		return os.Open(c.file)
	}
	sha := c.Metadata.SHA256
	if c.tier != nil && sha != "" {
		if rc, ok := c.tier.open(c.path, sha); ok {
			return rc, nil
		}
	}
	c.ops.get()
	rc, err := c.store.Open(c.path)
	if err != nil && c.onMissing != nil && (errors.Is(err, blobstore.ErrBlobNotFound) || errors.Is(err, os.ErrNotExist)) {
		c.onMissing()
	}
	if err == nil && c.tier != nil && sha != "" {
		rc = c.tier.fill(c.path, sha, rc)
	} else if err == nil && c.tier != nil && c.learnSHA != nil {
		rc = c.tier.learn(c.path, c.Metadata.Size, rc, c.learnSHA)
	}
	return rc, err
}

// OpenAt opens the content positioned at offset, for serving a client Range.
// A disk-tier or spool copy is seeked, and a blob store that supports it is
// asked for the range directly (an S3 ranged GET), so the bytes before
// offset are not transferred. Otherwise the prefix is read and discarded.
//
// A ranged read of a tier copy is not digest-checked: only a full read can
// be. The copy was checked when it was written, and a full read checks it
// again.
func (c *CachedContent) OpenAt(offset int64) (io.ReadCloser, error) {
	switch {
	case offset <= 0:
		return c.Open()
	case c.data != nil:
		return io.NopCloser(bytes.NewReader(c.data[min(offset, int64(len(c.data))):])), nil
	case c.file != "":
		return openFileAt(c.file, offset)
	}
	if c.tier != nil && c.Metadata.SHA256 != "" {
		if rc, ok := c.tier.openAt(c.path, c.Metadata.SHA256, offset); ok {
			return rc, nil
		}
	}
	if ro, ok := c.store.(blobstore.RangeOpener); ok {
		c.ops.get()
		rc, err := ro.OpenRange(c.path, offset)
		if err != nil && c.onMissing != nil && (errors.Is(err, blobstore.ErrBlobNotFound) || errors.Is(err, os.ErrNotExist)) {
			c.onMissing()
		}
		return rc, err
	}
	rc, err := c.Open()
	if err != nil {
		return nil, err
	}
	if _, err := io.CopyN(io.Discard, rc, offset); err != nil {
		rc.Close()
		return nil, err
	}
	return rc, nil
}

func openFileAt(path string, offset int64) (io.ReadCloser, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
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
	tier      *DiskTier
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

// SetDiskTier puts a local-disk cache in front of the blob store. Nil turns
// it off.
func (s *LocalStorage) SetDiskTier(t *DiskTier) {
	if s != nil {
		s.tier = t
	}
}

// Get loads a cached asset.
//
// Existence is decided by the metadata row, not by asking the blob store:
// Put writes the blob before the row and Remove deletes the row after the
// blob, so a row means the bytes were stored. The Stat this replaces was an
// S3 HEAD on every cache hit (p50 256 ms, p90 1.9 s on Contabo, and the
// first call to be throttled under load). If the bytes turn out to be gone
// anyway, CachedContent.Open drops the row so the next request refetches.
func (s *LocalStorage) Get(ctx context.Context, logicalPath string) (*CachedContent, error) {
	orgID := OrgFromContext(ctx)
	blobPath, meta, err := s.lookup(ctx, orgID, logicalPath)
	if err != nil {
		return nil, err
	}
	return s.content(ctx, blobPath, meta), nil
}

// lookup resolves logicalPath to its blob key and metadata, falling back to
// the pre-tenancy key for the default org. ErrNotFound when neither has a row.
func (s *LocalStorage) lookup(ctx context.Context, orgID, logicalPath string) (string, ContentMetadata, error) {
	blobPath, err := s.blobStore.BlobPathForOrg(orgID, s.repo, logicalPath)
	if err != nil {
		return "", ContentMetadata{}, err
	}
	meta, ok, err := s.readMeta(ctx, blobPath)
	if err != nil {
		return "", ContentMetadata{}, err
	}
	if ok {
		return blobPath, meta, nil
	}
	if orgID == tenancy.DefaultOrgID {
		legacyPath, err := s.blobStore.BlobPath(s.repo, logicalPath)
		if err != nil {
			return "", ContentMetadata{}, err
		}
		meta, ok, err := s.readMeta(ctx, legacyPath)
		if err != nil {
			return "", ContentMetadata{}, err
		}
		if ok {
			return legacyPath, meta, nil
		}
	}
	return "", ContentMetadata{}, ErrNotFound
}

// readMeta reads a blob's metadata through the in-memory cache.
func (s *LocalStorage) readMeta(ctx context.Context, blobPath string) (ContentMetadata, bool, error) {
	if s.metaCache != nil {
		if cached, ok := s.metaCache.Get(blobPath); ok {
			return cached, true, nil
		}
	}
	meta, ok, err := s.metaStore.Get(ctx, blobPath)
	if err != nil || !ok {
		return ContentMetadata{}, false, err
	}
	if s.metaCache != nil {
		s.metaCache.Put(blobPath, meta)
	}
	return meta, true, nil
}

// dropMeta deletes a blob's metadata row AND its in-memory cache entry.
// Since Get decides existence from metadata, a row (or cached copy of one)
// left behind after its blob is removed makes the blob look present.
func (s *LocalStorage) dropMeta(ctx context.Context, blobPath string) {
	if s.metaCache != nil {
		s.metaCache.Invalidate(blobPath)
	}
	if s.tier != nil {
		s.tier.drop(blobPath)
	}
	_ = s.metaStore.Delete(ctx, blobPath)
}

// content builds a CachedContent whose Open drops the metadata row when the
// blob it points at is missing, so a stale row costs one failed request
// rather than every request until it is noticed.
func (s *LocalStorage) content(ctx context.Context, blobPath string, meta ContentMetadata) *CachedContent {
	return &CachedContent{
		Metadata: meta,
		path:     blobPath,
		store:    s.blobStore,
		tier:     s.tier,
		ops:      blobOpsFrom(ctx),
		onMissing: func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s.dropMeta(ctx, blobPath)
		},
		learnSHA: func(sha string) {
			ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			defer cancel()
			s.recordSHA(ctx, blobPath, sha)
		},
	}
}

// recordSHA stores the digest learned from a legacy entry's first full
// read. It reads the row again rather than writing the caller's copy, so a
// concurrent CachedAt refresh is not rolled back, and it never overwrites a
// digest already recorded.
func (s *LocalStorage) recordSHA(ctx context.Context, blobPath, sha string) {
	meta, ok, err := s.metaStore.Get(ctx, blobPath)
	if err != nil || !ok || meta.SHA256 != "" {
		return
	}
	meta.SHA256 = sha
	if err := s.metaStore.Put(ctx, blobPath, OrgFromContext(ctx), s.repo, meta); err != nil {
		return
	}
	if s.metaCache != nil {
		s.metaCache.Put(blobPath, meta)
	}
}

// Put persists a new blob + metadata.
func (s *LocalStorage) Put(ctx context.Context, logicalPath string, src io.Reader, meta ContentMetadata) (*CachedContent, error) {
	c, _, err := s.put(ctx, logicalPath, src, meta, false)
	return c, err
}

// PutOrSpool is Put for a proxy fill, whose bytes can be fetched again: when
// the blob store write fails and a disk tier is configured, it reads the
// rest of src into the tier and serves that copy instead of failing the
// download. No metadata row is written, so the next request refetches and
// stores again. stored reports whether the blob store write succeeded.
// Never use it for a hosted upload: there the stored copy is the only one.
func (s *LocalStorage) PutOrSpool(ctx context.Context, logicalPath string, src io.Reader, meta ContentMetadata) (c *CachedContent, stored bool, err error) {
	return s.put(ctx, logicalPath, src, meta, true)
}

func (s *LocalStorage) put(ctx context.Context, logicalPath string, src io.Reader, meta ContentMetadata, spool bool) (*CachedContent, bool, error) {
	orgID := OrgFromContext(ctx)
	hash := sha256.New()
	var tw *tierWriter
	if s.tier != nil {
		tw = s.tier.newWriter()
	}
	sink := io.Writer(hash)
	if tw != nil {
		sink = io.MultiWriter(hash, tw)
	}
	tee := io.TeeReader(src, sink)
	blobOpsFrom(ctx).put()
	blob, err := s.blobStore.WriteForOrg(orgID, s.repo, logicalPath, tee)
	if err != nil {
		if !spool || tw == nil {
			tw.abort()
			return nil, false, err
		}
		return serveSpool(logicalPath, tee, hash, tw, meta, err)
	}
	meta.LogicalPath = logicalPath
	meta.Size = blob.Size
	meta.SHA256 = hex.EncodeToString(hash.Sum(nil))
	if meta.CachedAt.IsZero() {
		meta.CachedAt = time.Now()
	}
	if err := s.metaStore.Put(ctx, blob.Path, orgID, s.repo, meta); err != nil {
		tw.abort()
		return nil, false, err
	}
	if s.metaCache != nil {
		s.metaCache.Put(blob.Path, meta)
	}
	tw.commit(blob.Path, meta.SHA256)
	return s.content(ctx, blob.Path, meta), true, nil
}

// spoolTTL is how long a spooled fill stays readable. The request that
// spooled it is served well inside it; NewDiskTier clears any left behind.
const spoolTTL = 15 * time.Minute

// serveSpool finishes reading a fill whose blob store write failed into a
// local spool file and returns content served from it. The file is kept
// outside the tier's LRU, so eviction cannot pull it out from under the
// request. The digest is of every byte read from src: exactly what upstream
// sent.
func serveSpool(logicalPath string, rest io.Reader, hash hash.Hash, tw *tierWriter, meta ContentMetadata, storeErr error) (*CachedContent, bool, error) {
	if _, err := io.Copy(io.Discard, rest); err != nil {
		tw.abort()
		return nil, false, fmt.Errorf("%w (spooling the rest also failed: %v)", storeErr, err)
	}
	if tw.failed {
		tw.abort()
		return nil, false, storeErr
	}
	info, statErr := tw.f.Stat()
	if err := tw.f.Close(); err != nil || statErr != nil {
		tw.abort()
		return nil, false, storeErr
	}
	tw.done = true
	spool := tw.f.Name()
	time.AfterFunc(spoolTTL, func() { _ = os.Remove(spool) })
	meta.LogicalPath = logicalPath
	meta.Size = info.Size()
	meta.SHA256 = hex.EncodeToString(hash.Sum(nil))
	if meta.CachedAt.IsZero() {
		meta.CachedAt = time.Now()
	}
	return &CachedContent{Metadata: meta, file: spool}, false, nil
}

// UpdateMetadata replaces the metadata sidecar for an existing cached blob.
func (s *LocalStorage) UpdateMetadata(ctx context.Context, logicalPath string, meta ContentMetadata) (*CachedContent, error) {
	orgID := OrgFromContext(ctx)
	// Same existence rule as Get: the metadata row, not a blob HEAD.
	blobPath, prev, err := s.lookup(ctx, orgID, logicalPath)
	if err != nil {
		return nil, err
	}
	// The bytes did not change, so neither did their digest; callers
	// building a fresh ContentMetadata would otherwise erase it.
	if meta.SHA256 == "" {
		meta.SHA256 = prev.SHA256
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
	return s.content(ctx, blobPath, meta), nil
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
	if s.tier != nil {
		s.tier.drop(blobPath)
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
		if s.tier != nil {
			s.tier.drop(legacyPath)
		}
		if cs, ok := s.blobStore.(blobstore.ContextStore); ok {
			if err := cs.RemoveCtx(ctx, legacyPath); err != nil {
				return fmt.Errorf("remove legacy blob: %w", err)
			}
		} else if err := os.Remove(legacyPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove legacy blob: %w", err)
		}
		if s.metaCache != nil {
			s.metaCache.Invalidate(legacyPath)
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
				s.dropMeta(ctx, p)
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
			s.dropMeta(ctx, k)
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
