package blobstore

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/manager"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
)

// S3BlobStore stores blobs in any S3-API-compatible bucket (AWS S3,
// MinIO, Cloudflare R2, Backblaze B2, Google Cloud Storage S3 mode).
//
// Atomicity model: PutObject is atomic per-object (a reader never
// observes a half-written value) but concurrent writers to the same
// key race — last writer wins. Chainsaw's cache pattern (write-once
// on miss, read-many) tolerates this: the worst case is two
// upstream fetches for the same artifact, with one PUT silently
// overwriting the other.
type S3BlobStore struct {
	client       *s3.Client
	uploader     *manager.Uploader
	bucket       string
	keyPrefix    string
	sse          s3types.ServerSideEncryption
	sseKMSKey    string
	logger       *slog.Logger
	usePathStyle bool

	// observer is optional — when non-nil every S3 GET/PUT/DELETE/HEAD
	// records duration + outcome. nil is the default (no-op) so tests
	// don't have to wire a metrics registry.
	observer Observer
}

// SetObserver installs a metrics/logging observer on this store. Safe
// to call after construction but before first use; swapping at runtime
// is racy and not supported.
func (s *S3BlobStore) SetObserver(o Observer) {
	if s == nil {
		return
	}
	s.observer = o
}

// observeOp emits a metric + WARN log (on failure). truncate keeps the
// logged key under 80 chars so we don't blow out the log line on
// requests like `maven/2-byte-shard/very/deep/group/artifact/1.2.3/...`.
func (s *S3BlobStore) observeOp(op, key string, start time.Time, err error) {
	outcome := "ok"
	if err != nil {
		if errors.Is(err, ErrBlobNotFound) {
			outcome = "not_found"
		} else {
			outcome = "error"
		}
	}
	if s.observer != nil {
		s.observer.ObserveOp(op, outcome, time.Since(start).Seconds())
	}
	if outcome == "error" && s.logger != nil {
		s.logger.Warn("s3 blob op failed",
			slog.String("op", op),
			slog.String("bucket", s.bucket),
			slog.String("key", truncateKey(key, 80)),
			slog.Any("error", err))
	}
}

func truncateKey(key string, max int) string {
	if len(key) <= max {
		return key
	}
	if max <= 3 {
		return key[:max]
	}
	return key[:max-3] + "..."
}

// NewS3BlobStore constructs an S3-compatible blob store. Static
// credentials in cfg take precedence over the AWS SDK's ambient
// credential chain (env vars, IRSA, instance profile). With no
// credentials supplied the SDK chains the usual sources.
func NewS3BlobStore(cfg S3Config, logger *slog.Logger) (BlobStore, error) {
	if strings.TrimSpace(cfg.Bucket) == "" {
		return nil, errors.New("blobstore: s3 bucket is required")
	}
	if logger == nil {
		logger = slog.Default()
	}

	loadOpts := []func(*awsconfig.LoadOptions) error{}
	if cfg.Region != "" {
		loadOpts = append(loadOpts, awsconfig.WithRegion(cfg.Region))
	}
	if cfg.AccessKey != "" && cfg.SecretKey != "" {
		loadOpts = append(loadOpts, awsconfig.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(cfg.AccessKey, cfg.SecretKey, cfg.SessionToken),
		))
	}

	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(), loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("blobstore: load aws config: %w", err)
	}

	clientOpts := []func(*s3.Options){}
	if cfg.UsePathStyle {
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.UsePathStyle = true
		})
	}
	if cfg.Endpoint != "" {
		endpoint := strings.TrimSpace(cfg.Endpoint)
		// Accept bare hostnames like "minio.local:9000" by adding a
		// scheme — required by the AWS SDK BaseEndpoint validator.
		if !strings.HasPrefix(endpoint, "http://") && !strings.HasPrefix(endpoint, "https://") {
			if cfg.Insecure {
				endpoint = "http://" + endpoint
			} else {
				endpoint = "https://" + endpoint
			}
		} else if cfg.Insecure && strings.HasPrefix(endpoint, "https://") {
			endpoint = "http://" + strings.TrimPrefix(endpoint, "https://")
		}
		clientOpts = append(clientOpts, func(o *s3.Options) {
			o.BaseEndpoint = aws.String(endpoint)
		})
	}

	client := s3.NewFromConfig(awsCfg, clientOpts...)
	uploader := manager.NewUploader(client, func(u *manager.Uploader) {
		u.PartSize = 16 * 1024 * 1024 // 16 MB
		u.Concurrency = 4
	})

	store := &S3BlobStore{
		client:       client,
		uploader:     uploader,
		bucket:       cfg.Bucket,
		keyPrefix:    strings.Trim(cfg.KeyPrefix, "/"),
		logger:       logger,
		usePathStyle: cfg.UsePathStyle,
	}
	switch strings.ToLower(strings.TrimSpace(cfg.SSE)) {
	case "":
		// default — bucket policy controls encryption
	case "aes256":
		store.sse = s3types.ServerSideEncryptionAes256
	case "aws:kms", "kms":
		store.sse = s3types.ServerSideEncryptionAwsKms
		store.sseKMSKey = strings.TrimSpace(cfg.KMSKeyID)
	default:
		return nil, fmt.Errorf("blobstore: unknown s3 SSE mode %q (supported: AES256, aws:kms)", cfg.SSE)
	}
	return store, nil
}

// BlobPath returns the S3 object key for the given (repo, logicalPath).
// The 2-byte SHA1 sharding scheme matches the file backend so an
// operator can mirror an existing on-disk store into S3 with a
// straight `s3 sync` (key-for-path).
func (s *S3BlobStore) BlobPath(repo, logicalPath string) (string, error) {
	repo = sanitizeRepoName(repo)
	if repo == "" {
		return "", errors.New("invalid repository name")
	}
	logicalPath = normalizeLogicalPath(logicalPath)
	if logicalPath == "" {
		return "", errors.New("invalid logical path")
	}
	return s.joinKey(repo, s3Shard(logicalPath), logicalPath), nil
}

// BlobPathForOrg returns the org-scoped object key.
func (s *S3BlobStore) BlobPathForOrg(orgID, repo, logicalPath string) (string, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return s.BlobPath(repo, logicalPath)
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
	return s.joinKey(orgID, repo, s3Shard(logicalPath), logicalPath), nil
}

// RepoRoot returns the key prefix for the repository.
func (s *S3BlobStore) RepoRoot(repo string) (string, error) {
	repo = sanitizeRepoName(repo)
	if repo == "" {
		return "", errors.New("invalid repository name")
	}
	return s.joinKey(repo) + "/", nil
}

// RepoRootForOrg returns the org-scoped key prefix for the repository.
func (s *S3BlobStore) RepoRootForOrg(orgID, repo string) (string, error) {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return s.RepoRoot(repo)
	}
	repo = sanitizeRepoName(repo)
	if repo == "" {
		return "", errors.New("invalid repository name")
	}
	orgID = sanitizeRepoName(orgID)
	if orgID == "" {
		return "", errors.New("invalid org identifier")
	}
	return s.joinKey(orgID, repo) + "/", nil
}

// Write streams content to the canonical (non-org) key.
func (s *S3BlobStore) Write(repo, logicalPath string, src io.Reader) (*Blob, error) {
	return s.WriteForOrg("", repo, logicalPath, src)
}

// WriteForOrg streams content to the org-scoped key.
func (s *S3BlobStore) WriteForOrg(orgID, repo, logicalPath string, src io.Reader) (*Blob, error) {
	key, err := s.BlobPathForOrg(orgID, repo, logicalPath)
	if err != nil {
		return nil, err
	}
	start := time.Now()
	// CountingReader is used to capture the size — the uploader does not
	// always populate it (when the stream is unsigned or chunked).
	counter := &countingReader{r: src}
	input := &s3.PutObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
		Body:   counter,
	}
	if s.sse != "" {
		input.ServerSideEncryption = s.sse
	}
	if s.sseKMSKey != "" {
		input.SSEKMSKeyId = aws.String(s.sseKMSKey)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if _, uploadErr := s.uploader.Upload(ctx, input); uploadErr != nil {
		s.observeOp("put", key, start, uploadErr)
		return nil, fmt.Errorf("s3 upload %s: %w", key, uploadErr)
	}
	s.observeOp("put", key, start, nil)
	return &Blob{Path: key, Size: counter.n}, nil
}

// Open returns a reader for the blob at the given key. The caller
// MUST Close the reader to release the underlying TCP connection.
//
// Cancellation: the request context governs only the GetObject call
// (header fetch). Streaming the body uses a long-lived background
// context so multi-GB downloads aren't killed by a small timeout —
// the SDK's HTTP client owns idle/read timeouts at the transport layer.
func (s *S3BlobStore) Open(key string) (io.ReadCloser, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	out, err := s.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	cancel()
	if err != nil {
		if isS3NotFound(err) {
			s.observeOp("get", key, start, ErrBlobNotFound)
			return nil, ErrBlobNotFound
		}
		s.observeOp("get", key, start, err)
		return nil, fmt.Errorf("s3 get %s: %w", key, err)
	}
	s.observeOp("get", key, start, nil)
	return out.Body, nil
}

// Stat returns minimal metadata for the blob at the given key.
func (s *S3BlobStore) Stat(key string) (os.FileInfo, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		if isS3NotFound(err) {
			s.observeOp("stat", key, start, ErrBlobNotFound)
			return nil, ErrBlobNotFound
		}
		s.observeOp("stat", key, start, err)
		return nil, fmt.Errorf("s3 head %s: %w", key, err)
	}
	s.observeOp("stat", key, start, nil)
	size := int64(0)
	if out.ContentLength != nil {
		size = *out.ContentLength
	}
	mod := time.Time{}
	if out.LastModified != nil {
		mod = *out.LastModified
	}
	return s3FileInfo{key: key, size: size, mod: mod}, nil
}

// RemoveCtx deletes the object at the given key. Idempotent — S3
// returns success for missing keys, matching the file backend.
func (s *S3BlobStore) RemoveCtx(ctx context.Context, key string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()
	_, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil && !isS3NotFound(err) {
		s.observeOp("delete", key, start, err)
		return fmt.Errorf("s3 delete %s: %w", key, err)
	}
	s.observeOp("delete", key, start, nil)
	return nil
}

// ListCtx walks every object under the given key prefix invoking fn.
// Pagination is handled internally; callers see one continuous stream
// of [BlobInfo] entries.
func (s *S3BlobStore) ListCtx(ctx context.Context, prefix string, fn func(BlobInfo) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	paginator := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return fmt.Errorf("s3 list %s: %w", prefix, err)
		}
		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}
			info := BlobInfo{Key: *obj.Key}
			if obj.Size != nil {
				info.Size = *obj.Size
			}
			if err := fn(info); err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
		}
	}
	return nil
}

// Close releases backend resources. Currently a no-op — the AWS SDK
// uses HTTP keep-alive at the transport level and handles its own
// pool lifecycle.
func (s *S3BlobStore) Close() error { return nil }

// joinKey assembles segments into a clean S3 key, prepending the
// configured key prefix (when set).
func (s *S3BlobStore) joinKey(segments ...string) string {
	parts := make([]string, 0, len(segments)+1)
	if s.keyPrefix != "" {
		parts = append(parts, s.keyPrefix)
	}
	for _, seg := range segments {
		seg = strings.Trim(seg, "/")
		if seg == "" {
			continue
		}
		parts = append(parts, seg)
	}
	return path.Join(parts...)
}

func s3Shard(logicalPath string) string {
	sum := sha1.Sum([]byte(logicalPath))
	return hex.EncodeToString(sum[:1]) + "/" + hex.EncodeToString(sum[1:2])
}

func isS3NotFound(err error) bool {
	if err == nil {
		return false
	}
	var nsk *s3types.NoSuchKey
	if errors.As(err, &nsk) {
		return true
	}
	var nfa *s3types.NotFound
	if errors.As(err, &nfa) {
		return true
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "NoSuchKey", "NotFound", "404":
			return true
		}
	}
	return false
}

type s3FileInfo struct {
	key  string
	size int64
	mod  time.Time
}

func (i s3FileInfo) Name() string       { return path.Base(i.key) }
func (i s3FileInfo) Size() int64        { return i.size }
func (i s3FileInfo) Mode() os.FileMode  { return 0o644 }
func (i s3FileInfo) ModTime() time.Time { return i.mod }
func (i s3FileInfo) IsDir() bool        { return false }
func (i s3FileInfo) Sys() any           { return nil }

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// Compile-time interface assertion.
var (
	_ BlobStore    = (*S3BlobStore)(nil)
	_ ContextStore = (*S3BlobStore)(nil)
)
