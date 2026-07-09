package blobstore

import (
	"fmt"
	"log/slog"
	"strings"
)

// Config selects the backend at startup. The zero value selects the
// file backend with the supplied root directory, preserving the
// existing single-instance behaviour.
type Config struct {
	// Type selects the backend. Empty string and "file" both choose
	// the local filesystem. "s3" selects the S3-compatible backend.
	Type string

	// File holds file-backend options.
	File FileConfig

	// S3 holds S3-backend options. Required when Type == "s3".
	S3 *S3Config
}

// FileConfig configures the local filesystem backend.
type FileConfig struct {
	// Root is the on-disk directory under which blobs live. Required.
	Root string
}

// S3Config configures the S3-compatible backend. The Endpoint field
// is empty for AWS S3 (region resolves the endpoint) and points to
// the MinIO/R2/B2/GCS endpoint URL otherwise.
type S3Config struct {
	Endpoint     string
	Region       string
	Bucket       string
	AccessKey    string
	SecretKey    string
	SessionToken string
	UsePathStyle bool
	Insecure     bool
	SSE          string // "" | "AES256" | "aws:kms"
	KMSKeyID     string
	KeyPrefix    string // optional prefix prepended to every key
}

// New returns the BlobStore selected by cfg. The returned value also
// satisfies [ContextStore] for both supported backends.
//
// Selection rules:
//   - Type == "" or "file" → FileBlobStore at cfg.File.Root
//   - Type == "s3"          → S3BlobStore via cfg.S3
//   - any other value       → error (fail fast at startup)
func New(cfg Config, logger *slog.Logger) (BlobStore, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.Type)) {
	case "", "file":
		if cfg.File.Root == "" {
			return nil, fmt.Errorf("blobstore: file backend requires a root directory")
		}
		return NewFileBlobStore(cfg.File.Root)
	case "s3":
		if cfg.S3 == nil {
			return nil, fmt.Errorf("blobstore: s3 backend requires S3 configuration")
		}
		return NewS3BlobStore(*cfg.S3, logger)
	default:
		return nil, fmt.Errorf("blobstore: unknown backend type %q (supported: file, s3)", cfg.Type)
	}
}
