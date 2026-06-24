package storage

import (
	"context"
	"io"
	"os"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/formats/common"
)

// ScanResult captures the clean verdict metadata recorded with cached artifacts.
type ScanResult struct {
	SHA256    string
	DBVersion string
	ScannedAt time.Time
}

// ContentScanner scans artifact bytes before they are persisted or served.
type ContentScanner interface {
	Enabled() bool
	CurrentVersion(context.Context) (string, error)
	Scan(context.Context, string, io.Reader) (ScanResult, error)
}

// ScanningStorage applies artifact scanning before delegating writes.
type ScanningStorage struct {
	inner    StorageFacet
	resolver common.CoordinateResolver
	scanner  ContentScanner
}

// NewScanningStorage wraps a storage facet with scanner enforcement.
func NewScanningStorage(inner StorageFacet, resolver common.CoordinateResolver, scanner ContentScanner) StorageFacet {
	if inner == nil || scanner == nil {
		return inner
	}
	return &ScanningStorage{inner: inner, resolver: resolver, scanner: scanner}
}

func (s *ScanningStorage) Get(ctx context.Context, logicalPath string) (*CachedContent, error) {
	return s.inner.Get(ctx, logicalPath)
}

func (s *ScanningStorage) Put(ctx context.Context, logicalPath string, src io.Reader, meta ContentMetadata) (*CachedContent, error) {
	if s == nil || s.inner == nil {
		return nil, ErrNotFound
	}
	if s.scanner == nil || !s.scanner.Enabled() || !s.shouldScan(logicalPath, meta) {
		return s.inner.Put(ctx, logicalPath, src, meta)
	}
	if strings.TrimSpace(meta.ClamAVDBVersion) != "" && strings.TrimSpace(meta.ClamAVSHA256) != "" {
		return s.inner.Put(ctx, logicalPath, src, meta)
	}

	tmp, err := os.CreateTemp("", "chainsaw-clamav-*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	defer tmp.Close()

	if _, err := io.Copy(tmp, src); err != nil {
		return nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	result, err := s.scanner.Scan(ctx, logicalPath, tmp)
	if err != nil {
		return nil, err
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	meta.ClamAVScannedAt = result.ScannedAt
	meta.ClamAVDBVersion = result.DBVersion
	meta.ClamAVSHA256 = result.SHA256
	return s.inner.Put(ctx, logicalPath, tmp, meta)
}

func (s *ScanningStorage) UpdateMetadata(ctx context.Context, logicalPath string, meta ContentMetadata) (*CachedContent, error) {
	return s.inner.UpdateMetadata(ctx, logicalPath, meta)
}

func (s *ScanningStorage) Remove(ctx context.Context, logicalPath string) error {
	return s.inner.Remove(ctx, logicalPath)
}

func (s *ScanningStorage) FindPathsByCoordinate(ctx context.Context, packageName, version string) ([]string, error) {
	return s.inner.FindPathsByCoordinate(ctx, packageName, version)
}

func (s *ScanningStorage) shouldScan(logicalPath string, meta ContentMetadata) bool {
	if strings.HasSuffix(strings.ToLower(strings.TrimSpace(logicalPath)), ".metadata") {
		return false
	}
	if strings.TrimSpace(meta.PackageName) != "" && strings.TrimSpace(meta.PackageVersion) != "" {
		return true
	}
	if s.resolver == nil {
		return false
	}
	_, ok := s.resolver.Describe(logicalPath)
	return ok
}
