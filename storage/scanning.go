package storage

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync/atomic"
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

// ErrScanSizeLimit is returned when an artifact is larger than the scanner
// will scan. internal/clamav's ErrSizeLimit is this value, so the existing
// handling (refuse with 503: an artifact too large to scan is not served)
// covers both the spool cap below and clamd's own stream cap.
var ErrScanSizeLimit = errors.New("clamav scan stream exceeds configured limit")

// ScanIncompleteError means the scanner finished but could not inspect all
// of the artifact: a limit was reached (clamd Heuristics.Limits.Exceeded.*),
// the content is encrypted (Heuristics.Encrypted.*), or Chainsaw's own
// unpacker could not open a container clamd cannot read (Chainsaw.Unpack.*).
// It is never a malware verdict: before clamd was asked to report these they
// came back as a plain OK, and reported as FOUND they would have been a false
// 403 MALWARE on the proxy path (pentest #49, #53). The ScanResult returned
// alongside it is valid.
type ScanIncompleteError struct {
	Reason string
}

func (e *ScanIncompleteError) Error() string {
	return "malware scan incomplete: " + e.Reason
}

// RefusedOnUpload reports incompleteness an upload or push is refused for:
// an encrypted archive, nesting past the recursion limit, and a container our
// unpacker could not open. Those are evasion shapes a publisher controls.
// Size, file-count and scan-time limits are not refused: ordinary image
// layers (node_modules, site-packages) exceed MaxFiles, and refusing them
// would break hosted docker. Nor is an encrypted document (PDF, Office): it is
// inert without a reader holding the password, and test fixtures carry them.
// Those are stored and flagged instead (ContentMetadata.ClamAVIncomplete).
func (e *ScanIncompleteError) RefusedOnUpload() bool {
	r := e.Reason
	if kind, ok := strings.CutPrefix(r, "Heuristics.Encrypted."); ok {
		kind = strings.ToLower(kind)
		return !strings.HasPrefix(kind, "pdf") && !strings.HasPrefix(kind, "doc") && !strings.HasPrefix(kind, "ole2")
	}
	return r == "Heuristics.Limits.Exceeded.MaxRecursion" ||
		strings.HasPrefix(r, "Chainsaw.Unpack.Failed.")
}

var scanIncompleteTotal atomic.Uint64

// ScanIncompleteCount is the process-wide number of incomplete scans
// accepted (stored or served, flagged), exported as
// chainsaw_clamav_scan_incomplete_total.
func ScanIncompleteCount() uint64 { return scanIncompleteTotal.Load() }

// AcceptIncompleteScan reports whether a scan error is an incomplete scan the
// artifact may be stored or served under, returning its reason. uploaded is
// ContentMetadata.Uploaded: an upload is refused for RefusedOnUpload reasons,
// a proxied fill never is (refusing would block large legitimate artifacts;
// the bytes WERE scanned). Any other error is not accepted.
func AcceptIncompleteScan(err error, uploaded bool) (string, bool) {
	var inc *ScanIncompleteError
	if !errors.As(err, &inc) || (uploaded && inc.RefusedOnUpload()) {
		return "", false
	}
	scanIncompleteTotal.Add(1)
	return inc.Reason, true
}

// DefaultMaxScanBytes caps the scan spool when the scanner does not state its
// own limit. It matches ClamAV's default max_stream_bytes and clamd.conf's
// StreamMaxLength (512M).
const DefaultMaxScanBytes int64 = 512 << 20

// ScanSizeLimiter is implemented by a ContentScanner that refuses streams
// above a size (ClamAV: clamav.max_stream_bytes). Put stops spooling there.
type ScanSizeLimiter interface {
	MaxScanBytes() int64
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
	// The spool's bytes count against the process-wide budget (spool.go)
	// until the file is removed.
	spool := NewSpoolWriter(tmp)
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		spool.Release()
	}()

	// Spool at most the scanner's limit (+1 byte to detect overflow). Without
	// the cap every artifact was copied to /tmp in full before clamd refused
	// it, and /tmp counts toward the pod's ephemeral-storage limit, which
	// evicts the pod.
	limit := s.maxScanBytes()
	n, err := io.Copy(spool, io.LimitReader(src, limit+1))
	if err != nil {
		return nil, err
	}
	if n > limit {
		return nil, ErrScanSizeLimit
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	result, err := s.scanner.Scan(ctx, logicalPath, tmp)
	if reason, ok := AcceptIncompleteScan(err, meta.Uploaded); ok {
		meta.ClamAVIncomplete = reason
		err = nil
	}
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

func (s *ScanningStorage) maxScanBytes() int64 {
	if l, ok := s.scanner.(ScanSizeLimiter); ok {
		if n := l.MaxScanBytes(); n > 0 {
			return n
		}
	}
	return DefaultMaxScanBytes
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
