package storage

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

type testStorageFacet struct {
	puts int
	meta ContentMetadata
	data string
}

func (s *testStorageFacet) Get(context.Context, string) (*CachedContent, error) {
	return nil, ErrNotFound
}

func (s *testStorageFacet) Put(_ context.Context, logicalPath string, src io.Reader, meta ContentMetadata) (*CachedContent, error) {
	data, err := io.ReadAll(src)
	if err != nil {
		return nil, err
	}
	s.puts++
	meta.LogicalPath = logicalPath
	meta.Size = int64(len(data))
	s.meta = meta
	s.data = string(data)
	return &CachedContent{Metadata: meta}, nil
}

func (s *testStorageFacet) UpdateMetadata(_ context.Context, _ string, meta ContentMetadata) (*CachedContent, error) {
	s.meta = meta
	return &CachedContent{Metadata: meta}, nil
}

func (s *testStorageFacet) Remove(context.Context, string) error {
	return nil
}

func (s *testStorageFacet) FindPathsByCoordinate(context.Context, string, string) ([]string, error) {
	return nil, nil
}

type testContentScanner struct {
	enabled bool
	err     error
	scans   int
}

func (s *testContentScanner) Enabled() bool {
	return s.enabled
}

func (s *testContentScanner) CurrentVersion(context.Context) (string, error) {
	return "ClamAV test/1", nil
}

func (s *testContentScanner) Scan(_ context.Context, _ string, r io.Reader) (ScanResult, error) {
	s.scans++
	if _, err := io.ReadAll(r); err != nil {
		return ScanResult{}, err
	}
	if s.err != nil {
		return ScanResult{}, s.err
	}
	return ScanResult{
		SHA256:    "abc123",
		DBVersion: "ClamAV test/1",
		ScannedAt: time.Unix(123, 0).UTC(),
	}, nil
}

func TestScanningStoragePutScansAndPersistsCleanArtifact(t *testing.T) {
	inner := &testStorageFacet{}
	scanner := &testContentScanner{enabled: true}
	facet := NewScanningStorage(inner, nil, scanner)

	meta := ContentMetadata{PackageName: "pkg", PackageVersion: "1.0.0"}
	saved, err := facet.Put(context.Background(), "pkg-1.0.0.tgz", strings.NewReader("package"), meta)
	if err != nil {
		t.Fatalf("put: %v", err)
	}
	if scanner.scans != 1 {
		t.Fatalf("expected one scan, got %d", scanner.scans)
	}
	if inner.puts != 1 || inner.data != "package" {
		t.Fatalf("expected clean artifact to be persisted, puts=%d data=%q", inner.puts, inner.data)
	}
	if saved.Metadata.ClamAVDBVersion != "ClamAV test/1" || saved.Metadata.ClamAVSHA256 != "abc123" {
		t.Fatalf("expected clamav metadata on saved content, got %+v", saved.Metadata)
	}
}

func TestScanningStoragePutBlocksScanFailure(t *testing.T) {
	inner := &testStorageFacet{}
	scanner := &testContentScanner{enabled: true, err: errors.New("clamav unavailable")}
	facet := NewScanningStorage(inner, nil, scanner)

	meta := ContentMetadata{PackageName: "pkg", PackageVersion: "1.0.0"}
	if _, err := facet.Put(context.Background(), "pkg-1.0.0.tgz", strings.NewReader("package"), meta); err == nil {
		t.Fatal("expected scan error")
	}
	if inner.puts != 0 {
		t.Fatalf("expected blocked artifact not to be persisted, puts=%d", inner.puts)
	}
}

type limitedScanner struct {
	testContentScanner
	max int64
}

func (s *limitedScanner) MaxScanBytes() int64 { return s.max }

// endlessReader stands in for an upstream body far larger than the cap; it
// fails the test if the spool reads past cap+1.
type endlessReader struct {
	t     *testing.T
	read  int64
	limit int64
}

func (r *endlessReader) Read(p []byte) (int, error) {
	r.read += int64(len(p))
	if r.read > r.limit {
		r.t.Fatalf("spool read %d bytes, past the cap", r.read)
	}
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}

// M13 (adversarial review 2026-11-17): every scanned artifact was copied to
// /tmp in full, with no cap, before clamd refused it at its stream limit.
func TestScanningStoragePutCapsSpoolAtScannerLimit(t *testing.T) {
	inner := &testStorageFacet{}
	scanner := &limitedScanner{testContentScanner: testContentScanner{enabled: true}, max: 7}
	facet := NewScanningStorage(inner, nil, scanner)
	meta := ContentMetadata{PackageName: "pkg", PackageVersion: "1.0.0"}

	// Exactly at the limit is scanned and stored.
	if _, err := facet.Put(context.Background(), "pkg-1.0.0.tgz", strings.NewReader("package"), meta); err != nil {
		t.Fatalf("artifact at the limit refused: %v", err)
	}
	// One byte over is refused with the size-limit error, unscanned, unstored.
	_, err := facet.Put(context.Background(), "pkg-1.0.0.tgz", strings.NewReader("package!"), meta)
	if !errors.Is(err, ErrScanSizeLimit) {
		t.Fatalf("err = %v, want ErrScanSizeLimit", err)
	}
	if scanner.scans != 1 || inner.puts != 1 {
		t.Fatalf("oversized artifact was scanned or stored: scans=%d puts=%d", scanner.scans, inner.puts)
	}
	// A huge body stops at the cap rather than filling /tmp.
	scanner.max = 1 << 20
	big := &endlessReader{t: t, limit: 2 << 20}
	if _, err := facet.Put(context.Background(), "pkg-1.0.0.tgz", big, meta); !errors.Is(err, ErrScanSizeLimit) {
		t.Fatalf("huge body: err = %v, want ErrScanSizeLimit", err)
	}
}

func TestScanningStoragePutBypassesWhenDisabled(t *testing.T) {
	inner := &testStorageFacet{}
	scanner := &testContentScanner{enabled: false}
	facet := NewScanningStorage(inner, nil, scanner)

	meta := ContentMetadata{PackageName: "pkg", PackageVersion: "1.0.0"}
	if _, err := facet.Put(context.Background(), "pkg-1.0.0.tgz", strings.NewReader("package"), meta); err != nil {
		t.Fatalf("put: %v", err)
	}
	if scanner.scans != 0 {
		t.Fatalf("expected no scans while disabled, got %d", scanner.scans)
	}
	if inner.puts != 1 {
		t.Fatalf("expected artifact to be persisted, puts=%d", inner.puts)
	}
}
