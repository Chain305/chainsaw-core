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
