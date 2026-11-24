package storage

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// incompleteScanner finishes the scan (valid result) but reports that it
// could not inspect everything, as clamd does for Heuristics.Encrypted.* and
// Heuristics.Limits.Exceeded.* once the Alert* options are on.
type incompleteScanner struct {
	err error
}

func (s *incompleteScanner) Enabled() bool { return true }
func (s *incompleteScanner) CurrentVersion(context.Context) (string, error) {
	return "ClamAV test/1", nil
}
func (s *incompleteScanner) Scan(_ context.Context, _ string, r io.Reader) (ScanResult, error) {
	if _, err := io.ReadAll(r); err != nil {
		return ScanResult{}, err
	}
	return ScanResult{SHA256: "abc123", DBVersion: "ClamAV test/1", ScannedAt: time.Unix(123, 0).UTC()}, s.err
}

// The upload/proxy table (pentest #49, #53; RC9). Incomplete is never a
// malware verdict. On upload, encrypted content, nesting past the recursion
// limit and an archive our own unpacker could not open are refused; size,
// file-count and time limits are stored and flagged, because ordinary image
// layers exceed them. On the proxy path every incomplete scan is stored and
// flagged. Every other scan error refuses on both paths.
func TestSecurityGuard_ScanningStorageIncompleteUploadVsProxy(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		uploaded bool
		refuse   bool
	}{
		{"encrypted upload", &ScanIncompleteError{Reason: "Heuristics.Encrypted.Zip"}, true, true},
		{"encrypted proxy", &ScanIncompleteError{Reason: "Heuristics.Encrypted.Zip"}, false, false},
		{"encrypted pdf upload", &ScanIncompleteError{Reason: "Heuristics.Encrypted.PDF"}, true, false},
		{"recursion upload", &ScanIncompleteError{Reason: "Heuristics.Limits.Exceeded.MaxRecursion"}, true, true},
		{"recursion proxy", &ScanIncompleteError{Reason: "Heuristics.Limits.Exceeded.MaxRecursion"}, false, false},
		{"unpack failed upload", &ScanIncompleteError{Reason: "Chainsaw.Unpack.Failed.deb"}, true, true},
		{"unpack failed proxy", &ScanIncompleteError{Reason: "Chainsaw.Unpack.Failed.deb"}, false, false},
		{"maxfiles upload", &ScanIncompleteError{Reason: "Heuristics.Limits.Exceeded.MaxFiles"}, true, false},
		{"maxscansize upload", &ScanIncompleteError{Reason: "Heuristics.Limits.Exceeded.MaxScanSize"}, true, false},
		{"maxscansize proxy", &ScanIncompleteError{Reason: "Heuristics.Limits.Exceeded.MaxScanSize"}, false, false},
		{"wrapped encrypted upload", errors.Join(errors.New("ctx"), &ScanIncompleteError{Reason: "Heuristics.Encrypted.RAR"}), true, true},
		{"infected upload", errors.New("clamav detected malware: Eicar"), true, true},
		{"infected proxy", errors.New("clamav detected malware: Eicar"), false, true},
		{"size limit proxy", ErrScanSizeLimit, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			inner := &testStorageFacet{}
			facet := NewScanningStorage(inner, nil, &incompleteScanner{err: tc.err})
			before := ScanIncompleteCount()
			meta := ContentMetadata{PackageName: "pkg", PackageVersion: "1.0.0", Uploaded: tc.uploaded}
			saved, err := facet.Put(context.Background(), "pkg-1.0.0.tgz", strings.NewReader("package"), meta)
			if tc.refuse {
				if err == nil || inner.puts != 0 {
					t.Fatalf("want refused and unstored, got err=%v puts=%d", err, inner.puts)
				}
				return
			}
			if err != nil || inner.puts != 1 {
				t.Fatalf("want stored, got err=%v puts=%d", err, inner.puts)
			}
			var inc *ScanIncompleteError
			errors.As(tc.err, &inc)
			if saved.Metadata.ClamAVIncomplete != inc.Reason || saved.Metadata.ClamAVSHA256 != "abc123" {
				t.Fatalf("stored without the incomplete flag or scan record: %+v", saved.Metadata)
			}
			if ScanIncompleteCount() != before+1 {
				t.Fatalf("incomplete counter did not move")
			}
		})
	}
}

func TestAcceptIncompleteScan(t *testing.T) {
	if _, ok := AcceptIncompleteScan(nil, false); ok {
		t.Fatal("nil error accepted as incomplete")
	}
	if _, ok := AcceptIncompleteScan(errors.New("boom"), false); ok {
		t.Fatal("a scan failure accepted as incomplete")
	}
	if r, ok := AcceptIncompleteScan(&ScanIncompleteError{Reason: "Heuristics.Encrypted.Zip"}, false); !ok || r != "Heuristics.Encrypted.Zip" {
		t.Fatalf("proxied encrypted not accepted: %q %v", r, ok)
	}
	if _, ok := AcceptIncompleteScan(&ScanIncompleteError{Reason: "Heuristics.Encrypted.Zip"}, true); ok {
		t.Fatal("uploaded encrypted accepted")
	}
}
