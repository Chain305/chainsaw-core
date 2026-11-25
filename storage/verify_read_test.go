package storage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// tamper rewrites the blob under c in place, leaving its metadata (and the
// digest recorded in it) untouched: S3 bit-rot, or someone with bucket write.
func tamper(t *testing.T, c *CachedContent, body []byte) {
	t.Helper()
	if err := os.WriteFile(c.path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestSecurityGuard_TamperedBlobNeverServedClean (FINDINGS E4, INV-S4): a
// full read of a blob whose bytes no longer hash to the recorded SHA-256
// must not complete. The final byte is held back until the digest is
// checked, so a response with a Content-Length can never finish from bad
// bytes. Then: an uploaded (hosted) blob is quarantined and refused, never
// refetched; a proxied blob's row is evicted so the next request refills
// from upstream through the checksum gate.
func TestSecurityGuard_TamperedBlobNeverServedClean(t *testing.T) {
	body := []byte(strings.Repeat("genuine artifact bytes ", 4096)) // > one 32 KiB read
	tampers := map[string][]byte{
		"same length": append(bytes.Repeat([]byte{'X'}, 10), body[10:]...),
		"truncated":   body[:len(body)-1],
		"appended":    append(append([]byte{}, body...), "evil"...),
	}
	for _, withTier := range []bool{false, true} {
		for name, bad := range tampers {
			for _, uploaded := range []bool{true, false} {
				t.Run(fmt.Sprintf("%s/uploaded=%v/tier=%v", name, uploaded, withTier), func(t *testing.T) {
					s, _, tier := newTierStorage(t, 1<<30)
					if !withTier {
						s.SetDiskTier(nil)
					}
					ctx := WithOrg(context.Background(), "org-a")
					const path = "pkg/-/pkg-1.0.0.tgz"
					put, err := s.Put(ctx, path, bytes.NewReader(body), ContentMetadata{Uploaded: uploaded})
					if err != nil {
						t.Fatal(err)
					}
					if withTier {
						tier.drop(put.path) // force the blob-store read (and its tier fill)
					}

					// Positive control: the genuine bytes read cleanly.
					if got, err := readAll(t, mustGet(t, s, ctx, path)); err != nil || !bytes.Equal(got, body) {
						t.Fatalf("control read: %d bytes, %v", len(got), err)
					}
					if withTier {
						tier.drop(put.path)
					}

					kind := "proxy"
					if uploaded {
						kind = "hosted"
					}
					before := DigestMismatches(kind)
					tamper(t, put, bad)
					got, err := readAll(t, mustGet(t, s, ctx, path))
					if !errors.Is(err, ErrDigestMismatch) {
						t.Fatalf("tampered read: err = %v, want ErrDigestMismatch", err)
					}
					if len(got) >= len(body) {
						t.Fatalf("tampered read released %d bytes, want < %d: a Content-Length response would complete", len(got), len(body))
					}
					if DigestMismatches(kind) != before+1 {
						t.Fatalf("%s mismatch counter = %d, want %d", kind, DigestMismatches(kind), before+1)
					}
					if withTier {
						if files := tierFiles(t, tier); len(files) != 0 {
							t.Fatalf("tier kept bytes that failed verification: %v", files)
						}
					}

					c, err := s.Get(ctx, path)
					if uploaded {
						// Hosted: no upstream truth. The row stays, marked, and
						// every later read refuses before touching the bytes.
						if err != nil {
							t.Fatalf("hosted row dropped (%v): the facet would refetch a hosted name from upstream", err)
						}
						if !c.Metadata.IntegrityFailed {
							t.Fatal("hosted blob not quarantined")
						}
						if _, err := c.Open(); !errors.Is(err, ErrDigestMismatch) {
							t.Fatalf("quarantined Open = %v, want ErrDigestMismatch", err)
						}
						if _, err := c.OpenAt(5); !errors.Is(err, ErrDigestMismatch) {
							t.Fatalf("quarantined OpenAt = %v, want ErrDigestMismatch", err)
						}
						// Sticky: a metadata update built from an older copy
						// (the ClamAV recorder, the checksum commit) cannot clear it.
						if _, err := s.UpdateMetadata(ctx, path, put.Metadata); err != nil {
							t.Fatal(err)
						}
						if c := mustGet(t, s, ctx, path); !c.Metadata.IntegrityFailed {
							t.Fatal("UpdateMetadata cleared the quarantine")
						}
						return
					}
					// Proxy: evicted, so the facet refills from upstream.
					if !errors.Is(err, ErrNotFound) {
						t.Fatalf("proxy Get after mismatch = %v, want ErrNotFound so the next request refills", err)
					}
					if _, err := s.Put(ctx, path, bytes.NewReader(body), ContentMetadata{}); err != nil {
						t.Fatal(err)
					}
					if got, err := readAll(t, mustGet(t, s, ctx, path)); err != nil || !bytes.Equal(got, body) {
						t.Fatalf("refilled read: %d bytes, %v", len(got), err)
					}
				})
			}
		}
	}
}

// A ranged read cannot be verified (only a full read can) and is served
// unverified; a full read through OpenAt(0) is verified.
func TestOpenAtZeroIsVerified(t *testing.T) {
	s, _, _ := newTierStorage(t, 1<<20)
	s.SetDiskTier(nil)
	ctx := context.Background()
	put, err := s.Put(ctx, "a.tgz", bytes.NewReader([]byte("0123456789")), ContentMetadata{})
	if err != nil {
		t.Fatal(err)
	}
	tamper(t, put, []byte("0123456780"))
	rc, err := mustGet(t, s, ctx, "a.tgz").OpenAt(0)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	if _, err := io.ReadAll(rc); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("OpenAt(0) read = %v, want ErrDigestMismatch", err)
	}
}

func mustGet(t *testing.T, s *LocalStorage, ctx context.Context, path string) *CachedContent {
	t.Helper()
	c, err := s.Get(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
