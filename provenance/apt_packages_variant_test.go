package provenance

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// The defect these tests pin was found by executing claim C-021 against
// the real deb.debian.org rather than a fixture.
//
// Debian's bookworm InRelease lists all three of
//
//	main/binary-amd64/Packages
//	main/binary-amd64/Packages.gz
//	main/binary-amd64/Packages.xz
//
// but the mirror only SERVES .gz and .xz — a GET of the uncompressed path
// returns 404. pickPackagesEntry preferred the plain entry "for simpler
// fixture generation" and returned exactly one candidate with no
// fallback, so chainsaw fetched a 404 and returned
//
//	UNAVAILABLE  inconclusive: fetch Packages: HTTP 404
//
// on the canonical Debian repository, with a valid keyring loaded and the
// InRelease signature already verified. C-021 was unsatisfiable there even
// after the --source-url and keyring problems were solved.
//
// Every fixture in apt_test.go serves the plain file, so no existing test
// could see this.

// aptVariantFixture serves an APT mirror whose InRelease commits to
// several Packages representations while the mirror only makes some of
// them retrievable — the real Debian shape.
type aptVariantFixture struct {
	packageName string
	version     string
	debBody     []byte
	// servePlain / serveGz control which representations actually
	// answer. Both are always listed in InRelease.
	servePlain bool
	serveGz    bool
}

func newAPTVariantServer(t *testing.T, f aptVariantFixture) (*httptest.Server, *openpgp.Entity) {
	t.Helper()
	entity := newTestPGPEntity(t, "chainsaw-apt-variant", "variant@chainsaw.invalid")

	debSum := sha256.Sum256(f.debBody)
	debFilename := fmt.Sprintf("pool/main/c/%s/%s_%s_amd64.deb", f.packageName, f.packageName, f.version)

	plain := buildPackagesStanza(f.packageName, f.version, debFilename, debSum, len(f.debBody))
	plainSum := sha256.Sum256(plain)

	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	if _, err := zw.Write(plain); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	gzBytes := gzBuf.Bytes()
	gzSum := sha256.Sum256(gzBytes)

	// InRelease lists plain, gz and xz — exactly like Debian. The xz
	// entry is listed but never served, and chainsaw must not choose it.
	var b bytes.Buffer
	b.WriteString("Origin: Chainsaw Tests\nLabel: Chainsaw\nSuite: stable\nCodename: stable\n")
	b.WriteString("Date: Thu, 18 Apr 2026 00:00:00 UTC\nArchitectures: amd64\nComponents: main\n")
	b.WriteString("SHA256:\n")
	fmt.Fprintf(&b, " %s %d main/binary-amd64/Packages\n", hex.EncodeToString(plainSum[:]), len(plain))
	fmt.Fprintf(&b, " %s %d main/binary-amd64/Packages.gz\n", hex.EncodeToString(gzSum[:]), len(gzBytes))
	fmt.Fprintf(&b, " %s %d main/binary-amd64/Packages.xz\n", hex.EncodeToString(gzSum[:]), len(gzBytes))
	signed := clearsignBody(t, entity, b.Bytes())

	mux := http.NewServeMux()
	mux.HandleFunc("/dists/stable/InRelease", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(signed)
	})
	mux.HandleFunc("/dists/stable/main/binary-amd64/Packages", func(w http.ResponseWriter, r *http.Request) {
		if !f.servePlain {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(plain)
	})
	mux.HandleFunc("/dists/stable/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, r *http.Request) {
		if !f.serveGz {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(gzBytes)
	})
	mux.HandleFunc("/"+debFilename, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(f.debBody)
	})
	return httptest.NewServer(mux), entity
}

// TestAPTVerifiesWhenOnlyCompressedPackagesIsServed is the regression:
// the Debian shape must reach StatusVerified.
func TestAPTVerifiesWhenOnlyCompressedPackagesIsServed(t *testing.T) {
	srv, entity := newAPTVariantServer(t, aptVariantFixture{
		packageName: "openssl",
		version:     "3.0.15-1~deb12u1",
		debBody:     []byte("fake openssl .deb bytes"),
		servePlain:  false, // exactly what deb.debian.org does
		serveGz:     true,
	})
	defer srv.Close()

	c := &aptChecker{client: srv.Client(), keyringOverride: openpgp.EntityList{entity}}
	res := c.CheckWithSource(context.Background(), "openssl", "3.0.15-1~deb12u1", srv.URL+"/dists/stable")

	if res.Status != StatusVerified {
		t.Fatalf("status = %q (%s), want StatusVerified. The mirror serves only "+
			"Packages.gz — the shape deb.debian.org actually has.", res.Status, res.Error)
	}
}

// TestAPTStillVerifiesWhenOnlyPlainPackagesIsServed — the reorder must
// not break mirrors that publish only the uncompressed file.
func TestAPTStillVerifiesWhenOnlyPlainPackagesIsServed(t *testing.T) {
	srv, entity := newAPTVariantServer(t, aptVariantFixture{
		packageName: "curl",
		version:     "7.88.0-1",
		debBody:     []byte("fake curl .deb bytes"),
		servePlain:  true,
		serveGz:     false,
	})
	defer srv.Close()

	c := &aptChecker{client: srv.Client(), keyringOverride: openpgp.EntityList{entity}}
	res := c.CheckWithSource(context.Background(), "curl", "7.88.0-1", srv.URL+"/dists/stable")
	if res.Status != StatusVerified {
		t.Fatalf("status = %q (%s), want StatusVerified", res.Status, res.Error)
	}
}

// TestAPTFallbackDoesNotSurviveAHashMismatch is the security control on
// the fallback. Falling through on a FETCH error is fine; falling through
// on a hash MISMATCH would hand an attacker a retry — corrupt the
// first-choice file and chainsaw would quietly verify the second.
//
// The fixture tampers the .gz and serves the plain file clean, so it also
// pins the gz-first ordering: if plain were tried first the tampered file
// would never be read and the control would silently stop controlling.
func TestAPTFallbackDoesNotSurviveAHashMismatch(t *testing.T) {
	entity := newTestPGPEntity(t, "chainsaw-apt-variant", "variant@chainsaw.invalid")

	debBody := []byte("fake nginx .deb bytes")
	debSum := sha256.Sum256(debBody)
	debFilename := "pool/main/n/nginx/nginx_1.22.1-9_amd64.deb"
	plain := buildPackagesStanza("nginx", "1.22.1-9", debFilename, debSum, len(debBody))
	plainSum := sha256.Sum256(plain)

	var gzBuf bytes.Buffer
	zw := gzip.NewWriter(&gzBuf)
	_, _ = zw.Write(plain)
	_ = zw.Close()
	gzBytes := gzBuf.Bytes()
	gzSum := sha256.Sum256(gzBytes)

	var b bytes.Buffer
	b.WriteString("Origin: Chainsaw Tests\nSuite: stable\nCodename: stable\n")
	b.WriteString("Date: Thu, 18 Apr 2026 00:00:00 UTC\nArchitectures: amd64\nComponents: main\n")
	b.WriteString("SHA256:\n")
	fmt.Fprintf(&b, " %s %d main/binary-amd64/Packages\n", hex.EncodeToString(plainSum[:]), len(plain))
	fmt.Fprintf(&b, " %s %d main/binary-amd64/Packages.gz\n", hex.EncodeToString(gzSum[:]), len(gzBytes))
	signed := clearsignBody(t, entity, b.Bytes())

	mux := http.NewServeMux()
	mux.HandleFunc("/dists/stable/InRelease", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(signed)
	})
	// .gz is served TAMPERED (tried first). Plain is served clean.
	mux.HandleFunc("/dists/stable/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, r *http.Request) {
		bad := append([]byte(nil), gzBytes...)
		bad[len(bad)-1] ^= 0xFF
		_, _ = w.Write(bad)
	})
	mux.HandleFunc("/dists/stable/main/binary-amd64/Packages", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(plain)
	})
	mux.HandleFunc("/"+debFilename, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(debBody)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &aptChecker{client: srv.Client(), keyringOverride: openpgp.EntityList{entity}}
	res := c.CheckWithSource(context.Background(), "nginx", "1.22.1-9", srv.URL+"/dists/stable")

	if res.Status != StatusFailed {
		t.Fatalf("status = %q (%s), want StatusFailed — a tampered first-choice "+
			"Packages must terminate the walk, not fall through to a clean sibling",
			res.Status, res.Error)
	}
	if !strings.Contains(res.Error, "sha256 mismatch") {
		t.Errorf("error should name the mismatch, got %q", res.Error)
	}
}

// TestPickPackagesCandidatesPrefersCompressed documents the ordering
// contract directly.
func TestPickPackagesCandidatesPrefersCompressed(t *testing.T) {
	entries := []releaseFileEntry{
		{Path: "main/binary-amd64/Packages"},
		{Path: "main/binary-amd64/Packages.bz2"},
		{Path: "main/binary-amd64/Packages.gz"},
		{Path: "main/binary-amd64/Release"},
		{Path: "main/binary-amd64/Packages.xz"},
	}
	got := pickPackagesCandidates(entries)
	want := []string{
		"main/binary-amd64/Packages.gz",
		"main/binary-amd64/Packages.bz2",
		"main/binary-amd64/Packages",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d candidates, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Path != want[i] {
			t.Errorf("candidate %d = %q, want %q", i, got[i].Path, want[i])
		}
	}
	for _, c := range got {
		if strings.HasSuffix(c.Path, ".xz") {
			t.Errorf(".xz must not be a candidate — Go has no stdlib xz reader: %q", c.Path)
		}
	}
}

// TestAPTScansEveryPackagesIndexForTheCoordinate — the second half of the
// same live finding.
//
// An InRelease lists one Packages file per (component, arch); bookworm
// lists about forty. The old code read exactly ONE and reported MISSING if
// the coordinate was not in it, so `verify apt openssl 3.0.20-1~deb12u2`
// against deb.debian.org returned "package not found in Packages" for a
// package that is plainly in main/binary-amd64. The file header has
// claimed "stop at the first that verifies" since the checker was written.
func TestAPTScansEveryPackagesIndexForTheCoordinate(t *testing.T) {
	entity := newTestPGPEntity(t, "chainsaw-apt-multi", "multi@chainsaw.invalid")

	debBody := []byte("fake openssl .deb bytes")
	debSum := sha256.Sum256(debBody)
	debFilename := "pool/main/o/openssl/openssl_3.0.20-1~deb12u2_amd64.deb"

	// binary-all carries an unrelated arch-independent package.
	otherBody := []byte("unrelated")
	otherSum := sha256.Sum256(otherBody)
	allIdx := buildPackagesStanza("tzdata", "2024a-0+deb12u1", "pool/main/t/tzdata/tzdata.deb", otherSum, len(otherBody))
	amdIdx := buildPackagesStanza("openssl", "3.0.20-1~deb12u2", debFilename, debSum, len(debBody))

	gzip1 := gzipBytes(t, allIdx)
	gzip2 := gzipBytes(t, amdIdx)
	sum1, sum2 := sha256.Sum256(gzip1), sha256.Sum256(gzip2)

	var b bytes.Buffer
	b.WriteString("Origin: Chainsaw Tests\nSuite: stable\nCodename: stable\n")
	b.WriteString("Date: Thu, 18 Apr 2026 00:00:00 UTC\nArchitectures: all amd64\nComponents: contrib main\n")
	b.WriteString("SHA256:\n")
	// Deliberately list contrib first (Debian orders components
	// alphabetically) so the main-first preference is exercised too.
	fmt.Fprintf(&b, " %s %d contrib/binary-amd64/Packages.gz\n", hex.EncodeToString(sum1[:]), len(gzip1))
	fmt.Fprintf(&b, " %s %d main/binary-all/Packages.gz\n", hex.EncodeToString(sum1[:]), len(gzip1))
	fmt.Fprintf(&b, " %s %d main/binary-amd64/Packages.gz\n", hex.EncodeToString(sum2[:]), len(gzip2))
	signed := clearsignBody(t, entity, b.Bytes())

	var contribHits int
	mux := http.NewServeMux()
	mux.HandleFunc("/dists/stable/InRelease", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(signed)
	})
	mux.HandleFunc("/dists/stable/contrib/binary-amd64/Packages.gz", func(w http.ResponseWriter, r *http.Request) {
		contribHits++
		_, _ = w.Write(gzip1)
	})
	mux.HandleFunc("/dists/stable/main/binary-all/Packages.gz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(gzip1)
	})
	mux.HandleFunc("/dists/stable/main/binary-amd64/Packages.gz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(gzip2)
	})
	mux.HandleFunc("/"+debFilename, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(debBody)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	c := &aptChecker{client: srv.Client(), keyringOverride: openpgp.EntityList{entity}}
	res := c.CheckWithSource(context.Background(), "openssl", "3.0.20-1~deb12u2", srv.URL+"/dists/stable")

	if res.Status != StatusVerified {
		t.Fatalf("status = %q (%s), want StatusVerified — the coordinate is in the "+
			"third listed index, and one index is not an answer", res.Status, res.Error)
	}
	if contribHits != 0 {
		t.Errorf("contrib was fetched %d time(s) before main; main must be preferred", contribHits)
	}
}

// TestAPTGenuinelyAbsentPackageStillMissing — the scan must not turn
// "really not here" into something else, and the error must say how many
// indexes were read so the user can tell the two apart.
func TestAPTGenuinelyAbsentPackageStillMissing(t *testing.T) {
	srv, entity := newAPTVariantServer(t, aptVariantFixture{
		packageName: "curl",
		version:     "7.88.0-1",
		debBody:     []byte("fake curl .deb bytes"),
		servePlain:  false,
		serveGz:     true,
	})
	defer srv.Close()

	c := &aptChecker{client: srv.Client(), keyringOverride: openpgp.EntityList{entity}}
	res := c.CheckWithSource(context.Background(), "definitely-not-here", "9.9.9", srv.URL+"/dists/stable")
	if res.Status != StatusMissing {
		t.Fatalf("status = %q (%s), want StatusMissing", res.Status, res.Error)
	}
	if !strings.Contains(res.Error, "Packages indexes read") {
		t.Errorf("error should report how many indexes were searched, got %q", res.Error)
	}
}

func gzipBytes(t *testing.T, in []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(in); err != nil {
		t.Fatalf("gzip: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}
