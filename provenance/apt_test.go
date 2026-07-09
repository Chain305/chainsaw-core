package provenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
)

// TestAPTHappyPath walks the full InRelease → Packages → .deb hash chain
// against an httptest mirror whose InRelease is signed by a throw-away
// test keypair. Offline: no real network.
func TestAPTHappyPath(t *testing.T) {
	srv, entity := newAPTFixtureServer(t, aptFixture{
		packageName: "curl",
		version:     "7.88.0-1",
		debBody:     []byte("fake-curl-7.88.0-1 .deb content for hash chain test"),
	})
	defer srv.Close()

	c := &aptChecker{
		client: srv.Client(),

		keyringOverride: openpgp.EntityList{entity},
	}
	res := c.CheckWithSource(context.Background(), "curl", "7.88.0-1", srv.URL+"/dists/stable")
	if res.Status != StatusVerified {
		t.Fatalf("status = %q (%s), want StatusVerified", res.Status, res.Error)
	}
	if res.Ecosystem != "apt" {
		t.Errorf("ecosystem = %q", res.Ecosystem)
	}
	if res.AttestationType != "pgp-repo" {
		t.Errorf("attestationType = %q", res.AttestationType)
	}
	if res.BuilderID == "" {
		t.Errorf("BuilderID should name the signing key")
	}
}

// TestAPTTamperedPackages confirms that altering the Packages file on
// the mirror after the InRelease hash is committed flips the verdict to
// StatusFailed — the hash chain catches the mismatch.
func TestAPTTamperedPackages(t *testing.T) {
	f := aptFixture{
		packageName: "curl",
		version:     "7.88.0-1",
		debBody:     []byte("fake-curl .deb"),
		tamperPackages: func(b []byte) []byte {
			// Swap a byte after InRelease has committed to the hash.
			out := append([]byte(nil), b...)
			out[0] ^= 0xFF
			return out
		},
	}
	srv, entity := newAPTFixtureServer(t, f)
	defer srv.Close()

	c := &aptChecker{
		client: srv.Client(),

		keyringOverride: openpgp.EntityList{entity},
	}
	res := c.CheckWithSource(context.Background(), "curl", "7.88.0-1", srv.URL+"/dists/stable")
	if res.Status != StatusFailed {
		t.Fatalf("status = %q (%s), want StatusFailed", res.Status, res.Error)
	}
	if !strings.Contains(res.Error, "Packages sha256 mismatch") {
		t.Errorf("error should mention Packages mismatch, got %q", res.Error)
	}
}

// TestAPTTamperedSignature flips a byte inside the signature packet of
// the clearsigned InRelease. OpenPGP sig verify must reject.
func TestAPTTamperedSignature(t *testing.T) {
	f := aptFixture{
		packageName: "curl",
		version:     "7.88.0-1",
		debBody:     []byte("fake-curl .deb"),
		tamperInRelease: func(b []byte) []byte {
			// Find the armored signature block and flip a hex byte
			// within its base64 body. The sentinel is predictable.
			idx := bytes.Index(b, []byte("-----BEGIN PGP SIGNATURE-----"))
			if idx < 0 {
				return b
			}
			// Move past header line to something base64; flip one
			// byte deep enough to corrupt the packet.
			pos := idx + len("-----BEGIN PGP SIGNATURE-----\n\n") + 40
			if pos >= len(b) {
				return b
			}
			out := append([]byte(nil), b...)
			if out[pos] == 'A' {
				out[pos] = 'B'
			} else {
				out[pos] = 'A'
			}
			return out
		},
	}
	srv, entity := newAPTFixtureServer(t, f)
	defer srv.Close()

	c := &aptChecker{
		client: srv.Client(),

		keyringOverride: openpgp.EntityList{entity},
	}
	res := c.CheckWithSource(context.Background(), "curl", "7.88.0-1", srv.URL+"/dists/stable")
	if res.Status != StatusFailed {
		t.Fatalf("status = %q (%s), want StatusFailed", res.Status, res.Error)
	}
	if !strings.Contains(res.Error, "InRelease signature") {
		t.Errorf("error should mention InRelease signature, got %q", res.Error)
	}
}

// TestAPTMissingKeyring — if the configured keyring path is missing and
// no embedded keys are present, we must report StatusUnavailable with a
// clear reason instead of crashing or silently reporting Verified.
func TestAPTMissingKeyring(t *testing.T) {
	c := &aptChecker{
		client: &http.Client{Timeout: 1 * time.Second},

		keyringPath: "/nonexistent/apt/keyring/dir",
	}
	res := c.CheckWithSource(context.Background(), "curl", "7.88.0-1", "http://127.0.0.1:1/dists/stable")
	if res.Status != StatusUnavailable {
		t.Fatalf("status = %q, want StatusUnavailable", res.Status)
	}
	if !strings.Contains(res.Error, "keyring") {
		t.Errorf("error should mention keyring, got %q", res.Error)
	}
}

// TestAPTMissingSourceURL confirms the "needs source URL" shortcut.
func TestAPTMissingSourceURL(t *testing.T) {
	c := &aptChecker{client: http.DefaultClient}
	res := c.Check(context.Background(), "curl", "7.88.0-1")
	if res.Status != StatusUnavailable {
		t.Fatalf("status = %q", res.Status)
	}
	if !strings.Contains(res.Error, "source repository URL") {
		t.Errorf("error = %q", res.Error)
	}
}

// --- fixture server -------------------------------------------------------

type aptFixture struct {
	packageName     string
	version         string
	debBody         []byte
	tamperPackages  func([]byte) []byte
	tamperInRelease func([]byte) []byte
}

// newAPTFixtureServer builds a minimal APT mirror layout served from an
// httptest server. The returned entity's secret key is used to sign
// InRelease; callers use its public half as the keyring override.
func newAPTFixtureServer(t *testing.T, f aptFixture) (*httptest.Server, *openpgp.Entity) {
	t.Helper()

	entity := newTestPGPEntity(t, "chainsaw-apt-test", "test@chainsaw.invalid")

	debSum := sha256.Sum256(f.debBody)
	debFilename := fmt.Sprintf("pool/main/c/%s/%s_%s_amd64.deb", f.packageName, f.packageName, f.version)

	packages := buildPackagesStanza(f.packageName, f.version, debFilename, debSum, len(f.debBody))
	packagesServed := packages
	if f.tamperPackages != nil {
		packagesServed = f.tamperPackages(packages)
	}
	packagesSum := sha256.Sum256(packages) // hash committed to InRelease (the untampered one)
	packagesPath := "main/binary-amd64/Packages"

	inRelease := buildInReleaseBody(packagesPath, packagesSum, len(packages))
	signed := clearsignBody(t, entity, inRelease)
	if f.tamperInRelease != nil {
		signed = f.tamperInRelease(signed)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/dists/stable/InRelease", func(w http.ResponseWriter, r *http.Request) {
		w.Write(signed)
	})
	mux.HandleFunc("/dists/stable/main/binary-amd64/Packages", func(w http.ResponseWriter, r *http.Request) {
		w.Write(packagesServed)
	})
	mux.HandleFunc("/"+debFilename, func(w http.ResponseWriter, r *http.Request) {
		w.Write(f.debBody)
	})
	return httptest.NewServer(mux), entity
}

func buildPackagesStanza(name, version, filename string, sum [32]byte, size int) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "Package: %s\n", name)
	fmt.Fprintf(&b, "Version: %s\n", version)
	fmt.Fprintf(&b, "Architecture: amd64\n")
	fmt.Fprintf(&b, "Maintainer: Chainsaw Tests <test@chainsaw.invalid>\n")
	fmt.Fprintf(&b, "Filename: %s\n", filename)
	fmt.Fprintf(&b, "Size: %d\n", size)
	fmt.Fprintf(&b, "SHA256: %s\n", hex.EncodeToString(sum[:]))
	fmt.Fprintf(&b, "Description: test package\n")
	b.WriteString("\n")
	return b.Bytes()
}

func buildInReleaseBody(packagesPath string, sum [32]byte, size int) []byte {
	var b bytes.Buffer
	b.WriteString("Origin: Chainsaw Tests\n")
	b.WriteString("Label: Chainsaw\n")
	b.WriteString("Suite: stable\n")
	b.WriteString("Codename: stable\n")
	b.WriteString("Date: Thu, 18 Apr 2026 00:00:00 UTC\n")
	b.WriteString("Architectures: amd64\n")
	b.WriteString("Components: main\n")
	b.WriteString("SHA256:\n")
	fmt.Fprintf(&b, " %s %d %s\n", hex.EncodeToString(sum[:]), size, packagesPath)
	return b.Bytes()
}

// clearsignBody wraps body in a PGP cleartext-signed document using the
// supplied entity.
func clearsignBody(t *testing.T, entity *openpgp.Entity, body []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := clearsign.Encode(&out, entity.PrivateKey, nil)
	if err != nil {
		t.Fatalf("clearsign encode: %v", err)
	}
	if _, err := io.Copy(w, bytes.NewReader(body)); err != nil {
		t.Fatalf("clearsign copy: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("clearsign close: %v", err)
	}
	return out.Bytes()
}

// newTestPGPEntity generates a fresh RSA-2048 PGP keypair for fixture
// signing. The keys are ephemeral — regenerated per test run — so no
// secret material is committed to the repo.
func newTestPGPEntity(t *testing.T, name, email string) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity(name, "chainsaw test key", email, nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	// Drive signing subkeys through serialization so the private key
	// material is fully initialised for clearsign.
	var buf bytes.Buffer
	if err := e.SerializePrivate(&buf, nil); err != nil {
		t.Fatalf("SerializePrivate: %v", err)
	}
	return e
}
