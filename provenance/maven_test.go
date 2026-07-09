package provenance

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/chain305/chainsaw-core/provenance/pgpverify"
)

func TestSplitMavenCoords(t *testing.T) {
	cases := []struct {
		in                 string
		wantGroup, wantArt string
		wantOK             bool
	}{
		{"org.slf4j:slf4j-api", "org.slf4j", "slf4j-api", true},
		{"com.google.guava:guava", "com.google.guava", "guava", true},
		{"org/slf4j/slf4j-api", "org.slf4j", "slf4j-api", true}, // proxy-path form
		{"no-colon", "", "", false},
		{":empty-group", "", "", false},
		{"empty-artifact:", "", "", false},
	}
	for _, c := range cases {
		g, a, ok := splitMavenCoords(c.in)
		if g != c.wantGroup || a != c.wantArt || ok != c.wantOK {
			t.Errorf("splitMavenCoords(%q) = (%q, %q, %v), want (%q, %q, %v)",
				c.in, g, a, ok, c.wantGroup, c.wantArt, c.wantOK)
		}
	}
}

func TestMavenCheckerInvalidCoordReturnsFailed(t *testing.T) {
	c := newMavenChecker(&http.Client{}, nil)
	got := c.Check(context.Background(), "no-colon-here", "1.0.0")
	if got.Status != StatusFailed {
		t.Errorf("status: got %q, want %q", got.Status, StatusFailed)
	}
	if got.Ecosystem != "maven" {
		t.Errorf("ecosystem: got %q, want maven", got.Ecosystem)
	}
}

// TestMavenCheckerMissingSidecars routes both sigstore and asc requests to
// a test server that returns 404 → we should report StatusMissing without
// falling back to StatusFailed.
func TestMavenCheckerMissingSidecars(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// All requests 404 — neither sigstore nor asc sidecar exists.
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newMavenChecker(&http.Client{}, nil)
	c.baseURL = srv.URL

	got := c.Check(context.Background(), "org.example:foo", "1.0.0")
	if got.Status != StatusMissing {
		t.Errorf("want StatusMissing, got %+v", got)
	}
}

// TestMavenSigstoreUsesSha256Sidecar — when the .sha256 sidecar is present
// the checker must hash it (64 bytes) instead of streaming the full JAR.
// We assert that no GET ever hits the bare .jar URL.
func TestMavenSigstoreUsesSha256Sidecar(t *testing.T) {
	const knownHex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

	jarFetched := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sigstore.json"):
			w.WriteHeader(http.StatusOK)
			// Malformed bundle — we only care that verify is *attempted*
			// against the sidecar-supplied digest, not that it succeeds.
			_, _ = io.WriteString(w, "not-a-real-bundle")
		case strings.HasSuffix(r.URL.Path, ".jar.sha256"):
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, knownHex+"  foo-1.0.0.jar\n")
		case strings.HasSuffix(r.URL.Path, ".jar"):
			jarFetched = true
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "not used")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	c := newMavenChecker(&http.Client{}, nil)
	c.baseURL = srv.URL

	_ = c.Check(context.Background(), "org.example:foo", "1.0.0")
	if jarFetched {
		t.Error("checker should have used the .sha256 sidecar and skipped fetching the .jar")
	}
}

func TestParseHexSHA256(t *testing.T) {
	cases := []struct {
		body string
		ok   bool
	}{
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", true},
		{"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  foo.jar\n", true},
		{"  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n", true},
		{"not-hex", false},
		{"", false},
		{"e3b0c4", false}, // too short
	}
	for _, c := range cases {
		if _, ok := parseHexSHA256([]byte(c.body)); ok != c.ok {
			t.Errorf("parseHexSHA256(%q) = ok:%v, want %v", c.body, ok, c.ok)
		}
	}
}

// TestMavenCheckerPGPSidecarTriggersFallback confirms we fall through from
// sigstore (404) to PGP path when .asc is present.
func TestMavenCheckerPGPSidecarTriggersFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".sigstore.json") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if strings.HasSuffix(r.URL.Path, ".jar.asc") {
			// Malformed signature — we're not testing PGP cryptography,
			// just that the code path is reached.
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "-----BEGIN PGP SIGNATURE-----\nGARBAGE\n-----END PGP SIGNATURE-----\n")
			return
		}
		if strings.HasSuffix(r.URL.Path, ".jar") {
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "fake jar bytes")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newMavenChecker(&http.Client{}, nil)
	c.baseURL = srv.URL

	got := c.Check(context.Background(), "org.example:foo", "1.0.0")
	// Expect StatusFailed (pgp verify fails on garbage) with
	// AttestationType = "pgp-detached", confirming we reached the PGP branch.
	if got.Status != StatusFailed || got.AttestationType != "pgp-detached" {
		t.Errorf("want StatusFailed/pgp-detached, got %+v", got)
	}
}

// TestMavenCheckerPGPVerifiedHappyPath stands up a fake Maven repo that
// serves a real .jar + a real .asc generated against a freshly minted PGP
// keypair, plus a fake keyserver that returns the matching public key.
// Confirms AttestationType="pgp-detached", Status=verified, and that the
// trust-not-validated warning is attached.
func TestMavenCheckerPGPVerifiedHappyPath(t *testing.T) {
	signer, err := openpgp.NewEntity("Maven Signer", "", "maven@example.com", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}

	jarBytes := []byte("PK\x03\x04 fake jar contents")
	var sigBuf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&sigBuf, signer, bytes.NewReader(jarBytes), nil); err != nil {
		t.Fatalf("ArmoredDetachSign: %v", err)
	}
	sigBytes := sigBuf.Bytes()

	var pubBuf bytes.Buffer
	w, err := armor.Encode(&pubBuf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	if err := signer.Serialize(w); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	_ = w.Close()
	pubArmored := pubBuf.Bytes()

	// Keyserver: returns the public key for any /vks/v1 lookup.
	ks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/vks/v1/") {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(pubArmored)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ks.Close()

	// Maven repo: 404s sigstore sidecar, serves jar + asc.
	repo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sigstore.json"):
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, ".jar.asc"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(sigBytes)
		case strings.HasSuffix(r.URL.Path, ".jar"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(jarBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer repo.Close()

	c := newMavenChecker(&http.Client{}, nil)
	c.baseURL = repo.URL
	c.pgp = pgpverify.NewVerifier(ks.Client(), ks.URL)

	got := c.Check(context.Background(), "org.example:foo", "1.0.0")
	if got.Status != StatusVerified {
		t.Fatalf("Status = %q, want verified; result=%+v", got.Status, got)
	}
	if got.AttestationType != "pgp-detached" {
		t.Errorf("AttestationType = %q, want pgp-detached", got.AttestationType)
	}
	if got.BundleFormat != "gpg-detached" {
		t.Errorf("BundleFormat = %q, want gpg-detached", got.BundleFormat)
	}
	if got.BuilderID != "maven@example.com" {
		t.Errorf("BuilderID = %q, want maven@example.com", got.BuilderID)
	}
	foundWarning := false
	for _, wn := range got.Warnings {
		if strings.Contains(wn, "trust not validated") {
			foundWarning = true
		}
	}
	if !foundWarning {
		t.Errorf("expected a 'trust not validated' warning, got %v", got.Warnings)
	}
	// Sanity: keyserver URL the Verifier reports must round-trip cleanly.
	if _, err := url.Parse(c.pgp.Keyserver()); err != nil {
		t.Errorf("keyserver URL unparseable: %v", err)
	}
}

// TestMavenCheckerPGPKeyMissingIsUnavailable: the .asc fetches fine but the
// keyserver doesn't have the key. Expect StatusUnavailable + a warning, NOT
// StatusFailed (we don't penalise for keyserver outages).
func TestMavenCheckerPGPKeyMissingIsUnavailable(t *testing.T) {
	signer, err := openpgp.NewEntity("Lonely Signer", "", "lonely@example.com", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	jarBytes := []byte("contents")
	var sigBuf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&sigBuf, signer, bytes.NewReader(jarBytes), nil); err != nil {
		t.Fatalf("ArmoredDetachSign: %v", err)
	}

	// Keyserver: always 404.
	ks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ks.Close()

	repo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".sigstore.json"):
			w.WriteHeader(http.StatusNotFound)
		case strings.HasSuffix(r.URL.Path, ".jar.asc"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(sigBuf.Bytes())
		case strings.HasSuffix(r.URL.Path, ".jar"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(jarBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer repo.Close()

	c := newMavenChecker(&http.Client{}, nil)
	c.baseURL = repo.URL
	c.pgp = pgpverify.NewVerifier(ks.Client(), ks.URL)

	got := c.Check(context.Background(), "org.example:foo", "1.0.0")
	if got.Status != StatusUnavailable {
		t.Errorf("Status = %q, want unavailable; got=%+v", got.Status, got)
	}
	if got.AttestationType != "pgp-detached" {
		t.Errorf("AttestationType = %q, want pgp-detached", got.AttestationType)
	}
}
