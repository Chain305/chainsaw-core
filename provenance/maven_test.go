package provenance

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/chain305/chainsaw-core/provenance/pgpverify"
	"github.com/chain305/chainsaw-core/upstreamhttp"
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

// The provenance provider passes the upstream URL of the file the proxy served
// as sourceURL, and for a POM that is the full file path. Appending the
// coordinate to it asked for ".../x-1.0.pom/org/example/x/1.0/x-1.0.jar.asc"
// on every such row. Every request must land on the coordinate's own path.
func TestMavenCheckerTrimsFileSourceURLToRepoBase(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	c := newMavenChecker(&http.Client{}, nil)
	source := srv.URL + "/maven2/org/example/foo/1.0.0/foo-1.0.0.pom"
	got := c.CheckWithSource(context.Background(), "org.example:foo", "1.0.0", source)
	if got.Status != StatusMissing {
		t.Errorf("want StatusMissing, got %+v", got)
	}
	if len(paths) == 0 {
		t.Fatal("checker made no requests")
	}
	for _, p := range paths {
		if !strings.HasPrefix(p, "/maven2/org/example/foo/1.0.0/foo-1.0.0.jar") {
			t.Errorf("request %q is not under the repo base; the source URL was not trimmed", p)
		}
	}
}

func TestMavenRepoBase(t *testing.T) {
	cases := []struct{ source, group, want string }{
		{"https://repo1.maven.org/maven2", "org/example", "https://repo1.maven.org/maven2"},
		{"https://repo1.maven.org/maven2/", "org/example", "https://repo1.maven.org/maven2"},
		{"https://repo1.maven.org/maven2/org/example/foo/1.0/foo-1.0.pom", "org/example", "https://repo1.maven.org/maven2"},
		{"", "org/example", ""},
	}
	for _, c := range cases {
		if got := mavenRepoBase(c.source, c.group); got != c.want {
			t.Errorf("mavenRepoBase(%q, %q) = %q, want %q", c.source, c.group, got, c.want)
		}
	}
}

type errRT struct{ err error }

func (e errRT) RoundTrip(*http.Request) (*http.Response, error) { return nil, e.err }

// A fetch refused for rate checked nothing, so it must not read as the status
// a tampered artifact gets. 22 of 28 "failed" gradle rows sampled after
// v0.22.139 were Central 429s or our own limiter.
func TestMavenCheckerRateLimitedIsUnavailableNotFailed(t *testing.T) {
	// The sigstore sidecar 404s so the checker reaches the PGP path; the
	// 429 lands on the .asc and, in the second case, on the jar.
	for _, tc := range []struct {
		name   string
		status func(path string) int
	}{
		{"asc", func(p string) int {
			if strings.HasSuffix(p, ".asc") {
				return http.StatusTooManyRequests
			}
			return http.StatusNotFound
		}},
		{"jar", func(p string) int {
			switch {
			case strings.HasSuffix(p, ".asc"):
				return http.StatusOK
			case strings.HasSuffix(p, ".jar"):
				return http.StatusTooManyRequests
			}
			return http.StatusNotFound
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status(r.URL.Path))
			}))
			defer srv.Close()
			c := newMavenChecker(&http.Client{}, nil)
			c.baseURL = srv.URL
			got := c.Check(context.Background(), "org.example:foo", "1.0.0")
			if got.Status != StatusUnavailable || got.Reason != ReasonRateLimited {
				t.Errorf("Central 429: got %q/%q, want %q/%q (%+v)",
					got.Status, got.Reason, StatusUnavailable, ReasonRateLimited, got)
			}
		})
	}

	t.Run("local limiter", func(t *testing.T) {
		c := newMavenChecker(&http.Client{Transport: errRT{upstreamhttp.ErrUpstreamStandoff}}, nil)
		got := c.Check(context.Background(), "org.example:foo", "1.0.0")
		if got.Status != StatusUnavailable || got.Reason != ReasonRateLimited {
			t.Errorf("standoff: got %q/%q, want %q/%q (%+v)",
				got.Status, got.Reason, StatusUnavailable, ReasonRateLimited, got)
		}
	})

	// Only rate is reclassified: a 500 on the signature is still a failure.
	t.Run("500 stays failed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv.Close()
		c := newMavenChecker(&http.Client{}, nil)
		c.baseURL = srv.URL
		if got := c.Check(context.Background(), "org.example:foo", "1.0.0"); got.Status != StatusFailed {
			t.Errorf("500: got %q, want %q", got.Status, StatusFailed)
		}
	})
}

// The provenance provider hands the checker the bytes the scanner already
// fetched. A signature that verifies over them must not cost a second jar
// download; held bytes that are some other file of the coordinate (the .pom
// the proxy served, an .aar) must still reach the jar rather than read as a
// tampered artifact; and a missing signing key is decided without the jar.
func TestMavenCheckerPGPVerifiesHeldBytesWithoutRefetchingJar(t *testing.T) {
	signer, err := openpgp.NewEntity("Maven Signer", "", "maven@example.com", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	jarBytes := []byte("PK\x03\x04 held jar contents")
	var sigBuf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&sigBuf, signer, bytes.NewReader(jarBytes), nil); err != nil {
		t.Fatalf("ArmoredDetachSign: %v", err)
	}
	var pubBuf bytes.Buffer
	w, err := armor.Encode(&pubBuf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	if err := signer.Serialize(w); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	_ = w.Close()

	cases := []struct {
		name         string
		held         []byte
		keyKnown     bool
		wantStatus   Status
		wantJarFetch int
	}{
		{"held bytes are the jar", jarBytes, true, StatusVerified, 0},
		{"held bytes are the pom", []byte("<project/>"), true, StatusVerified, 1},
		{"no held bytes", nil, true, StatusVerified, 1},
		{"signing key missing", []byte("<project/>"), false, StatusUnavailable, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.keyKnown && strings.Contains(r.URL.Path, "/vks/v1/") {
					_, _ = w.Write(pubBuf.Bytes())
					return
				}
				w.WriteHeader(http.StatusNotFound)
			}))
			defer ks.Close()
			jarFetches := 0
			repo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, ".jar.asc"):
					_, _ = w.Write(sigBuf.Bytes())
				case strings.HasSuffix(r.URL.Path, ".jar"):
					jarFetches++
					_, _ = w.Write(jarBytes)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer repo.Close()

			c := newMavenChecker(&http.Client{}, nil)
			c.baseURL = repo.URL
			c.pgp = pgpverify.NewVerifier(ks.Client(), ks.URL)

			ctx := WithArtifactBytes(context.Background(), tc.held)
			got := c.Check(ctx, "org.example:foo", "1.0.0")
			if got.Status != tc.wantStatus {
				t.Fatalf("Status = %q, want %q; result=%+v", got.Status, tc.wantStatus, got)
			}
			if jarFetches != tc.wantJarFetch {
				t.Errorf("jar fetched %d times, want %d", jarFetches, tc.wantJarFetch)
			}
		})
	}
}

// pathRT answers by path whatever the host, and records every URL asked.
type pathRT struct {
	files map[string][]byte // path suffix -> body
	asked []string
}

func (rt *pathRT) RoundTrip(r *http.Request) (*http.Response, error) {
	rt.asked = append(rt.asked, r.URL.Host+r.URL.Path)
	for suffix, body := range rt.files {
		if strings.HasSuffix(r.URL.Path, suffix) {
			return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}, Request: r}, nil
		}
	}
	return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}, nil
}

// Google Maven hosts androidx as .aar and publishes no sigstore bundles:
// probing `.jar.asc` read every androidx row as unsigned. A Google base must
// probe the .aar signature first, skip sigstore, and still find a .jar
// (annotation-jvm, the Android Gradle plugin) when there is no .aar.
func TestMavenCheckerGoogleMavenProbesAarThenJar(t *testing.T) {
	signer, err := openpgp.NewEntity("Android", "", "android@example.com", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	body := []byte("PK\x03\x04 artifact")
	var sig, pub bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&sig, signer, bytes.NewReader(body), nil); err != nil {
		t.Fatalf("sign: %v", err)
	}
	w, _ := armor.Encode(&pub, openpgp.PublicKeyType, nil)
	_ = signer.Serialize(w)
	_ = w.Close()

	for _, ext := range []string{"aar", "jar"} {
		t.Run(ext, func(t *testing.T) {
			rt := &pathRT{files: map[string][]byte{
				"-1.9.0." + ext + ".asc": sig.Bytes(),
				"-1.9.0." + ext:          body,
				"/vks/v1/by-fingerprint/" + fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint): pub.Bytes(),
			}}
			client := &http.Client{Transport: rt}
			c := newMavenChecker(client, nil)
			c.pgp = pgpverify.NewVerifier(client, "https://keys.test")

			got := c.CheckWithSource(context.Background(), "androidx.activity:activity", "1.9.0", GoogleMavenBase)
			if got.Status != StatusVerified {
				t.Fatalf("Status = %q, want verified; asked %v; result %+v", got.Status, rt.asked, got)
			}
			for _, u := range rt.asked {
				if strings.HasSuffix(u, ".sigstore.json") {
					t.Errorf("probed a sigstore bundle on Google Maven: %s", u)
				}
				if !strings.HasPrefix(u, "dl.google.com/dl/android/maven2/") && !strings.HasPrefix(u, "keys.test/") {
					t.Errorf("asked a host other than Google Maven: %s", u)
				}
			}
		})
	}
}
