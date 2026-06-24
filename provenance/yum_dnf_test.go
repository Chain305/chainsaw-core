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
)

func TestYumHappyPath(t *testing.T) {
	srv, entity := newYumFixtureServer(t, yumFixture{
		packageName: "curl",
		version:     "7.88.0",
		release:     "1.fc40",
		rpmBody:     []byte("fake-curl-7.88.0-1.fc40 .rpm content"),
	})
	defer srv.Close()

	c := &yumChecker{
		client: srv.Client(),

		keyringOverride: openpgp.EntityList{entity},
	}
	res := c.CheckWithSource(context.Background(), "curl", "7.88.0", srv.URL)
	if res.Status != StatusVerified {
		t.Fatalf("status = %q (%s), want StatusVerified", res.Status, res.Error)
	}
	if res.AttestationType != "pgp-repo" {
		t.Errorf("attestationType = %q", res.AttestationType)
	}
}

func TestYumTamperedPrimary(t *testing.T) {
	f := yumFixture{
		packageName: "curl",
		version:     "7.88.0",
		release:     "1.fc40",
		rpmBody:     []byte("fake-curl .rpm"),
		tamperPrimary: func(b []byte) []byte {
			out := append([]byte(nil), b...)
			out[0] ^= 0xFF
			return out
		},
	}
	srv, entity := newYumFixtureServer(t, f)
	defer srv.Close()

	c := &yumChecker{
		client: srv.Client(),

		keyringOverride: openpgp.EntityList{entity},
	}
	res := c.CheckWithSource(context.Background(), "curl", "7.88.0", srv.URL)
	if res.Status != StatusFailed {
		t.Fatalf("status = %q (%s), want StatusFailed", res.Status, res.Error)
	}
	if !strings.Contains(res.Error, "primary.xml sha256 mismatch") {
		t.Errorf("error = %q", res.Error)
	}
}

func TestYumTamperedSignature(t *testing.T) {
	f := yumFixture{
		packageName: "curl",
		version:     "7.88.0",
		release:     "1.fc40",
		rpmBody:     []byte("fake-curl .rpm"),
		tamperSignature: func(b []byte) []byte {
			// Flip one base64 byte inside the armored signature.
			idx := bytes.Index(b, []byte("-----BEGIN PGP SIGNATURE-----"))
			if idx < 0 {
				return b
			}
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
	srv, entity := newYumFixtureServer(t, f)
	defer srv.Close()

	c := &yumChecker{
		client: srv.Client(),

		keyringOverride: openpgp.EntityList{entity},
	}
	res := c.CheckWithSource(context.Background(), "curl", "7.88.0", srv.URL)
	if res.Status != StatusFailed {
		t.Fatalf("status = %q (%s), want StatusFailed", res.Status, res.Error)
	}
	if !strings.Contains(res.Error, "repomd.xml signature") {
		t.Errorf("error = %q", res.Error)
	}
}

func TestYumMissingKeyring(t *testing.T) {
	c := &yumChecker{
		client: &http.Client{Timeout: 1 * time.Second},

		keyringPath: "/nonexistent/rpm/keyring",
	}
	res := c.CheckWithSource(context.Background(), "curl", "7.88.0", "http://127.0.0.1:1/repo")
	if res.Status != StatusUnavailable {
		t.Fatalf("status = %q", res.Status)
	}
	if !strings.Contains(res.Error, "keyring") {
		t.Errorf("error = %q", res.Error)
	}
}

// --- fixture server --------------------------------------------------------

type yumFixture struct {
	packageName     string
	version         string
	release         string
	rpmBody         []byte
	tamperPrimary   func([]byte) []byte
	tamperSignature func([]byte) []byte
}

func newYumFixtureServer(t *testing.T, f yumFixture) (*httptest.Server, *openpgp.Entity) {
	t.Helper()

	entity := newTestPGPEntity(t, "chainsaw-rpm-test", "rpm@chainsaw.invalid")

	rpmSum := sha256.Sum256(f.rpmBody)
	rpmHref := fmt.Sprintf("Packages/%s-%s-%s.x86_64.rpm", f.packageName, f.version, f.release)

	primaryXML := buildPrimaryXML(f.packageName, f.version, f.release, rpmHref, rpmSum, len(f.rpmBody))
	primaryServed := primaryXML
	if f.tamperPrimary != nil {
		primaryServed = f.tamperPrimary(primaryXML)
	}
	primarySum := sha256.Sum256(primaryXML)
	primaryHref := "repodata/primary.xml"

	repomd := buildRepomd(primaryHref, primarySum)
	sig := detachedSignArmored(t, entity, repomd)
	if f.tamperSignature != nil {
		sig = f.tamperSignature(sig)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/repodata/repomd.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write(repomd)
	})
	mux.HandleFunc("/repodata/repomd.xml.asc", func(w http.ResponseWriter, r *http.Request) {
		w.Write(sig)
	})
	mux.HandleFunc("/repodata/primary.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Write(primaryServed)
	})
	mux.HandleFunc("/"+rpmHref, func(w http.ResponseWriter, r *http.Request) {
		w.Write(f.rpmBody)
	})
	return httptest.NewServer(mux), entity
}

func buildRepomd(primaryHref string, primarySum [32]byte) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<repomd xmlns="http://linux.duke.edu/metadata/repo">
  <revision>1234567890</revision>
  <data type="primary">
    <checksum type="sha256">%s</checksum>
    <location href="%s"/>
    <timestamp>1234567890</timestamp>
  </data>
</repomd>`, hex.EncodeToString(primarySum[:]), primaryHref))
}

func buildPrimaryXML(name, ver, rel, href string, sum [32]byte, size int) []byte {
	return []byte(fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<metadata xmlns="http://linux.duke.edu/metadata/common" packages="1">
  <package type="rpm">
    <name>%s</name>
    <arch>x86_64</arch>
    <version epoch="0" ver="%s" rel="%s"/>
    <checksum type="sha256" pkgid="YES">%s</checksum>
    <summary>chainsaw test package</summary>
    <description>chainsaw test package</description>
    <packager>chainsaw</packager>
    <url>http://example.invalid</url>
    <size package="%d" installed="%d" archive="%d"/>
    <location href="%s"/>
  </package>
</metadata>`, name, ver, rel, hex.EncodeToString(sum[:]), size, size, size, href))
}

// detachedSignArmored signs body using entity and returns an armored
// detached signature (what yum/dnf expect in repomd.xml.asc).
func detachedSignArmored(t *testing.T, entity *openpgp.Entity, body []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&out, entity, bytes.NewReader(body), nil); err != nil {
		t.Fatalf("detached sign: %v", err)
	}
	return out.Bytes()
}

// sanity helper used indirectly to silence unused warnings across files.
var _ = io.Discard
