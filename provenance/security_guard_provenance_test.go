package provenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/chain305/chainsaw-core/provenance/pgpverify"
)

// TestSecurityGuard_MavenPGPBoundToHeldBytes pins pentest #13's PGP half.
// When the scanner holds the bytes being served, the verdict is about THOSE
// bytes: a .asc that verifies the genuine upstream jar says nothing about an
// unsigned jar an org uploaded under the same coordinate. The old code fell
// back to downloading the upstream jar and reported `verified`. Every
// verified result also records the sha256 it was verified over, so the proxy
// can refuse to lend the verdict to different bytes.
func TestSecurityGuard_MavenPGPBoundToHeldBytes(t *testing.T) {
	signer, err := openpgp.NewEntity("Maven Signer", "", "maven@example.com", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	genuine := []byte("PK\x03\x04 genuine upstream jar")
	var sig bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&sig, signer, bytes.NewReader(genuine), nil); err != nil {
		t.Fatalf("sign: %v", err)
	}
	var pub bytes.Buffer
	w, _ := armor.Encode(&pub, openpgp.PublicKeyType, nil)
	_ = signer.Serialize(w)
	_ = w.Close()
	ks := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(pub.Bytes())
	}))
	defer ks.Close()
	repo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ".jar.asc"):
			_, _ = w.Write(sig.Bytes())
		case strings.HasSuffix(r.URL.Path, ".jar"):
			_, _ = w.Write(genuine)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer repo.Close()
	check := func(held []byte) Result {
		c := newMavenChecker(&http.Client{}, nil)
		c.baseURL = repo.URL
		c.pgp = pgpverify.NewVerifier(ks.Client(), ks.URL)
		return c.Check(WithArtifactBytes(context.Background(), held), "org.example:foo", "1.0.0")
	}
	sha := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

	if got := check([]byte("PK\x03\x04 unsigned jar an org uploaded")); got.Status == StatusVerified {
		t.Fatalf("held bytes the signature does not cover read as verified (upstream fallback): %+v", got)
	}
	// Positive controls: the genuine bytes verify, held or fetched, and the
	// result names the bytes it is about.
	for name, held := range map[string][]byte{"held genuine": genuine, "nothing held": nil} {
		got := check(held)
		if got.Status != StatusVerified || got.VerifiedSHA256 != sha(genuine) {
			t.Fatalf("%s: got %q verifiedSha256=%q, want verified over %s", name, got.Status, got.VerifiedSHA256, sha(genuine))
		}
	}
}
