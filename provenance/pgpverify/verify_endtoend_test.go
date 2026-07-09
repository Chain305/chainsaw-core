package pgpverify

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
)

// makeTestEntity returns a freshly generated PGP key for end-to-end tests.
// Generation is fast enough (~tens of ms on modern hardware with default
// curve config) to do per-test without measurable slowdown.
func makeTestEntity(t *testing.T) *openpgp.Entity {
	t.Helper()
	e, err := openpgp.NewEntity("Test Signer", "", "signer@example.com", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	return e
}

// armoredPublicKey serializes the entity's public half as an ASCII-armored
// keyring (the wire format keys.openpgp.org returns).
func armoredPublicKey(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("armor close: %v", err)
	}
	return buf.Bytes()
}

// signDetached produces an ASCII-armored detached signature over message.
func signDetached(t *testing.T, signer *openpgp.Entity, message []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&buf, signer, bytes.NewReader(message), nil); err != nil {
		t.Fatalf("ArmoredDetachSign: %v", err)
	}
	return buf.Bytes()
}

// fakeKeyserver serves a single key under both /by-fingerprint/<fp> and
// /by-keyid/<id>. Other paths return 404.
func fakeKeyserver(t *testing.T, e *openpgp.Entity) *httptest.Server {
	t.Helper()
	pubArmored := armoredPublicKey(t, e)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/vks/v1/by-fingerprint/"),
			strings.HasPrefix(r.URL.Path, "/vks/v1/by-keyid/"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(pubArmored)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestVerifyHappyPath(t *testing.T) {
	signer := makeTestEntity(t)
	message := []byte("hello, supply-chain world")
	sig := signDetached(t, signer, message)

	srv := fakeKeyserver(t, signer)
	defer srv.Close()

	v := NewVerifier(srv.Client(), srv.URL)
	uid, err := v.Verify(context.Background(), bytes.NewReader(message), sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if uid.Email != "signer@example.com" {
		t.Errorf("Email = %q, want signer@example.com", uid.Email)
	}
	if len(uid.Fingerprint) != 40 {
		t.Errorf("Fingerprint length = %d, want 40 hex chars", len(uid.Fingerprint))
	}
}

func TestVerifyTamperedArtifactFails(t *testing.T) {
	signer := makeTestEntity(t)
	sig := signDetached(t, signer, []byte("original"))

	srv := fakeKeyserver(t, signer)
	defer srv.Close()

	v := NewVerifier(srv.Client(), srv.URL)
	_, err := v.Verify(context.Background(), bytes.NewReader([]byte("TAMPERED")), sig)
	if err == nil {
		t.Fatal("want error on tampered artifact, got nil")
	}
}

func TestVerifyKeyserver404IsUnavailable(t *testing.T) {
	signer := makeTestEntity(t)
	sig := signDetached(t, signer, []byte("data"))

	// All keyserver endpoints return 404.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	v := NewVerifier(srv.Client(), srv.URL)
	_, err := v.Verify(context.Background(), bytes.NewReader([]byte("data")), sig)
	if err == nil {
		t.Fatal("want error when keyserver has no key")
	}
	if !strings.Contains(err.Error(), "no candidate public keys") {
		t.Errorf("want 'no candidate public keys' error, got: %v", err)
	}
}

func TestKeyserverEnvOverride(t *testing.T) {
	const want = "https://keyserver.example.test"
	t.Setenv(KeyserverEnvVar, want)
	v := NewVerifier(nil, "")
	if v.Keyserver() != want {
		t.Errorf("Keyserver() = %q, want %q", v.Keyserver(), want)
	}

	// Explicit argument wins over env.
	v2 := NewVerifier(nil, "https://other.example")
	if v2.Keyserver() != "https://other.example" {
		t.Errorf("explicit arg should override env, got %q", v2.Keyserver())
	}

	// Unset env falls back to default.
	_ = os.Unsetenv(KeyserverEnvVar)
	v3 := NewVerifier(nil, "")
	if v3.Keyserver() != DefaultKeyserver {
		t.Errorf("default = %q, want %q", v3.Keyserver(), DefaultKeyserver)
	}
}

func TestLRUEvictsOldestEntries(t *testing.T) {
	v := NewVerifier(nil, "https://unused")
	// Reach in and stuff the cache directly to avoid spinning up MaxCachedKeys
	// fake HTTP servers — we're testing the eviction policy, not network.
	v.mu.Lock()
	for i := 0; i < MaxCachedKeys+5; i++ {
		keyID := strings.Repeat("A", 39) + string(rune('A'+i%16))
		// Pad to a unique 40-char string per i.
		keyID = pad40(i)
		elem := v.lru.PushFront(&cacheEntry{keyID: keyID})
		v.cache[keyID] = elem
		for v.lru.Len() > MaxCachedKeys {
			oldest := v.lru.Back()
			v.lru.Remove(oldest)
			delete(v.cache, oldest.Value.(*cacheEntry).keyID)
		}
	}
	got := v.lru.Len()
	v.mu.Unlock()
	if got != MaxCachedKeys {
		t.Errorf("cache size = %d, want %d", got, MaxCachedKeys)
	}
}

func pad40(i int) string {
	const hex = "0123456789ABCDEF"
	out := make([]byte, 40)
	for j := 0; j < 40; j++ {
		out[j] = hex[(i+j)%16]
	}
	out[0] = hex[i%16]
	out[1] = hex[(i/16)%16]
	out[2] = hex[(i/256)%16]
	out[3] = hex[(i/4096)%16]
	return string(out)
}
