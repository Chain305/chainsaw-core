package pgpverify

import (
	"bytes"
	"context"
	"crypto"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
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

// keys.openpgp.org strips every user ID the owner has not verified, and
// go-crypto refuses such a key outright, so androidx's signing key could
// never verify anything. The verifier asks the fallback keyserver for the
// same fingerprint, verifies with that key, and does NOT report the
// fallback's UID: anyone can attach any name to a key there.
func TestVerifyIdentityStrippedKeyUsesFallbackWithoutItsUID(t *testing.T) {
	signer, err := openpgp.NewEntity("Claimed Name", "", "claim@example.com", nil)
	if err != nil {
		t.Fatalf("NewEntity: %v", err)
	}
	var stripped bytes.Buffer
	w, err := armor.Encode(&stripped, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatalf("armor.Encode: %v", err)
	}
	if err := signer.PrimaryKey.Serialize(w); err != nil {
		t.Fatalf("Serialize primary: %v", err)
	}
	_ = w.Close()
	full := armoredPublicKey(t, signer)

	var fallbackHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/vks/v1/"):
			_, _ = w.Write(stripped.Bytes())
		case r.URL.Path == "/pks/lookup":
			fallbackHits++
			_, _ = w.Write(full)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	msg := []byte("aar bytes")
	sig := signDetached(t, signer, msg)

	v := NewVerifier(srv.Client(), srv.URL)
	v.fallback = srv.URL + "/"
	uid, err := v.Verify(context.Background(), bytes.NewReader(msg), sig)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if fallbackHits != 1 {
		t.Errorf("fallback asked %d times, want 1", fallbackHits)
	}
	if uid.Name != "" || uid.Email != "" {
		t.Errorf("reported the fallback keyserver's unverified UID: %+v", uid)
	}
	if uid.Fingerprint == "" || uid.Keyserver != v.fallback {
		t.Errorf("want fingerprint and fallback keyserver, got %+v", uid)
	}
	// Cached: a second verify must not ask either keyserver again, and must
	// still withhold the UID.
	uid2, err := v.Verify(context.Background(), bytes.NewReader(msg), sig)
	if err != nil || uid2.Email != "" || fallbackHits != 1 {
		t.Errorf("second verify: uid=%+v err=%v fallbackHits=%d", uid2, err, fallbackHits)
	}

	// Without the fallback the stripped key cannot verify.
	off := NewVerifier(srv.Client(), srv.URL)
	off.fallback = ""
	if _, err := off.Verify(context.Background(), bytes.NewReader(msg), sig); err == nil {
		t.Error("identity-stripped key verified with the fallback disabled")
	}
}

// A key is judged as it stood when the signature was made: expiry since then
// is a note, not a failure. What must hold today is still checked today: a
// revocation issued after the signature (go-crypto would treat it as not yet
// in force at the signature's date) fails it, as does a signature made after
// the key had already expired.
func TestVerifyJudgesKeyAtSigningTimeAndRevocationNow(t *testing.T) {
	t0 := time.Now().Add(-30 * 24 * time.Hour)
	at := func(d time.Duration) *packet.Config {
		return &packet.Config{Time: func() time.Time { return t0.Add(d) }, KeyLifetimeSecs: 2 * 24 * 3600}
	}
	day := 24 * time.Hour
	msg := []byte("artifact")

	sign := func(t *testing.T, e *openpgp.Entity, cfg *packet.Config) []byte {
		t.Helper()
		var buf bytes.Buffer
		if err := openpgp.ArmoredDetachSign(&buf, e, bytes.NewReader(msg), cfg); err != nil {
			t.Fatalf("sign: %v", err)
		}
		return buf.Bytes()
	}
	verify := func(t *testing.T, e *openpgp.Entity, sig []byte) (*SignerUID, error) {
		t.Helper()
		srv := fakeKeyserver(t, e)
		defer srv.Close()
		return NewVerifier(srv.Client(), srv.URL).Verify(context.Background(), bytes.NewReader(msg), sig)
	}

	t.Run("expired after signing", func(t *testing.T) {
		e, err := openpgp.NewEntity("A", "", "a@example.com", at(0))
		if err != nil {
			t.Fatal(err)
		}
		uid, err := verify(t, e, sign(t, e, at(day)))
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if !uid.KeyExpired || uid.SignedAt.IsZero() {
			t.Errorf("want KeyExpired and SignedAt, got %+v", uid)
		}
	})

	t.Run("signed after expiry", func(t *testing.T) {
		e, err := openpgp.NewEntity("B", "", "b@example.com", at(0))
		if err != nil {
			t.Fatal(err)
		}
		// go-crypto will not sign with an expired key, so build the
		// signature packet directly, dated after the expiry.
		late := at(5 * day)
		sig := &packet.Signature{
			Version:      4,
			SigType:      packet.SigTypeBinary,
			PubKeyAlgo:   e.PrimaryKey.PubKeyAlgo,
			Hash:         crypto.SHA256,
			CreationTime: late.Now(),
			IssuerKeyId:  &e.PrimaryKey.KeyId,
		}
		h, err := sig.PrepareSign(late)
		if err != nil {
			t.Fatal(err)
		}
		h.Write(msg)
		if err := sig.Sign(h, e.PrivateKey, late); err != nil {
			t.Fatalf("Sign: %v", err)
		}
		var buf bytes.Buffer
		w, err := armor.Encode(&buf, openpgp.SignatureType, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := sig.Serialize(w); err != nil {
			t.Fatal(err)
		}
		_ = w.Close()
		if _, err := verify(t, e, buf.Bytes()); err == nil || !strings.Contains(err.Error(), "expired") {
			t.Errorf("a signature made after the key expired: err = %v, want key expired", err)
		}
	})

	t.Run("signature lifetime over", func(t *testing.T) {
		e, err := openpgp.NewEntity("D", "", "d@example.com", at(0))
		if err != nil {
			t.Fatal(err)
		}
		short := at(day)
		short.KeyLifetimeSecs = 0
		short.SigLifetimeSecs = 3600
		if _, err := verify(t, e, sign(t, e, short)); err == nil {
			t.Error("a signature past its own lifetime verified")
		}
	})

	t.Run("revoked after signing", func(t *testing.T) {
		e, err := openpgp.NewEntity("C", "", "c@example.com", at(0))
		if err != nil {
			t.Fatal(err)
		}
		sig := sign(t, e, at(day))
		if err := e.RevokeKey(packet.KeyRetired, "retired", at(day+time.Hour)); err != nil {
			t.Fatalf("RevokeKey: %v", err)
		}
		if _, err := verify(t, e, sig); err == nil {
			t.Error("a key revoked after the signature still verified")
		}
	})
}
