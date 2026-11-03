// Package pgpverify is a thin wrapper around ProtonMail/go-crypto that
// verifies an ASCII-armored detached PGP signature against an artifact,
// fetching the public key from keys.openpgp.org on demand.
//
// The package keeps an in-process LRU-ish cache of fetched keys to avoid
// refetching the same key for every artifact in the same repo.
package pgpverify

import (
	"bytes"
	"container/list"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	pgperrors "github.com/ProtonMail/go-crypto/openpgp/errors"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/chain305/chainsaw-core/httpclient"
)

// KeyserverEnvVar lets operators override the default keyserver without
// recompiling. Read once when NewVerifier is called.
const KeyserverEnvVar = "CHAINSAW_PGP_KEYSERVER"

// MaxCachedKeys caps the in-process key cache. The cache is intentionally
// memory-only (per-process, never persisted) — supply-chain trust roots
// MUST be re-fetched on restart. The bound prevents a malicious or
// malformed signature stream from pinning unbounded memory.
const MaxCachedKeys = 1000

// SignerUID identifies the verifying key by its user-ID string (e.g.
// "Alice <alice@example.com>") and short fingerprint.
type SignerUID struct {
	Name        string
	Email       string
	Fingerprint string // hex-encoded 20-byte fingerprint
	Keyserver   string // the keyserver the verifying key came from
	// SignedAt is the signature's creation time, the instant the key is
	// judged at; KeyExpired reports that the key has expired since.
	SignedAt   time.Time
	KeyExpired bool
}

// DefaultKeyserver is queried by LookupKey when no keyserver is specified.
const DefaultKeyserver = "https://keys.openpgp.org"

// FallbackKeyserver is asked only when the primary keyserver returns a key
// with every user ID stripped. keys.openpgp.org publishes a UID only after
// its owner verifies the address, and go-crypto refuses a key with no UID at
// all ("v4 entity without any identities"), so such a key could never verify
// anything: the signing key of every androidx artifact on Google Maven
// (A5F483CD733A4EBAEA378B2AE88979FB9B30ACF2) is served that way, while the
// Ubuntu keyserver serves the same key with its UID (verified 2026-11-03).
const FallbackKeyserver = "https://keyserver.ubuntu.com"

// Verifier verifies armored detached signatures. A zero-value Verifier is
// NOT usable; build via NewVerifier.
type Verifier struct {
	client    *http.Client
	keyserver string
	// fallback is FallbackKeyserver; empty disables it (tests).
	fallback string

	mu    sync.Mutex
	cache map[string]*list.Element // keyID → element holding cacheEntry
	lru   *list.List               // front = most recently used
}

type cacheEntry struct {
	keyID    string
	entities openpgp.EntityList
	// fromFallback marks a key fetched from the fallback keyserver.
	fromFallback bool
}

// NewVerifier returns a Verifier with the given HTTP client (8 s default
// if nil) and keyserver. Resolution order for the keyserver:
//  1. explicit non-empty argument
//  2. CHAINSAW_PGP_KEYSERVER env var
//  3. DefaultKeyserver (keys.openpgp.org)
//
// The trust policy is intentionally minimal: we verify that the .asc was
// produced by *some* key that the keyserver returns for the issuer
// fingerprint. We do NOT walk a web-of-trust, do NOT validate that the
// key is "owned" by anyone in particular, and do NOT pin to a registry
// of approved signing keys. Callers that need a stronger root should
// layer policy on top of the SignerID returned in Result.
func NewVerifier(client *http.Client, keyserver string) *Verifier {
	if client == nil {
		client = httpclient.New(httpclient.WithTimeout(8 * time.Second))
	}
	if keyserver == "" {
		keyserver = strings.TrimSpace(os.Getenv(KeyserverEnvVar))
	}
	if keyserver == "" {
		keyserver = DefaultKeyserver
	}
	return &Verifier{
		client:    client,
		keyserver: keyserver,
		fallback:  FallbackKeyserver,
		cache:     map[string]*list.Element{},
		lru:       list.New(),
	}
}

// Keyserver reports the keyserver URL the Verifier will query. Useful for
// tests asserting env-var resolution.
func (v *Verifier) Keyserver() string { return v.keyserver }

// Verify checks an ASCII-armored detached signature over the given
// artifact. The artifact is consumed as a stream so callers don't have to
// buffer large JARs/tarballs. It tries to look up every signing key
// referenced by the signature on the configured keyserver, then calls
// openpgp.CheckArmoredDetachedSignature. Returns the signer's UID on success.
func (v *Verifier) Verify(ctx context.Context, artifact io.Reader, armoredSig []byte) (*SignerUID, error) {
	// First pass: discover which key IDs the signature claims.
	keyIDs, err := signatureKeyIDs(armoredSig)
	if err != nil {
		return nil, fmt.Errorf("parse signature: %w", err)
	}
	if len(keyIDs) == 0 {
		return nil, fmt.Errorf("signature contains no issuer key IDs")
	}

	// Fetch all candidate keys.
	var keyring openpgp.EntityList
	fallbackKeys := map[string]bool{}
	for _, kid := range keyIDs {
		entities, fromFallback, err := v.lookup(ctx, kid)
		if err != nil {
			continue // try the next key ID
		}
		if fromFallback {
			for _, e := range entities {
				fallbackKeys[fmt.Sprintf("%X", e.PrimaryKey.Fingerprint)] = true
			}
		}
		keyring = append(keyring, entities...)
	}
	if len(keyring) == 0 {
		return nil, fmt.Errorf("no candidate public keys found on keyserver for %v", keyIDs)
	}

	// The key is judged as it stood when the signature was made, which is
	// what gpg does ("Good signature" plus an expired-key note). Judged at
	// today's date, every artifact signed before its key expired fails as
	// if tampered with: the androidx signing subkey has expired, and
	// activity-1.9.0.aar read "key expired" (2026-11-03).
	sig, err := firstSignature(armoredSig)
	if err != nil {
		return nil, fmt.Errorf("parse signature: %w", err)
	}
	now := time.Now()
	at := sig.CreationTime
	signer, err := openpgp.CheckArmoredDetachedSignature(
		keyring, artifact, bytes.NewReader(armoredSig), &packet.Config{Time: func() time.Time { return at }},
	)
	if err != nil {
		return nil, fmt.Errorf("pgp verify: %w", err)
	}
	// The signer chooses the creation time, so what must hold TODAY is still
	// checked today: a revocation issued after that date (go-crypto treats a
	// revocation newer than its clock as not yet in force), and the message
	// signature's own expiry, which also refuses a signature dated in the
	// future.
	if keyRevoked(signer, sig, now) {
		return nil, fmt.Errorf("pgp verify: %w", pgperrors.ErrKeyRevoked)
	}
	if sig.SigExpired(now) {
		return nil, fmt.Errorf("pgp verify: %w", pgperrors.ErrSignatureExpired)
	}

	uid := &SignerUID{
		Fingerprint: fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint),
		Keyserver:   v.keyserver,
		SignedAt:    sig.CreationTime,
		KeyExpired:  keyExpired(signer, sig, now),
	}
	if fallbackKeys[uid.Fingerprint] {
		// The fallback keyserver does not verify user IDs: anyone can
		// attach any name to a key there. The key itself is bound by the
		// fingerprint the signature names, so it still verifies; its UID
		// is a claim, and is not reported as the signer.
		uid.Keyserver = v.fallback
		return uid, nil
	}
	for _, id := range signer.Identities {
		uid.Name = id.UserId.Name
		uid.Email = id.UserId.Email
		break
	}
	return uid, nil
}

// keyRevoked reports whether, at now, the signer's primary key, its primary
// identity or the subkey that made sig carries a revocation.
func keyRevoked(signer *openpgp.Entity, sig *packet.Signature, now time.Time) bool {
	if signer.Revoked(now) {
		return true
	}
	if _, id := signer.PrimarySelfSignature(); id != nil && id.Revoked(now) {
		return true
	}
	for i := range signer.Subkeys {
		sk := &signer.Subkeys[i]
		if sig.IssuerKeyId != nil && sk.PublicKey.KeyId == *sig.IssuerKeyId && sk.Revoked(now) {
			return true
		}
	}
	return false
}

// keyExpired reports whether the primary key, or the subkey that made sig,
// has expired by now.
func keyExpired(signer *openpgp.Entity, sig *packet.Signature, now time.Time) bool {
	if self, _ := signer.PrimarySelfSignature(); self != nil && signer.PrimaryKey.KeyExpired(self, now) {
		return true
	}
	for i := range signer.Subkeys {
		sk := &signer.Subkeys[i]
		if sig.IssuerKeyId != nil && sk.PublicKey.KeyId == *sig.IssuerKeyId && sk.Sig != nil && sk.PublicKey.KeyExpired(sk.Sig, now) {
			return true
		}
	}
	return false
}

// LookupKey fetches a public key from the configured keyserver by key ID or
// fingerprint (hex, with optional "0x" prefix). Results are cached
// in-process.
func (v *Verifier) LookupKey(ctx context.Context, keyID string) (openpgp.EntityList, error) {
	entities, _, err := v.lookup(ctx, keyID)
	return entities, err
}

// lookup is LookupKey that also reports whether the key came from the
// fallback keyserver.
func (v *Verifier) lookup(ctx context.Context, keyID string) (openpgp.EntityList, bool, error) {
	keyID = strings.TrimPrefix(strings.ToUpper(keyID), "0X")

	v.mu.Lock()
	if elem, ok := v.cache[keyID]; ok {
		v.lru.MoveToFront(elem)
		entry := elem.Value.(*cacheEntry)
		v.mu.Unlock()
		return entry.entities, entry.fromFallback, nil
	}
	v.mu.Unlock()

	// keys.openpgp.org exposes two lookup endpoints: /vks/v1/by-fingerprint
	// for the full 20-byte v4 fingerprint (40 hex chars) and /vks/v1/by-keyid
	// for the 8-byte long key ID (16 hex chars). Older signatures that carry
	// only an IssuerKeyId subpacket (no v4 IssuerFingerprint) land on the
	// short-ID endpoint.
	var endpoint string
	switch len(keyID) {
	case 40:
		endpoint = "by-fingerprint"
	case 16:
		endpoint = "by-keyid"
	default:
		return nil, false, fmt.Errorf("unsupported pgp key identifier length %d (want 16 or 40 hex chars)", len(keyID))
	}
	entities, err := v.fetchKeyRing(ctx, fmt.Sprintf("%s/vks/v1/%s/%s", strings.TrimRight(v.keyserver, "/"), endpoint, keyID), keyID)
	fromFallback := false
	if err != nil && v.fallback != "" && strings.Contains(err.Error(), "without any identities") {
		fb, ferr := v.fetchKeyRing(ctx, fmt.Sprintf("%s/pks/lookup?op=get&options=mr&search=0x%s", strings.TrimRight(v.fallback, "/"), keyID), keyID)
		if ferr == nil {
			entities, err, fromFallback = fb, nil, true
		}
	}
	if err != nil {
		return nil, false, err
	}

	v.mu.Lock()
	if elem, ok := v.cache[keyID]; ok {
		// Lost a race with another goroutine that just inserted the same
		// key. Promote and reuse theirs to avoid keeping two copies.
		v.lru.MoveToFront(elem)
		entities = elem.Value.(*cacheEntry).entities
	} else {
		elem := v.lru.PushFront(&cacheEntry{keyID: keyID, entities: entities, fromFallback: fromFallback})
		v.cache[keyID] = elem
		// Evict LRU entries beyond the cap. We do this in a loop in case
		// MaxCachedKeys is ever lowered at runtime (currently it isn't).
		for v.lru.Len() > MaxCachedKeys {
			oldest := v.lru.Back()
			if oldest == nil {
				break
			}
			v.lru.Remove(oldest)
			delete(v.cache, oldest.Value.(*cacheEntry).keyID)
		}
	}
	v.mu.Unlock()
	return entities, fromFallback, nil
}

// fetchKeyRing GETs an armored key from url and parses it.
func (v *Verifier) fetchKeyRing(ctx context.Context, url, keyID string) (openpgp.EntityList, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keyserver returned HTTP %d for %s", resp.StatusCode, keyID)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MiB
	if err != nil {
		return nil, err
	}
	entities, err := openpgp.ReadArmoredKeyRing(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("parse key %s: %w", keyID, err)
	}
	return entities, nil
}

// signatureKeyIDs extracts the issuer key IDs / fingerprints from an
// ASCII-armored detached signature without verifying it.
func signatureKeyIDs(armoredSig []byte) ([]string, error) {
	// Simplest path: parse packets and collect signature issuer IDs.
	// We use openpgp's armor + packet machinery.
	//
	// Rather than pull in packet.Reader directly, we lean on the fact
	// that CheckArmoredDetachedSignature returns openpgp.errors.ErrUnknownIssuer
	// when the keyring is empty but gives us IssuerKeyId in the wrapped
	// error chain — but that's fragile. Parse directly instead.
	return parseIssuerKeyIDs(armoredSig)
}
