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
}

// DefaultKeyserver is queried by LookupKey when no keyserver is specified.
const DefaultKeyserver = "https://keys.openpgp.org"

// Verifier verifies armored detached signatures. A zero-value Verifier is
// NOT usable; build via NewVerifier.
type Verifier struct {
	client    *http.Client
	keyserver string

	mu    sync.Mutex
	cache map[string]*list.Element // keyID → element holding cacheEntry
	lru   *list.List               // front = most recently used
}

type cacheEntry struct {
	keyID    string
	entities openpgp.EntityList
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
	for _, kid := range keyIDs {
		entities, err := v.LookupKey(ctx, kid)
		if err != nil {
			continue // try the next key ID
		}
		keyring = append(keyring, entities...)
	}
	if len(keyring) == 0 {
		return nil, fmt.Errorf("no candidate public keys found on keyserver for %v", keyIDs)
	}

	signer, err := openpgp.CheckArmoredDetachedSignature(
		keyring, artifact, bytes.NewReader(armoredSig), nil,
	)
	if err != nil {
		return nil, fmt.Errorf("pgp verify: %w", err)
	}

	uid := &SignerUID{
		Fingerprint: fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint),
	}
	for _, id := range signer.Identities {
		uid.Name = id.UserId.Name
		uid.Email = id.UserId.Email
		break
	}
	return uid, nil
}

// LookupKey fetches a public key from the configured keyserver by key ID or
// fingerprint (hex, with optional "0x" prefix). Results are cached
// in-process.
func (v *Verifier) LookupKey(ctx context.Context, keyID string) (openpgp.EntityList, error) {
	keyID = strings.TrimPrefix(strings.ToUpper(keyID), "0X")

	v.mu.Lock()
	if elem, ok := v.cache[keyID]; ok {
		v.lru.MoveToFront(elem)
		entities := elem.Value.(*cacheEntry).entities
		v.mu.Unlock()
		return entities, nil
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
		return nil, fmt.Errorf("unsupported pgp key identifier length %d (want 16 or 40 hex chars)", len(keyID))
	}
	url := fmt.Sprintf("%s/vks/v1/%s/%s", strings.TrimRight(v.keyserver, "/"), endpoint, keyID)
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

	v.mu.Lock()
	if elem, ok := v.cache[keyID]; ok {
		// Lost a race with another goroutine that just inserted the same
		// key. Promote and reuse theirs to avoid keeping two copies.
		v.lru.MoveToFront(elem)
		entities = elem.Value.(*cacheEntry).entities
	} else {
		elem := v.lru.PushFront(&cacheEntry{keyID: keyID, entities: entities})
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
