package provenance

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
)

// ErrNoTrustedKeys is returned by OSRepoKeyring when neither the
// configured keyring path nor the embedded snapshot holds a key.
var ErrNoTrustedKeys = errKeyringEmpty

// OSRepoKeyring returns the keyring the apt ("apt") or yum/dnf ("rpm")
// provenance checkers trust: CHAINSAW_APT_KEYRING / CHAINSAW_RPM_KEYRING,
// falling back to the embedded keys. Exported for callers that verify an
// upstream index before re-signing it, so both paths trust the same keys.
func OSRepoKeyring(kind string) (openpgp.EntityList, error) {
	switch kind {
	case "apt":
		return loadKeyring(os.Getenv("CHAINSAW_APT_KEYRING"), "apt")
	case "rpm":
		return loadKeyring(os.Getenv("CHAINSAW_RPM_KEYRING"), "rpm")
	}
	return nil, fmt.Errorf("unknown os repo keyring %q", kind)
}

// SignerKey names the key that made a signature, as upper-case hex
// fingerprints: Signing is the (sub)key that signed ("" when the
// signature does not say), Primary the primary key it belongs to.
type SignerKey struct{ Signing, Primary string }

// MatchesSignedBy reports whether the signer is one of fingerprints, with
// apt's Signed-By semantics: a fingerprint names the signing key or the
// primary key it is a subkey of; a trailing "!" names the signing key only.
func (k SignerKey) MatchesSignedBy(fingerprints []string) bool {
	for _, fp := range fingerprints {
		exact := strings.HasSuffix(fp, "!")
		fp = strings.ToUpper(strings.TrimSuffix(fp, "!"))
		if fp != "" && ((k.Signing != "" && fp == k.Signing) || (!exact && fp == k.Primary)) {
			return true
		}
	}
	return false
}

// VerifyClearsigned checks a clearsigned document (apt InRelease) against
// keyring and returns the signed text exactly as written (LF line
// endings, dash-escaping removed) and the key that signed it. Nothing
// outside the signed block is returned, so unsigned text around it cannot
// reach the caller.
func VerifyClearsigned(signed []byte, keyring openpgp.KeyRing) ([]byte, SignerKey, error) {
	block, _ := clearsign.Decode(signed)
	if block == nil {
		return nil, SignerKey{}, errors.New("not a clearsigned document")
	}
	sig, signer, err := openpgp.VerifyDetachedSignature(keyring, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, nil)
	if err != nil {
		return nil, SignerKey{}, err
	}
	k := SignerKey{Primary: fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint)}
	// ponytail: a key-ID-only signature by a subkey leaves Signing "", so
	// only a primary-key pin matches it (fails closed); resolve subkey IDs
	// if an upstream ever needs a subkey pin without the fingerprint subpacket.
	switch {
	case len(sig.IssuerFingerprint) > 0:
		k.Signing = fmt.Sprintf("%X", sig.IssuerFingerprint)
	case sig.IssuerKeyId != nil && *sig.IssuerKeyId == signer.PrimaryKey.KeyId:
		k.Signing = k.Primary
	}
	return block.Plaintext, k, nil
}
