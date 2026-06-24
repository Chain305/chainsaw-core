package pgpverify

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

// parseIssuerKeyIDs decodes an ASCII-armored detached signature and returns
// the issuer fingerprints (hex, uppercase) or 8-byte key IDs referenced by
// each signature packet.
func parseIssuerKeyIDs(armoredSig []byte) ([]string, error) {
	block, err := armor.Decode(bytes.NewReader(armoredSig))
	if err != nil {
		return nil, fmt.Errorf("armor decode: %w", err)
	}
	reader := packet.NewReader(block.Body)

	var ids []string
	var parseErrs []error
	for {
		pkt, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Not every signature variant is implemented by the library;
			// we keep going but remember the error so we can return it if
			// NOTHING parsed — otherwise a caller sees an empty list with
			// nil error and emits a misleading "no issuer key IDs" message.
			parseErrs = append(parseErrs, err)
			continue
		}
		sig, ok := pkt.(*packet.Signature)
		if !ok {
			continue
		}
		if len(sig.IssuerFingerprint) >= 20 {
			ids = append(ids, fmt.Sprintf("%X", sig.IssuerFingerprint))
			continue
		}
		if sig.IssuerKeyId != nil {
			ids = append(ids, fmt.Sprintf("%016X", *sig.IssuerKeyId))
		}
	}
	if len(ids) == 0 && len(parseErrs) > 0 {
		return nil, fmt.Errorf("signature packets unparseable: %w", parseErrs[0])
	}
	return ids, nil
}
