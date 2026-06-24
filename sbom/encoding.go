package sbom

import (
	"encoding/base64"
	"encoding/hex"
)

// base64DecodeStrict decodes a base64-encoded string. Tries the standard
// encoding first, falls back to the URL-safe variant. Sigstore bundle
// payloads are typically standard, but the DSSE spec permits either.
func base64DecodeStrict(s string) ([]byte, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

// encodeHex is hex.EncodeToString with lowercase output. Wrapped so the
// callers in verify.go don't import encoding/hex just for one call.
func encodeHex(b []byte) string {
	return hex.EncodeToString(b)
}
