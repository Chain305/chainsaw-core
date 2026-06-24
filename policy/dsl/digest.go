package dsl

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
)

// hasher wraps sha256 with the methods sourceDigest reaches for. A
// thin shim so the digest helper reads cleanly even though Go's
// crypto/sha256 already exposes everything we need.
type hasher struct {
	h hash.Hash
}

func newHasher() *hasher {
	return &hasher{h: sha256.New()}
}

func (h *hasher) Write(p []byte) (int, error) {
	return h.h.Write(p)
}

func (h *hasher) WriteString(s string) {
	_, _ = h.h.Write([]byte(s))
}

func (h *hasher) Hex() string {
	return hex.EncodeToString(h.h.Sum(nil))
}
