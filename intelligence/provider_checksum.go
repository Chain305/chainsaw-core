package intelligence

// checksumProvider is a Tier-2 provider — it needs artifact bytes to
// compute the actual SHA-256 (and, in algorithm-agility mode, whichever
// algorithm the upstream sidecar declared). The declared-hash side is
// best-effort: the intelligence fan-out does not fetch registry metadata
// bytes itself (that's the registry-metadata provider's job), so unless
// the caller populated Artifact.Digests.Declared / Artifact.SHA256 / a
// sidecar via prior, we simply emit Actual and leave Declared empty.
// Verified stays false in that case — matching the PR brief: "If declared
// is empty (ecosystem without sidecar hash): set Verified=false with no
// warning; it's normal."
//
// IMPORTANT — circular-verification caveat. The digest comparison this
// provider performs (declared vs actual) is bit-flip detection only:
// both halves of the comparison come from data the attacker controls
// (registry metadata + tarball bytes), so a matching digest proves
// nothing about upstream authenticity. Real cryptographic verification
// — checking an upstream signature against an independent trust root —
// happens in provider_signature_verify.go (Tier-3 enricher), which
// projects the verdict produced by the Tier-1 Provenance provider
// (internal/provenance.CheckWithSource) onto Artifact.SignatureVerified
// / SignatureKind / SignatureKeyID. Policy rules and TrustScore should
// reference SignatureVerified, not Digests.Verified, when "is this
// artifact actually who it claims to be" is the question.

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"hash"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/blake2b"
)

// WarnChecksumMismatch is the stable warning code the evaluator / UI
// keys on. Declared locally because this is the first site that needs
// it and the matrix brief asks for it here specifically.
const WarnChecksumMismatch = "checksum_mismatch"

// maxArtifactBytesForHash caps the per-scan read. Hashing a multi-GB
// artifact synchronously in the fan-out blows the deadline — the
// checksum enforcer upstream of the proxy already imposes a similar
// cap. 512 MiB covers every npm / pypi / maven artifact we've seen in
// the wild with room to spare.
const maxArtifactBytesForHash = 512 * 1024 * 1024

// checksumProvider computes the artifact digest and compares against
// whatever declared hash upstream put on the handle.
type checksumProvider struct{}

// newChecksumProvider constructs the provider. No external deps — all
// the work is pure-function over bytes or a file path.
func newChecksumProvider() *checksumProvider {
	return &checksumProvider{}
}

func (p *checksumProvider) Name() string { return "checksum" }

func (p *checksumProvider) Signal() SignalMask { return SignalChecksum }

// Tier: 2 — needs artifact bytes.
func (p *checksumProvider) Tier() int { return 2 }

// NeedsArtifact is true — the digest is computed over the bytes.
func (p *checksumProvider) NeedsArtifact() bool { return true }

// supportedChecksumEcosystems matches the POLICY_PROXY_MATRIX.md
// "Checksum fail-closed enforcement" row: every ecosystem we can
// compare an upstream-declared hash against. Swift is included via its
// Digest: sha-256=... response header (partial coverage per the matrix
// — header-based, not sidecar-based; runSwift handles the graceful
// no-digest case).
var supportedChecksumEcosystems = map[string]struct{}{
	"npm": {}, "pip": {}, "pypi": {}, "rubygems": {}, "composer": {},
	"maven": {}, "gradle": {}, "nuget": {}, "cargo": {}, "swift": {},
}

func (p *checksumProvider) Supports(ecosystem string) bool {
	_, ok := supportedChecksumEcosystems[ecosystem]
	return ok
}

// hashAlgo enumerates every digest algorithm the checksum provider
// understands. Strength ordering (strongest first) is used by
// pickDeclared and parseSRI to pick a winner across multi-algo input.
type hashAlgo int

const (
	algoUnknown hashAlgo = iota
	algoMD5
	algoSHA1
	algoSHA256
	algoSHA384
	algoSHA512
	algoBlake2b256
)

// strength assigns a comparable rank — higher is stronger. Unknown
// stays at zero so any known algo wins.
func (a hashAlgo) strength() int {
	switch a {
	case algoMD5:
		return 1
	case algoSHA1:
		return 2
	case algoBlake2b256:
		return 3
	case algoSHA256:
		return 4
	case algoSHA384:
		return 5
	case algoSHA512:
		return 6
	default:
		return 0
	}
}

// String is used for warning messages and (lowercase) prefix matching
// in normaliseHex.
func (a hashAlgo) String() string {
	switch a {
	case algoMD5:
		return "md5"
	case algoSHA1:
		return "sha1"
	case algoSHA256:
		return "sha256"
	case algoSHA384:
		return "sha384"
	case algoSHA512:
		return "sha512"
	case algoBlake2b256:
		return "blake2b256"
	default:
		return "unknown"
	}
}

// newHasher returns a fresh hash.Hash for the given algo, or nil if
// the algo is unknown / not supported on this build.
func newHasher(a hashAlgo) hash.Hash {
	switch a {
	case algoMD5:
		return md5.New()
	case algoSHA1:
		return sha1.New()
	case algoSHA256:
		return sha256.New()
	case algoSHA384:
		return sha512.New384()
	case algoSHA512:
		return sha512.New()
	case algoBlake2b256:
		// blake2b.New256 with a nil key returns the unkeyed hash; the
		// only error path is "key too long", which can't fire here.
		h, err := blake2b.New256(nil)
		if err != nil {
			return nil
		}
		return h
	default:
		return nil
	}
}

// Run dispatches per-ecosystem (currently only Swift gets a dedicated
// branch — every other supported ecosystem falls through to runDefault,
// which is the algorithm-agile path used for npm sidecars, Composer
// SHA-256 sidecars, PyPI MD5/SHA-256, etc.).
func (p *checksumProvider) Run(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	if req.Artifact == nil {
		// Scanner already emits WarnNeedsArtifact; don't duplicate.
		return PartialReport{}, nil
	}
	switch req.Key.Ecosystem {
	case "swift":
		return p.runSwift(ctx, req, prior)
	default:
		return p.runDefault(ctx, req, prior)
	}
}

// runDefault is the algorithm-agile per-ecosystem path. It picks the
// strongest declared digest available, hashes the artifact bytes with
// the matching algorithm, and emits Verified / WarnChecksumMismatch
// accordingly. Always populates Digests.SHA256 even when verified algo
// is something else, so downstream cache keys / dedup paths keep
// working.
func (p *checksumProvider) runDefault(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	declaredHex, declaredAlgo := pickDeclared(req.Artifact, prior)

	// Always compute SHA-256 — downstream cache keys / dedup paths
	// depend on it being populated regardless of which algorithm the
	// declared hash used.
	sha256Hex, err := computeArtifactSHA256(ctx, req.Artifact)
	if err != nil {
		return PartialReport{}, err
	}
	if sha256Hex == "" {
		return PartialReport{}, nil
	}

	digests := ArtifactDigest{SHA256: sha256Hex, Actual: sha256Hex}
	var warnings []Warning

	switch {
	case declaredHex == "":
		// No declared hash to compare — normal for ecosystems without a
		// sidecar. Verified stays false; no warning.
	case declaredAlgo == algoUnknown || declaredAlgo == algoSHA256:
		// Either the declared digest had no algo prefix (treat as SHA-256
		// per the legacy behaviour) or it was explicitly SHA-256.
		if hashesEqual(declaredHex, sha256Hex) {
			digests.Declared = normaliseHex(declaredHex)
			digests.Verified = true
		} else {
			digests.Declared = normaliseHex(declaredHex)
			digests.Verified = false
			warnings = append(warnings, mismatchWarning(digests.Declared, sha256Hex))
		}
	default:
		// Algorithm-agile path: hash the artifact a second time with
		// the declared algorithm and compare. SHA-256 is already in
		// digests.SHA256, so downstream caches stay happy.
		altHex, herr := computeArtifactHash(ctx, req.Artifact, declaredAlgo)
		if herr != nil {
			return PartialReport{}, herr
		}
		if altHex == "" {
			return PartialReport{Artifact: &ArtifactSection{Digests: digests}}, nil
		}
		digests.Declared = normaliseHex(declaredHex)
		// Reflect the algo we actually verified in Actual.
		digests.Actual = altHex
		switch declaredAlgo {
		case algoSHA1:
			digests.SHA1 = altHex
		case algoMD5:
			digests.MD5 = altHex
		case algoSHA512:
			digests.SHA512 = altHex
		case algoBlake2b256:
			digests.Blake2b256 = altHex
		}
		if hashesEqual(declaredHex, altHex) {
			digests.Verified = true
		} else {
			digests.Verified = false
			warnings = append(warnings, mismatchWarning(digests.Declared, altHex))
		}
	}

	return PartialReport{
		Artifact: &ArtifactSection{Digests: digests},
		Warnings: warnings,
	}, nil
}

// runSwift is the per-ecosystem branch for Swift Package Registry
// artifacts. The Swift registry does not ship sidecar hash files; it
// returns a `Digest: sha-256=…` proxy header which the caller threads
// through ArtifactHandle.SHA256 (or, equivalently, via prior.Digests).
// When no declared digest reaches us, we return an empty PartialReport
// — the matrix calls this graceful (Verified=false, no warning), since
// header-based coverage is best-effort. When a digest is available,
// we hash the bytes with the matching algo (defaulting to SHA-256 for
// the bare-hex case) and emit Verified / WarnChecksumMismatch.
func (p *checksumProvider) runSwift(ctx context.Context, req Request, prior *Report) (PartialReport, error) {
	declaredHex, declaredAlgo := pickDeclared(req.Artifact, prior)
	if declaredHex == "" {
		// Graceful: header-based ecosystems often arrive with no digest
		// (e.g. cache miss in the proxy). Don't compute anything; let
		// the registry-metadata provider populate digests if it can.
		return PartialReport{}, nil
	}

	// SHA-256 is always computed so downstream cache keys are stable.
	sha256Hex, err := computeArtifactSHA256(ctx, req.Artifact)
	if err != nil {
		return PartialReport{}, err
	}
	if sha256Hex == "" {
		return PartialReport{}, nil
	}

	digests := ArtifactDigest{
		SHA256:   sha256Hex,
		Actual:   sha256Hex,
		Declared: normaliseHex(declaredHex),
	}
	var warnings []Warning

	algo := declaredAlgo
	if algo == algoUnknown {
		algo = algoSHA256
	}

	var actualHex string
	if algo == algoSHA256 {
		actualHex = sha256Hex
	} else {
		altHex, herr := computeArtifactHash(ctx, req.Artifact, algo)
		if herr != nil {
			return PartialReport{}, herr
		}
		if altHex == "" {
			return PartialReport{Artifact: &ArtifactSection{Digests: digests}}, nil
		}
		actualHex = altHex
		digests.Actual = altHex
		switch algo {
		case algoSHA1:
			digests.SHA1 = altHex
		case algoMD5:
			digests.MD5 = altHex
		case algoSHA512:
			digests.SHA512 = altHex
		case algoBlake2b256:
			digests.Blake2b256 = altHex
		}
	}

	if hashesEqual(declaredHex, actualHex) {
		digests.Verified = true
	} else {
		digests.Verified = false
		warnings = append(warnings, mismatchWarning(digests.Declared, actualHex))
	}

	return PartialReport{
		Artifact: &ArtifactSection{Digests: digests},
		Warnings: warnings,
	}, nil
}

// mismatchWarning packages a uniform WarnChecksumMismatch warning so
// runDefault and runSwift emit the same shape.
func mismatchWarning(declared, actual string) Warning {
	return Warning{
		Provider: "checksum",
		Code:     WarnChecksumMismatch,
		Message:  "declared hash does not match actual: declared=" + declared + " actual=" + actual,
	}
}

// pickDeclared returns the strongest declared digest available on the
// handle / prior report, plus the algorithm it represents. Priority:
//
//  1. handle's typed SHA256 field (legacy proxy header path).
//  2. prior.Digests.Integrity (parsed as SRI — multi-algo capable).
//  3. typed prior.Digests fields (strongest-first: SHA-512 > SHA-256 >
//     Blake2b-256 > SHA-1 > MD5).
//  4. free-form Declared field — try SRI first, fall back to raw hex
//     with algoUnknown.
//
// Returns ("", algoUnknown) when nothing usable is available.
func pickDeclared(handle *ArtifactHandle, prior *Report) (string, hashAlgo) {
	if handle != nil {
		if h := normaliseHex(handle.SHA256); h != "" {
			return h, algoSHA256
		}
	}
	if prior != nil {
		// SRI integrity field is the canonical multi-algo carrier.
		if integ := strings.TrimSpace(prior.Artifact.Digests.Integrity); integ != "" {
			if algo, hexHash, ok := parseSRI(integ); ok {
				return hexHash, algo
			}
		}
		// Typed fields, strongest first. Each is treated as raw hex.
		d := prior.Artifact.Digests
		if v := normaliseHex(d.SHA512); v != "" {
			return v, algoSHA512
		}
		if v := normaliseHex(d.SHA256); v != "" {
			return v, algoSHA256
		}
		if v := normaliseHex(d.Blake2b256); v != "" {
			return v, algoBlake2b256
		}
		if v := normaliseHex(d.SHA1); v != "" {
			return v, algoSHA1
		}
		if v := normaliseHex(d.MD5); v != "" {
			return v, algoMD5
		}
		// Free-form declared — try SRI, fall back to raw hex.
		if decl := strings.TrimSpace(d.Declared); decl != "" {
			if algo, hexHash, ok := parseSRI(decl); ok {
				return hexHash, algo
			}
			return normaliseHex(decl), algoUnknown
		}
	}
	return "", algoUnknown
}

// parseSRI decodes a Subresource-Integrity-style string (RFC 6920-ish:
// "<algo>-<base64>" with optional "?option" suffix; whitespace splits
// multi-algo values). Returns the strongest entry, plus the lowercase
// hex of its decoded digest. Returns ok=false on garbage input.
//
// Tolerant decoder: tries std, raw, and URL-safe base64 variants, since
// real-world npm tarballs occasionally smuggle URL-safe variants.
func parseSRI(s string) (hashAlgo, string, bool) {
	bestAlgo := algoUnknown
	var bestHex string
	for _, token := range strings.Fields(s) {
		if i := strings.IndexByte(token, '?'); i >= 0 {
			token = token[:i]
		}
		dash := strings.IndexByte(token, '-')
		if dash <= 0 || dash == len(token)-1 {
			continue
		}
		name := strings.ToLower(token[:dash])
		body := token[dash+1:]
		var algo hashAlgo
		switch name {
		case "md5":
			algo = algoMD5
		case "sha1":
			algo = algoSHA1
		case "sha256":
			algo = algoSHA256
		case "sha384":
			algo = algoSHA384
		case "sha512":
			algo = algoSHA512
		case "blake2b256", "blake2b-256":
			algo = algoBlake2b256
		default:
			continue
		}
		raw, ok := decodeBase64Tolerant(body)
		if !ok || len(raw) == 0 {
			continue
		}
		if algo.strength() > bestAlgo.strength() {
			bestAlgo = algo
			bestHex = hex.EncodeToString(raw)
		}
	}
	if bestAlgo == algoUnknown {
		return algoUnknown, "", false
	}
	return bestAlgo, bestHex, true
}

// decodeBase64Tolerant tries std, raw-std, URL, and raw-URL alphabets
// in order and returns the first successful decode. SRI in the wild is
// inconsistent enough that being lenient here is a net win.
func decodeBase64Tolerant(s string) ([]byte, bool) {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if raw, err := enc.DecodeString(s); err == nil {
			return raw, true
		}
	}
	return nil, false
}

// computeArtifactSHA256 is preserved as a thin wrapper around the
// algorithm-agile computeArtifactHash so existing call sites (and the
// "always populate Digests.SHA256" guarantee) keep their shape.
func computeArtifactSHA256(ctx context.Context, h *ArtifactHandle) (string, error) {
	return computeArtifactHash(ctx, h, algoSHA256)
}

// computeArtifactHash reads either the inline bytes or the spooled
// file (in that order) and returns the lowercase hex digest under the
// requested algorithm. Empty handle → empty string, no error.
func computeArtifactHash(ctx context.Context, h *ArtifactHandle, algo hashAlgo) (string, error) {
	if h == nil {
		return "", nil
	}
	hasher := newHasher(algo)
	if hasher == nil {
		return "", nil
	}
	if len(h.Bytes) > 0 {
		buf := h.Bytes
		if len(buf) > maxArtifactBytesForHash {
			// Hash the capped prefix rather than error out — truncating
			// is better than a 0-byte result because the caller may
			// still compare against a partial declared hash.
			buf = buf[:maxArtifactBytesForHash]
		}
		hasher.Write(buf)
		return hex.EncodeToString(hasher.Sum(nil)), nil
	}
	if strings.TrimSpace(h.Path) == "" {
		return "", nil
	}
	f, err := os.Open(h.Path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(hasher, io.LimitReader(f, maxArtifactBytesForHash)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// normaliseHex strips whitespace, lowercases, and drops the optional
// "<algo>:" / "<algo>=" / "<algo-dashed>=" prefix some ecosystems
// advertise so the equality check can treat all shapes uniformly. The
// list below covers every algo we hash with.
func normaliseHex(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" {
		return ""
	}
	prefixes := []string{
		"sha256:", "sha-256:", "sha-256=", "sha256=",
		"sha512:", "sha-512:", "sha-512=", "sha512=",
		"sha384:", "sha-384:", "sha-384=", "sha384=",
		"sha1:", "sha-1:", "sha-1=", "sha1=",
		"md5:", "md5=",
		"blake2b256:", "blake2b-256:", "blake2b-256=", "blake2b256=",
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			s = s[len(prefix):]
			break
		}
	}
	return strings.TrimSpace(s)
}

// hashesEqual compares two hex digests after normalising for prefix /
// case differences. Intentionally not constant-time — this is a
// cache-fill comparison, not a security boundary (the fail-closed
// enforcer in internal/checksum does the timing-safe compare).
func hashesEqual(a, b string) bool {
	return normaliseHex(a) == normaliseHex(b)
}

var _ Provider = (*checksumProvider)(nil)
