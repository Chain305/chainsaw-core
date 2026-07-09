package provenance

import (
	"bufio"
	"bytes"
	"compress/bzip2"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
)

// aptChecker verifies the Debian/Ubuntu APT hash chain:
//
//	InRelease (clearsigned PGP) ──► Packages[.gz|.bz2] SHA256
//	                              └► .deb SHA256
//
// A StatusVerified result means every step of that chain matched. Any
// mismatch in the chain is StatusFailed with a descriptive reason.
// Missing keyring / unreachable mirror degrade to StatusInconclusive:
// "we could not evaluate trust" is qualitatively different from "we
// evaluated trust and it failed" and users bundle different response
// runbooks against the two.
//
// The keyring is taken from (in order):
//  1. CHAINSAW_APT_KEYRING — file or directory of .asc/.gpg keys.
//  2. Value passed to newAPTCheckerWithKeyring at construction time.
//  3. Embedded keys under internal/provenance/keys/apt/.
//
// Known limitations:
//   - `by-hash` layouts (/by-hash/SHA256/<hex>) are NOT walked as a
//     separate path; we fetch the canonical filename. Mirrors that only
//     expose by-hash will miss and fall to StatusInconclusive.
//   - The Release file (unsigned) with detached Release.gpg is not
//     supported — we require the clearsigned InRelease layout, which is
//     what modern mirrors publish.
//   - InRelease can list multiple Packages files per (component, arch);
//     we scan the file list for any entry whose filename ends in
//     /Packages, /Packages.gz, or /Packages.bz2 and stop at the first
//     that verifies, so callers don't need to pass component/arch when
//     the package name is unique in a small fixture.
type aptChecker struct {
	client      *http.Client
	logger      *slog.Logger
	keyringPath string

	// keyringOverride, when non-nil, is used verbatim and bypasses
	// disk/embedded loading. Tests inject ephemeral keyrings through this
	// field.
	keyringOverride openpgp.EntityList
}

func newAPTCheckerWithKeyring(client *http.Client, logger *slog.Logger, keyringPath string) *aptChecker {
	return &aptChecker{
		client:      client,
		logger:      logger,
		keyringPath: keyringPath,
	}
}

// newAPTChecker constructs an APT checker using the CHAINSAW_APT_KEYRING
// environment variable (if set) as its keyring path. The registration in
// provenance.go has historically used newAPTChecker(client, logger); we
// preserve that signature and layer the env lookup here so the
// dispatcher wiring doesn't need to know about the keyring.
func newAPTChecker(client *http.Client, logger *slog.Logger) *aptChecker {
	return newAPTCheckerWithKeyring(client, logger, os.Getenv("CHAINSAW_APT_KEYRING"))
}

func (c *aptChecker) Ecosystem() string { return "apt" }

func (c *aptChecker) Check(ctx context.Context, packageName, version string) Result {
	return c.CheckWithSource(ctx, packageName, version, "")
}

// CheckWithSource expects sourceURL to point at an APT "distribution
// root" — the directory containing dists/<suite>/InRelease. For
// convenience we accept either the distribution root itself (in which
// case we require the suite to be appended, e.g.
// https://deb.debian.org/debian/dists/stable) or the suite root directly.
// A missing trailing slash is tolerated.
func (c *aptChecker) CheckWithSource(ctx context.Context, packageName, version, sourceURL string) Result {
	if sourceURL == "" {
		return Result{
			Status:    StatusUnavailable,
			Ecosystem: "apt",
			Error:     "OS package provenance requires the source repository URL; call CheckWithSource",
		}
	}
	base := strings.TrimRight(sourceURL, "/")

	keyring, err := c.loadKeyring()
	if err != nil {
		if c.logger != nil {
			c.logger.Warn("apt provenance: keyring unavailable",
				"package", packageName, "version", version, "error", err.Error())
		}
		return Result{
			Status:          StatusUnavailable,
			Ecosystem:       "apt",
			AttestationType: "pgp-repo",
			Error:           fmt.Sprintf("keyring unavailable: %v", err),
		}
	}

	// Step 1 — fetch + verify InRelease.
	inReleaseURL := base + "/InRelease"
	inRelease, err := c.fetch(ctx, inReleaseURL, 32<<20) // 32 MiB cap
	if err != nil {
		return inconclusive("apt", fmt.Sprintf("fetch InRelease: %v", err))
	}
	releaseBody, signer, err := verifyClearsign(inRelease, keyring)
	if err != nil {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "apt",
			AttestationType: "pgp-repo",
			Error:           fmt.Sprintf("InRelease signature: %v", err),
		}
	}

	// Step 2 — locate a Packages entry in the signed body.
	entries, err := parseReleaseFileHashes(releaseBody)
	if err != nil {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "apt",
			AttestationType: "pgp-repo",
			Error:           fmt.Sprintf("parse InRelease: %v", err),
		}
	}
	packagesEntry, ok := pickPackagesEntry(entries)
	if !ok {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "apt",
			AttestationType: "pgp-repo",
			Error:           "no Packages entry in InRelease",
		}
	}

	// Step 3 — fetch Packages and compare its SHA256.
	packagesURL := base + "/" + strings.TrimLeft(packagesEntry.Path, "/")
	packagesBytes, err := c.fetch(ctx, packagesURL, 256<<20) // 256 MiB cap
	if err != nil {
		return inconclusive("apt", fmt.Sprintf("fetch Packages: %v", err))
	}
	if got := sha256.Sum256(packagesBytes); !bytes.Equal(got[:], packagesEntry.SHA256) {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "apt",
			AttestationType: "pgp-repo",
			Error:           fmt.Sprintf("Packages sha256 mismatch: got %x, want %x", got, packagesEntry.SHA256),
		}
	}
	packagesPlain, err := maybeDecompress(packagesEntry.Path, packagesBytes)
	if err != nil {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "apt",
			AttestationType: "pgp-repo",
			Error:           fmt.Sprintf("decompress Packages: %v", err),
		}
	}

	// Step 4 — find the requested package's .deb entry.
	debEntry, ok := findPackageEntry(packagesPlain, packageName, version)
	if !ok {
		return Result{
			Status:          StatusMissing,
			Ecosystem:       "apt",
			AttestationType: "pgp-repo",
			Error:           fmt.Sprintf("package %s=%s not found in Packages", packageName, version),
		}
	}

	// Step 5 — fetch the .deb and hash it.
	// The Packages Filename field is a path relative to the distribution
	// root (e.g. pool/main/c/curl/curl_7.88.0-1_amd64.deb). It lives
	// *above* dists/<suite>, so we need to strip the "dists/<suite>"
	// suffix from base before joining.
	distRoot := stripSuite(base)
	debURL := distRoot + "/" + strings.TrimLeft(debEntry.Filename, "/")
	debHash, err := c.fetchSHA256(ctx, debURL)
	if err != nil {
		return inconclusive("apt", fmt.Sprintf("fetch .deb: %v", err))
	}
	if !bytes.Equal(debHash[:], debEntry.SHA256) {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "apt",
			AttestationType: "pgp-repo",
			Error:           fmt.Sprintf(".deb sha256 mismatch: got %x, want %x", debHash, debEntry.SHA256),
		}
	}

	return Result{
		Status:          StatusVerified,
		Ecosystem:       "apt",
		AttestationType: "pgp-repo",
		BuilderID:       signer,
	}
}

// fetch issues a GET and returns the body (up to maxBytes).
func (c *aptChecker) fetch(ctx context.Context, target string, maxBytes int64) ([]byte, error) {
	if _, err := url.Parse(target); err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

func (c *aptChecker) fetchSHA256(ctx context.Context, target string) ([32]byte, error) {
	var digest [32]byte
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return digest, err
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return digest, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return digest, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.LimitReader(resp.Body, 512<<20)); err != nil {
		return digest, err
	}
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func (c *aptChecker) loadKeyring() (openpgp.EntityList, error) {
	if c.keyringOverride != nil {
		return c.keyringOverride, nil
	}
	return loadKeyring(c.keyringPath, "apt")
}

// verifyClearsign decodes a PGP clearsigned document, checks the
// signature against the supplied keyring, and returns the signed payload
// plus a short signer description. The signer string is formatted
// "Name <email> [fingerprint]" or "fingerprint" if the entity carries
// no identity.
func verifyClearsign(signed []byte, keyring openpgp.KeyRing) ([]byte, string, error) {
	block, rest := clearsign.Decode(signed)
	if block == nil {
		return nil, "", errors.New("not a clearsigned document")
	}
	_ = rest
	signer, err := openpgp.CheckDetachedSignature(keyring, bytes.NewReader(block.Bytes), block.ArmoredSignature.Body, nil)
	if err != nil {
		return nil, "", err
	}
	desc := fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint)
	for _, id := range signer.Identities {
		if id.UserId != nil {
			desc = fmt.Sprintf("%s <%s> [%s]", id.UserId.Name, id.UserId.Email, desc)
			break
		}
	}
	return block.Bytes, desc, nil
}

// releaseFileEntry represents one line of the `SHA256:` stanza in a
// Debian Release/InRelease file.
type releaseFileEntry struct {
	SHA256 []byte
	Size   int64
	Path   string // e.g. "main/binary-amd64/Packages.gz"
}

// parseReleaseFileHashes parses the SHA256 stanza from a Release file
// body (the signed payload, not the full clearsigned document). Returns
// at least one entry or an error.
func parseReleaseFileHashes(body []byte) ([]releaseFileEntry, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 0, 1<<16), 1<<20)
	inSHA256 := false
	var entries []releaseFileEntry
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			// Top-level field.
			inSHA256 = strings.EqualFold(strings.TrimSuffix(strings.SplitN(line, ":", 2)[0], " "), "SHA256")
			continue
		}
		if !inSHA256 {
			continue
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 3 {
			continue
		}
		hash, err := hex.DecodeString(fields[0])
		if err != nil || len(hash) != 32 {
			continue
		}
		// fields[1] is the size, fields[2] is the path.
		var size int64
		fmt.Sscanf(fields[1], "%d", &size)
		entries = append(entries, releaseFileEntry{
			SHA256: hash,
			Size:   size,
			Path:   fields[2],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("no SHA256 entries in Release file")
	}
	return entries, nil
}

// pickPackagesEntry returns the first Packages/Packages.gz/Packages.bz2
// entry from the InRelease listing, preferring the plain file for simpler
// fixture generation and falling back to gz/bz2.
func pickPackagesEntry(entries []releaseFileEntry) (releaseFileEntry, bool) {
	var plain, gz, bz2 *releaseFileEntry
	for i := range entries {
		e := &entries[i]
		switch {
		case strings.HasSuffix(e.Path, "/Packages") || e.Path == "Packages":
			if plain == nil {
				plain = e
			}
		case strings.HasSuffix(e.Path, "/Packages.gz") || e.Path == "Packages.gz":
			if gz == nil {
				gz = e
			}
		case strings.HasSuffix(e.Path, "/Packages.bz2") || e.Path == "Packages.bz2":
			if bz2 == nil {
				bz2 = e
			}
		}
	}
	switch {
	case plain != nil:
		return *plain, true
	case gz != nil:
		return *gz, true
	case bz2 != nil:
		return *bz2, true
	}
	return releaseFileEntry{}, false
}

func maybeDecompress(path string, data []byte) ([]byte, error) {
	switch {
	case strings.HasSuffix(path, ".gz"):
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		return io.ReadAll(io.LimitReader(gz, 1<<30))
	case strings.HasSuffix(path, ".bz2"):
		return io.ReadAll(io.LimitReader(bzip2.NewReader(bytes.NewReader(data)), 1<<30))
	default:
		return data, nil
	}
}

// debEntry is a single stanza pulled out of a Packages file — just the
// fields we need for hash verification.
type debEntry struct {
	Package  string
	Version  string
	Filename string
	SHA256   []byte
	Size     int64
}

// findPackageEntry scans a plain Packages file for a stanza matching
// (name, version) and returns its Filename/SHA256.
func findPackageEntry(packages []byte, name, version string) (debEntry, bool) {
	scanner := bufio.NewScanner(bytes.NewReader(packages))
	scanner.Buffer(make([]byte, 0, 1<<16), 4<<20)

	var cur debEntry
	reset := func() { cur = debEntry{} }
	flush := func() (debEntry, bool) {
		if cur.Package == name && cur.Version == version && cur.Filename != "" && len(cur.SHA256) == 32 {
			return cur, true
		}
		return debEntry{}, false
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if e, ok := flush(); ok {
				return e, true
			}
			reset()
			continue
		}
		// Packages files are RFC-822-ish: continuation lines start with
		// a space. We only care about Package/Version/Filename/SHA256
		// and those never span lines in practice.
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		switch strings.ToLower(key) {
		case "package":
			cur.Package = val
		case "version":
			cur.Version = val
		case "filename":
			cur.Filename = val
		case "sha256":
			if h, err := hex.DecodeString(val); err == nil && len(h) == 32 {
				cur.SHA256 = h
			}
		case "size":
			fmt.Sscanf(val, "%d", &cur.Size)
		}
	}
	// Final stanza without trailing blank line.
	if e, ok := flush(); ok {
		return e, true
	}
	return debEntry{}, false
}

// stripSuite removes a trailing "/dists/<suite>" from base, leaving the
// distribution root that pool paths are relative to.
func stripSuite(base string) string {
	idx := strings.LastIndex(base, "/dists/")
	if idx < 0 {
		return base
	}
	return base[:idx]
}

// inconclusive is a small helper to produce the "we could not evaluate"
// variant — we reuse StatusUnavailable because that's what the existing
// vocabulary supports; the Error string names the specific failure so
// callers can distinguish it from other Unavailable causes.
func inconclusive(ecosystem, reason string) Result {
	return Result{
		Status:          StatusUnavailable,
		Ecosystem:       ecosystem,
		AttestationType: "pgp-repo",
		Error:           "inconclusive: " + reason,
	}
}
