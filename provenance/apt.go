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
	"sort"
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
// InRelease lists one Packages file per (component, arch) — about forty
// for a Debian suite — in several compressions. We build an ordered
// candidate list (gz, bz2, plain; `main` first), fetch each in turn, and
// stop at the first that hash-verifies AND contains the requested
// coordinate, so callers need not pass component/arch. A fetch failure
// moves to the next candidate; a hash mismatch or decompress failure does
// not — that is evidence, and falling through would hand an attacker a
// retry.
//
// Known limitations:
//   - `by-hash` layouts (/by-hash/SHA256/<hex>) are NOT walked as a
//     separate path; we fetch the canonical filename. Mirrors that only
//     expose by-hash will miss and fall to StatusInconclusive.
//   - `Packages.xz` is not read (no stdlib xz reader). Every mirror that
//     publishes .xz also publishes .gz, so this costs nothing today.
//   - At most maxPackagesCandidates indexes are read per check, so a
//     coordinate in an unusual component/arch beyond that bound reports
//     StatusMissing with the count in the message.
//   - The Release file (unsigned) with detached Release.gpg is not
//     supported — we require the clearsigned InRelease layout, which is
//     what modern mirrors publish.
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
		return sourceURLRequired("apt")
	}
	base := strings.TrimRight(sourceURL, "/")

	keyring, err := c.loadKeyring()
	if err != nil {
		if c.logger != nil {
			c.logger.Warn("apt provenance: keyring unavailable",
				"package", packageName, "version", version, "error", err.Error())
		}
		return keyringUnavailable("apt", "CHAINSAW_APT_KEYRING",
			"/etc/apt/trusted.gpg.d/ (Debian/Ubuntu) or an exported archive keyring", err)
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
	candidates := pickPackagesCandidates(entries)
	if len(candidates) == 0 {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "apt",
			AttestationType: "pgp-repo",
			Error:           "no Packages entry in InRelease",
		}
	}

	// Step 3 — fetch Packages and compare its SHA256.
	//
	// Fall through to the next candidate ONLY on a fetch error. A hash
	// mismatch or a decompress failure on bytes we did retrieve is
	// evidence, not a transport problem: it terminates the walk as
	// StatusFailed so an attacker cannot buy a retry by corrupting the
	// first-choice file.
	//
	// Step 4 is folded into the same loop. An InRelease lists one
	// Packages file per (component, arch), so "not in this index" is not
	// an answer — it just means we read the wrong one. The original code
	// read exactly ONE index and reported MISSING, which is how a package
	// that is plainly in Debian main/binary-amd64 came back as "has no
	// provenance". The file header has promised "stop at the first that
	// verifies" since this checker was written; this is that promise.
	var (
		foundDeb   debEntry
		found      bool
		readAny    bool
		fetchErrs  []string
		tried      int
		lastPkgErr string
	)
	for _, cand := range candidates {
		if tried >= maxPackagesCandidates {
			break
		}
		tried++
		packagesURL := base + "/" + strings.TrimLeft(cand.Path, "/")
		packagesBytes, ferr := c.fetch(ctx, packagesURL, 256<<20) // 256 MiB cap
		if ferr != nil {
			fetchErrs = append(fetchErrs, fmt.Sprintf("%s: %v", cand.Path, ferr))
			continue
		}
		if got := sha256.Sum256(packagesBytes); !bytes.Equal(got[:], cand.SHA256) {
			return Result{
				Status:          StatusFailed,
				Ecosystem:       "apt",
				AttestationType: "pgp-repo",
				Error:           fmt.Sprintf("Packages sha256 mismatch: got %x, want %x", got, cand.SHA256),
			}
		}
		plain, derr := maybeDecompress(cand.Path, packagesBytes)
		if derr != nil {
			return Result{
				Status:          StatusFailed,
				Ecosystem:       "apt",
				AttestationType: "pgp-repo",
				Error:           fmt.Sprintf("decompress Packages: %v", derr),
			}
		}
		readAny = true
		if e, ok := findPackageEntry(plain, packageName, version); ok {
			foundDeb, found = e, true
			break
		}
		lastPkgErr = cand.Path
	}
	if !readAny {
		return inconclusive("apt", fmt.Sprintf("fetch Packages: %s", strings.Join(fetchErrs, "; ")))
	}
	if !found {
		return Result{
			Status:          StatusMissing,
			Ecosystem:       "apt",
			AttestationType: "pgp-repo",
			Reason:          ReasonNoAttestationFound,
			Error: fmt.Sprintf("package %s=%s not found in any of the %d Packages indexes read (last: %s)",
				packageName, version, tried, lastPkgErr),
		}
	}

	// Step 5 — fetch the .deb and hash it.
	// The Packages Filename field is a path relative to the distribution
	// root (e.g. pool/main/c/curl/curl_7.88.0-1_amd64.deb). It lives
	// *above* dists/<suite>, so we need to strip the "dists/<suite>"
	// suffix from base before joining.
	distRoot := stripSuite(base)
	debURL := distRoot + "/" + strings.TrimLeft(foundDeb.Filename, "/")
	debHash, err := c.fetchSHA256(ctx, debURL)
	if err != nil {
		return inconclusive("apt", fmt.Sprintf("fetch .deb: %v", err))
	}
	if !bytes.Equal(debHash[:], foundDeb.SHA256) {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "apt",
			AttestationType: "pgp-repo",
			Error:           fmt.Sprintf(".deb sha256 mismatch: got %x, want %x", debHash, foundDeb.SHA256),
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

// pickPackagesCandidates returns every Packages/Packages.gz/Packages.bz2
// entry the InRelease listing names, in fetch-preference order.
//
// Two things changed here, and they are separable.
//
// (1) Returning a LIST instead of one entry is the actual bug fix.
// deb.debian.org's InRelease LISTS main/binary-amd64/Packages with a
// hash, but the mirror only SERVES Packages.gz and Packages.xz — the
// uncompressed path 404s. The old pickPackagesEntry returned exactly one
// entry, preferring the uncompressed file "for simpler fixture
// generation", so chainsaw fetched a 404 and returned INCONCLUSIVE
// against the canonical Debian repository with a valid keyring and an
// already-verified InRelease signature.
//
// (2) Ordering gz before plain saves a guaranteed-wasted round trip on
// every Debian-shaped mirror. It is a cost choice, not a safety one.
//
// Falling through is scoped to FETCH failures. A hash mismatch or a
// decompress error on bytes we did retrieve terminates the walk as
// StatusFailed, so an attacker cannot buy a second attempt by corrupting
// the first-choice file.
//
// .xz is deliberately not in the list — Go has no stdlib xz reader and
// gz is universally published alongside it.
func pickPackagesCandidates(entries []releaseFileEntry) []releaseFileEntry {
	var plain, gz, bz2 []releaseFileEntry
	for i := range entries {
		e := entries[i]
		switch {
		case strings.HasSuffix(e.Path, "/Packages.gz") || e.Path == "Packages.gz":
			gz = append(gz, e)
		case strings.HasSuffix(e.Path, "/Packages.bz2") || e.Path == "Packages.bz2":
			bz2 = append(bz2, e)
		case strings.HasSuffix(e.Path, "/Packages") || e.Path == "Packages":
			plain = append(plain, e)
		}
	}
	out := make([]releaseFileEntry, 0, len(gz)+len(bz2)+len(plain))
	out = append(out, gz...)
	out = append(out, bz2...)
	out = append(out, plain...)
	// Within the compression preference, try the `main` component first.
	// A real suite lists one Packages file per (component, arch) —
	// bookworm has ~40 — and the overwhelming majority of coordinates
	// live in main. Debian orders components alphabetically, so without
	// this every lookup would walk all of contrib first. Stable sort so
	// the compression preference and the InRelease order both survive.
	sort.SliceStable(out, func(i, j int) bool {
		return isMainComponent(out[i].Path) && !isMainComponent(out[j].Path)
	})
	return out
}

func isMainComponent(path string) bool {
	return strings.HasPrefix(path, "main/") || strings.Contains(path, "/main/")
}

// maxPackagesCandidates bounds how many Packages files one check will
// fetch before giving up. A suite lists one per (component, arch), so an
// unbounded walk on a miss would pull every architecture's index. Twelve
// covers main across the common arches with room to spare.
const maxPackagesCandidates = 12

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
// vocabulary supports; Reason plus the Error string let callers
// distinguish it from the other Unavailable causes without string
// matching.
func inconclusive(ecosystem, reason string) Result {
	return Result{
		Status:          StatusUnavailable,
		Ecosystem:       ecosystem,
		AttestationType: "pgp-repo",
		Reason:          ReasonInconclusive,
		Error:           "inconclusive: " + reason,
	}
}

// osRepoExamples gives each OS-package ecosystem a copy-pasteable
// --source-url so the error tells the operator what to type, not just
// what is missing.
var osRepoExamples = map[string]string{
	"apt": "https://deb.debian.org/debian/dists/bookworm  (or https://archive.ubuntu.com/ubuntu/dists/jammy)",
	"yum": "https://dl.fedoraproject.org/pub/fedora/linux/releases/40/Everything/x86_64/os",
	"dnf": "https://dl.fedoraproject.org/pub/fedora/linux/releases/40/Everything/x86_64/os",
}

// sourceURLRequired is the P8-47 result: no source repository URL was
// supplied, so nothing was attempted.
//
// This is a BAD INVOCATION, not a property of the ecosystem. APT, YUM and
// DNF all publish signed repository metadata and this package walks the
// whole InRelease → Packages → .deb sha256 chain — but (name, version)
// alone does not name a trust domain, and guessing a default mirror is
// strictly worse than saying so: if the guessed mirror happens to carry a
// matching name+version, the chain walk SUCCEEDS and reports VERIFIED for
// bytes the user never installed (openssl 3.0.2 exists in both jammy and
// Debian), and in the common miss it reports StatusFailed — the status a
// tampered package gets.
//
// The old message named CheckWithSource, an internal Go API, at an end
// user. `chainsaw verify` now refuses the invocation with exit 4 before
// reaching this point; this result covers the server-side path, where
// provider_provenance.go calls CheckWithSource with whatever UpstreamURL
// the scan carried.
func sourceURLRequired(ecosystem string) Result {
	msg := "no source repository URL supplied, so no verification was attempted. " +
		ecosystem + " DOES publish signed repository metadata — chainsaw walks the full " +
		"signed-metadata → package-digest chain — but (name, version) alone does not identify " +
		"which repository signed it, and guessing a mirror could verify bytes you never installed. " +
		"Pass --source-url <repo-url>"
	if ex, ok := osRepoExamples[ecosystem]; ok {
		msg += ", e.g. " + ex
	}
	return Result{
		Status:    StatusUnavailable,
		Ecosystem: ecosystem,
		Reason:    ReasonSourceURLRequired,
		Error:     msg,
	}
}

// keyringUnavailable is the P8-47 half the plan under-called: fixing the
// --source-url flag converts UNAVAILABLE into INCONCLUSIVE, not VERIFIED,
// because core/provenance/keys/apt and keys/rpm ship with README.md and
// nothing else. embeddedKeyrings therefore holds zero keys and
// loadEmbeddedKeyring falls through to errKeyringEmpty on every default
// build. That is documented intent (see the READMEs), but it means the
// message must name the knob or the operator is stuck.
func keyringUnavailable(ecosystem, envVar, exampleDir string, err error) Result {
	return Result{
		Status:          StatusUnavailable,
		Ecosystem:       ecosystem,
		AttestationType: "pgp-repo",
		Reason:          ReasonKeyringUnavailable,
		Error: fmt.Sprintf("no trusted keys available to evaluate this repository (%v). "+
			"chainsaw ships no embedded %s keyring by default — point %s at a keyring "+
			"file or directory, e.g. %s. Nothing was verified either way; this is not a "+
			"signature failure", err, ecosystem, envVar, exampleDir),
	}
}
