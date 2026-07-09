package provenance

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
)

// yumChecker verifies the RPM repo hash chain:
//
//	repomd.xml + repomd.xml.asc (GPG detached sig) ──► primary.xml[.gz] SHA256
//	                                                └► .rpm SHA256
//
// Same status mapping as APT: StatusVerified only when every step
// matches; StatusFailed on mismatch; StatusUnavailable with a descriptive
// "inconclusive" reason on missing keyring / unreachable mirror.
//
// Known limitations:
//   - Only the "primary" data type is walked. We do not verify filelists
//     or other.xml, since the .rpm hash is already in primary.
//   - Modular repos (`modules.yaml.gz`) are not verified — they carry
//     content metadata, not package content.
//   - DeltaRPM entries are ignored.
//   - repomd.xml can sometimes be signed inside the file itself via
//     Signed-By clearsign; we require the detached .asc layout that
//     dnf/yum publish by default.
type yumChecker struct {
	client      *http.Client
	logger      *slog.Logger
	ecosystem   string // "yum" or "dnf" — same format, different dispatch key
	keyringPath string

	keyringOverride openpgp.EntityList
}

func newYumCheckerWithKeyring(client *http.Client, logger *slog.Logger, ecosystem, keyringPath string) *yumChecker {
	return &yumChecker{
		client:      client,
		logger:      logger,
		ecosystem:   ecosystem,
		keyringPath: keyringPath,
	}
}

func newYUMChecker(client *http.Client, logger *slog.Logger) *yumChecker {
	return newYumCheckerWithKeyring(client, logger, "yum", os.Getenv("CHAINSAW_RPM_KEYRING"))
}

func newDNFChecker(client *http.Client, logger *slog.Logger) *yumChecker {
	return newYumCheckerWithKeyring(client, logger, "dnf", os.Getenv("CHAINSAW_RPM_KEYRING"))
}

func (c *yumChecker) Ecosystem() string { return c.ecosystem }

func (c *yumChecker) Check(ctx context.Context, packageName, version string) Result {
	return c.CheckWithSource(ctx, packageName, version, "")
}

func (c *yumChecker) CheckWithSource(ctx context.Context, packageName, version, sourceURL string) Result {
	if sourceURL == "" {
		return Result{
			Status:    StatusUnavailable,
			Ecosystem: c.ecosystem,
			Error:     "OS package provenance requires the source repository URL; call CheckWithSource",
		}
	}
	base := strings.TrimRight(sourceURL, "/")

	keyring, err := c.loadKeyring()
	if err != nil {
		if c.logger != nil {
			c.logger.Warn("rpm provenance: keyring unavailable",
				"package", packageName, "version", version, "error", err.Error())
		}
		return Result{
			Status:          StatusUnavailable,
			Ecosystem:       c.ecosystem,
			AttestationType: "pgp-repo",
			Error:           fmt.Sprintf("keyring unavailable: %v", err),
		}
	}

	// Step 1 — fetch repomd.xml and its detached signature.
	repomdBytes, err := c.fetchBytes(ctx, base+"/repodata/repomd.xml", 4<<20)
	if err != nil {
		return inconclusive(c.ecosystem, fmt.Sprintf("fetch repomd.xml: %v", err))
	}
	sigBytes, err := c.fetchBytes(ctx, base+"/repodata/repomd.xml.asc", 1<<20)
	if err != nil {
		return inconclusive(c.ecosystem, fmt.Sprintf("fetch repomd.xml.asc: %v", err))
	}

	// Step 2 — verify detached signature against repomd bytes.
	signer, err := openpgp.CheckArmoredDetachedSignature(keyring, bytes.NewReader(repomdBytes), bytes.NewReader(sigBytes), nil)
	if err != nil {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       c.ecosystem,
			AttestationType: "pgp-repo",
			Error:           fmt.Sprintf("repomd.xml signature: %v", err),
		}
	}
	signerDesc := fmt.Sprintf("%X", signer.PrimaryKey.Fingerprint)
	for _, id := range signer.Identities {
		if id.UserId != nil {
			signerDesc = fmt.Sprintf("%s <%s> [%s]", id.UserId.Name, id.UserId.Email, signerDesc)
			break
		}
	}

	// Step 3 — parse repomd.xml, pull the primary.xml[.gz] entry.
	primary, err := pickPrimaryEntry(repomdBytes)
	if err != nil {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       c.ecosystem,
			AttestationType: "pgp-repo",
			Error:           fmt.Sprintf("parse repomd.xml: %v", err),
		}
	}

	// Step 4 — fetch and hash primary.
	primaryURL := base + "/" + strings.TrimLeft(primary.Location, "/")
	primaryBytes, err := c.fetchBytes(ctx, primaryURL, 512<<20)
	if err != nil {
		return inconclusive(c.ecosystem, fmt.Sprintf("fetch primary.xml: %v", err))
	}
	if got := sha256.Sum256(primaryBytes); !bytes.Equal(got[:], primary.SHA256) {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       c.ecosystem,
			AttestationType: "pgp-repo",
			Error:           fmt.Sprintf("primary.xml sha256 mismatch: got %x, want %x", got, primary.SHA256),
		}
	}
	primaryPlain, err := maybeDecompress(primary.Location, primaryBytes)
	if err != nil {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       c.ecosystem,
			AttestationType: "pgp-repo",
			Error:           fmt.Sprintf("decompress primary.xml: %v", err),
		}
	}

	// Step 5 — find the requested NEVRA in primary.xml.
	pkg, ok := findPrimaryPackage(primaryPlain, packageName, version)
	if !ok {
		return Result{
			Status:          StatusMissing,
			Ecosystem:       c.ecosystem,
			AttestationType: "pgp-repo",
			Error:           fmt.Sprintf("package %s=%s not found in primary.xml", packageName, version),
		}
	}

	// Step 6 — fetch the .rpm and hash it.
	rpmURL := base + "/" + strings.TrimLeft(pkg.Location, "/")
	rpmHash, err := c.fetchSHA256(ctx, rpmURL)
	if err != nil {
		return inconclusive(c.ecosystem, fmt.Sprintf("fetch .rpm: %v", err))
	}
	if !bytes.Equal(rpmHash[:], pkg.SHA256) {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       c.ecosystem,
			AttestationType: "pgp-repo",
			Error:           fmt.Sprintf(".rpm sha256 mismatch: got %x, want %x", rpmHash, pkg.SHA256),
		}
	}

	return Result{
		Status:          StatusVerified,
		Ecosystem:       c.ecosystem,
		AttestationType: "pgp-repo",
		BuilderID:       signerDesc,
	}
}

func (c *yumChecker) loadKeyring() (openpgp.EntityList, error) {
	if c.keyringOverride != nil {
		return c.keyringOverride, nil
	}
	return loadKeyring(c.keyringPath, "rpm")
}

func (c *yumChecker) fetchBytes(ctx context.Context, target string, maxBytes int64) ([]byte, error) {
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

func (c *yumChecker) fetchSHA256(ctx context.Context, target string) ([32]byte, error) {
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
	if _, err := io.Copy(h, io.LimitReader(resp.Body, 1<<30)); err != nil {
		return digest, err
	}
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

// --- repomd.xml / primary.xml parsing --------------------------------------

type repomdData struct {
	XMLName  xml.Name        `xml:"repomd"`
	DataList []repomdDataElt `xml:"data"`
}

type repomdDataElt struct {
	Type     string         `xml:"type,attr"`
	Checksum repomdChecksum `xml:"checksum"`
	Location repomdLocation `xml:"location"`
}

type repomdChecksum struct {
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

type repomdLocation struct {
	Href string `xml:"href,attr"`
}

// primaryEntry is the subset we need from repomd.xml's "primary" data
// entry.
type primaryEntry struct {
	Location string
	SHA256   []byte
}

func pickPrimaryEntry(body []byte) (primaryEntry, error) {
	var doc repomdData
	if err := xml.Unmarshal(body, &doc); err != nil {
		return primaryEntry{}, err
	}
	for _, d := range doc.DataList {
		if d.Type != "primary" {
			continue
		}
		if !strings.EqualFold(d.Checksum.Type, "sha256") {
			return primaryEntry{}, fmt.Errorf("primary checksum is %q, want sha256", d.Checksum.Type)
		}
		raw, err := hex.DecodeString(strings.TrimSpace(d.Checksum.Value))
		if err != nil || len(raw) != 32 {
			return primaryEntry{}, fmt.Errorf("primary checksum unparseable")
		}
		if d.Location.Href == "" {
			return primaryEntry{}, errors.New("primary location missing")
		}
		return primaryEntry{Location: d.Location.Href, SHA256: raw}, nil
	}
	return primaryEntry{}, errors.New(`no <data type="primary"> entry`)
}

type primaryPackage struct {
	Name     string
	Version  string // we compare against the <version ver=…> attribute
	Location string
	SHA256   []byte
}

// Minimal primary.xml schema — RPM primary.xml is verbose, but we only
// need a few fields per package.
type primaryDoc struct {
	XMLName  xml.Name     `xml:"metadata"`
	Packages []primaryPkg `xml:"package"`
}

type primaryPkg struct {
	Type     string          `xml:"type,attr"`
	Name     string          `xml:"name"`
	Version  primaryVersion  `xml:"version"`
	Checksum primaryChecksum `xml:"checksum"`
	Location primaryPkgLoc   `xml:"location"`
}

type primaryVersion struct {
	Ver string `xml:"ver,attr"`
	Rel string `xml:"rel,attr"`
}

type primaryChecksum struct {
	Type  string `xml:"type,attr"`
	Pkgid string `xml:"pkgid,attr"`
	Value string `xml:",chardata"`
}

type primaryPkgLoc struct {
	Href string `xml:"href,attr"`
}

// findPrimaryPackage scans primary.xml for an rpm-type package matching
// (name, version). "version" here is the full RPM version-release
// (e.g. "1.0-1") when callers pass it that way; we also match on just
// <ver> when the caller doesn't know the release, because the Packages
// proxy commonly receives the "upstream version" only.
func findPrimaryPackage(body []byte, name, version string) (primaryPackage, bool) {
	var doc primaryDoc
	if err := xml.Unmarshal(body, &doc); err != nil {
		return primaryPackage{}, false
	}
	for _, p := range doc.Packages {
		if p.Type != "rpm" && p.Type != "" {
			continue
		}
		if p.Name != name {
			continue
		}
		// Try version match against either "ver" alone or "ver-rel".
		if p.Version.Ver != version && p.Version.Ver+"-"+p.Version.Rel != version {
			continue
		}
		if !strings.EqualFold(p.Checksum.Type, "sha256") {
			continue
		}
		raw, err := hex.DecodeString(strings.TrimSpace(p.Checksum.Value))
		if err != nil || len(raw) != 32 {
			continue
		}
		return primaryPackage{
			Name:     p.Name,
			Version:  p.Version.Ver,
			Location: p.Location.Href,
			SHA256:   raw,
		}, true
	}
	return primaryPackage{}, false
}
