package provenance

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/digitorus/pkcs7"
	"github.com/jonboulle/clockwork"
)

// nugetChecker verifies NuGet packages by downloading the .nupkg (a signed
// zip), extracting its embedded PKCS#7 signature, and validating it
// against nuget.org's published repository-signing certificate list.
type nugetChecker struct {
	client *http.Client
	logger *slog.Logger

	trustCache *nugetTrustCache
}

func newNuGetChecker(client *http.Client, logger *slog.Logger) *nugetChecker {
	return &nugetChecker{
		client: client,
		logger: logger,
		trustCache: &nugetTrustCache{
			clock: clockwork.NewRealClock(),
			loader: func(ctx context.Context) (*x509.CertPool, error) {
				return fetchNuGetTrustPool(ctx, client)
			},
		},
	}
}

// nugetTrustCache is a TTL-gated cache of the nuget.org repository-signing
// trust pool. Success is cached for nugetTrustTTL; failure for
// nugetTrustBackoff so a transient fetch error doesn't poison the process.
type nugetTrustCache struct {
	mu        sync.Mutex
	clock     clockwork.Clock
	loader    func(context.Context) (*x509.CertPool, error)
	pool      *x509.CertPool
	err       error
	expiresAt time.Time
}

const (
	nugetTrustTTL     = 6 * time.Hour
	nugetTrustBackoff = 1 * time.Minute
)

func (c *nugetTrustCache) get(ctx context.Context) (*x509.CertPool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock.Now()
	if c.pool != nil && now.Before(c.expiresAt) {
		return c.pool, nil
	}
	if c.err != nil && now.Before(c.expiresAt) {
		return nil, c.err
	}
	pool, err := c.loader(ctx)
	if err != nil {
		c.pool = nil
		c.err = err
		c.expiresAt = now.Add(nugetTrustBackoff)
		return nil, err
	}
	c.pool = pool
	c.err = nil
	c.expiresAt = now.Add(nugetTrustTTL)
	return pool, nil
}

func (c *nugetChecker) Ecosystem() string { return "nuget" }

func (c *nugetChecker) Check(ctx context.Context, packageName, version string) Result {
	nameLower := strings.ToLower(packageName)
	versionLower := strings.ToLower(version)
	pkgURL := fmt.Sprintf("https://api.nuget.org/v3-flatcontainer/%s/%s/%s.%s.nupkg",
		nameLower, versionLower, nameLower, versionLower)

	// Most signed .nupkg files are under 10 MiB; the long tail (huge SDK
	// bundles) would otherwise force us to buffer 100s of MiB just to
	// read a few KiB .signature.p7s entry. Pre-check Content-Length via
	// HEAD and report StatusUnavailable for oversized packages.
	const nupkgSizeCap = 50 << 20
	if over, err := headContentTooLarge(ctx, c.client, pkgURL, nupkgSizeCap); err == nil && over {
		return Result{
			Status:    StatusUnavailable,
			Ecosystem: "nuget",
			Reason:    ReasonArtifactTooLarge,
			Error:     fmt.Sprintf("artifact too large to verify (> %d bytes); range-GET path is a follow-up", nupkgSizeCap),
		}
	}
	pkgBytes, status, err := fetchBytes(ctx, c.client, pkgURL, nupkgSizeCap)
	if err != nil {
		if isNotFound(status) {
			return Result{
				Status:    StatusMissing,
				Ecosystem: "nuget",
				Reason:    ReasonNoAttestationFound,
				Error:     "nuget.org has no .nupkg at this coordinate (404)",
			}
		}
		// Not reaching nuget.org is not a signature failure. StatusFailed
		// is reserved for "we validated and it did not hold" — see the
		// StatusFailed doc comment.
		return Result{
			Status:    StatusUnavailable,
			Ecosystem: "nuget",
			Reason:    ReasonUpstreamError,
			Error:     fmt.Sprintf("fetch .nupkg: %v", err),
		}
	}

	sig, err := extractNupkgSignature(pkgBytes)
	if err != nil {
		return Result{
			Status:    StatusMissing,
			Ecosystem: "nuget",
			Reason:    ReasonNoAttestationFound,
			Error:     "the .nupkg contains no .signature.p7s entry (package is unsigned)",
		}
	}

	p7, err := pkcs7.Parse(sig)
	if err != nil {
		// A signature IS present — we simply cannot walk its wire format.
		// That is a coverage gap in chainsaw, not evidence against the
		// package, so it must never render as StatusFailed (the status a
		// TAMPERED package gets). See P8-46.
		return Result{
			Status:          StatusUnverified,
			Ecosystem:       "nuget",
			AttestationType: "x509",
			Reason:          ReasonAttestationUnparseable,
			Error: fmt.Sprintf("chainsaw could not parse the .signature.p7s CMS structure (%v); "+
				"the package IS signed — this is a chainsaw coverage gap, not a signature failure", err),
		}
	}

	// P8-46, the case that actually bites: pkcs7.Parse SUCCEEDS on a real
	// nuget.org signature and returns ZERO signers.
	//
	// nuget.org emits CMS SignedData version 3 whose SignerInfo uses the
	// CMS SignerIdentifier CHOICE `subjectKeyIdentifier [0] IMPLICIT OCTET
	// STRING`. digitorus/pkcs7 models only the PKCS#7 `issuerAndSerialNumber
	// SEQUENCE` form, so the SET OF SignerInfo fails to decode — and
	// parseSignedData (verify.go:242) DISCARDS the asn1.Unmarshal error.
	// Parse therefore returns a PKCS7 with 6 certificates and no signers,
	// and VerifyWithChain reports "pkcs7: Message has no signers", which
	// this checker used to surface as FAILED — the same verdict a tampered
	// package gets, on a package that is correctly author- AND
	// repository-signed.
	//
	// Distinguishing the gap from a real failure is exact, not heuristic:
	// re-decode the SignedData with the SignerIdentifier left opaque. If
	// SignerInfo entries are present in the DER but absent from p7.Signers,
	// the library dropped them and nothing has been verified either way.
	if len(p7.Signers) == 0 {
		if n, derr := cmsSignerInfoCount(sig); derr == nil && n > 0 {
			return Result{
				Status:          StatusUnverified,
				Ecosystem:       "nuget",
				AttestationType: "x509",
				Reason:          ReasonAttestationUnparseable,
				Error: fmt.Sprintf("the .signature.p7s carries %d CMS SignerInfo entr(ies) that chainsaw's "+
					"PKCS#7 parser cannot read (nuget.org uses the CMS subjectKeyIdentifier form of "+
					"SignerIdentifier; digitorus/pkcs7 only models issuerAndSerialNumber). The package IS "+
					"signed — this is a chainsaw coverage gap, not a signature failure", n),
			}
		}
		return Result{
			Status:          StatusUnverified,
			Ecosystem:       "nuget",
			AttestationType: "x509",
			Reason:          ReasonAttestationUnparseable,
			Error:           "the .signature.p7s parsed but declares no signers; nothing could be validated",
		}
	}

	trust, err := c.loadTrustRoots(ctx)
	if err != nil {
		return Result{
			Status:          StatusUnverified,
			Ecosystem:       "nuget",
			AttestationType: "x509",
			Reason:          ReasonTrustRootsUnavailable,
			Error:           fmt.Sprintf("load trust roots: %v", err),
		}
	}
	if err := p7.VerifyWithChain(trust); err != nil {
		if c.logger != nil {
			c.logger.Debug("nuget pkcs7 verification failed",
				"package", packageName, "version", version, "error", err.Error())
		}
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "nuget",
			AttestationType: "x509",
			Error:           err.Error(),
		}
	}

	signer := p7.GetOnlySigner()
	builderID := ""
	if signer != nil {
		builderID = signer.Subject.CommonName
	}
	return Result{
		Status:          StatusVerified,
		Ecosystem:       "nuget",
		AttestationType: "x509",
		BuilderID:       builderID,
	}
}

// extractNupkgSignature opens a .nupkg (zip) and returns the contents of
// the `.signature.p7s` entry, if present.
func extractNupkgSignature(pkg []byte) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		return nil, fmt.Errorf("open nupkg: %w", err)
	}
	for _, f := range zr.File {
		if f.Name != ".signature.p7s" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(io.LimitReader(rc, 10<<20))
	}
	return nil, fmt.Errorf("no .signature.p7s in nupkg")
}

// loadTrustRoots fetches nuget.org's repository signature certificates and
// assembles them into an x509.CertPool, cached in-process with a TTL.
func (c *nugetChecker) loadTrustRoots(ctx context.Context) (*x509.CertPool, error) {
	return c.trustCache.get(ctx)
}

func fetchNuGetTrustPool(ctx context.Context, client *http.Client) (*x509.CertPool, error) {
	return fetchNuGetTrustPoolFrom(ctx, client,
		"https://api.nuget.org/v3-index/repository-signatures/5.0.0/index.json")
}

// fetchNuGetTrustPoolFrom is fetchNuGetTrustPool with an overridable index
// URL — exposed for testing.
func fetchNuGetTrustPoolFrom(ctx context.Context, client *http.Client, indexURL string) (*x509.CertPool, error) {
	body, _, err := fetchBytes(ctx, client, indexURL, 1<<20)
	if err != nil {
		return nil, err
	}
	var idx struct {
		SigningCertificates []struct {
			ContentURL string `json:"contentUrl"`
		} `json:"signingCertificates"`
	}
	if err := json.Unmarshal(body, &idx); err != nil {
		return nil, fmt.Errorf("parse cert index: %w", err)
	}

	pool := x509.NewCertPool()
	var errs []error
	added := 0
	for _, sc := range idx.SigningCertificates {
		if sc.ContentURL == "" {
			continue
		}
		certBytes, _, err := fetchBytes(ctx, client, sc.ContentURL, 1<<20)
		if err != nil {
			errs = append(errs, fmt.Errorf("fetch %s: %w", sc.ContentURL, err))
			continue
		}
		// Accept either PEM or DER.
		if block, _ := pem.Decode(certBytes); block != nil {
			certBytes = block.Bytes
		}
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			errs = append(errs, fmt.Errorf("parse %s: %w", sc.ContentURL, err))
			continue
		}
		pool.AddCert(cert)
		added++
	}
	if added == 0 {
		return nil, fmt.Errorf("no nuget trust certificates loaded (%d errors: %v)", len(errs), errs)
	}
	return pool, nil
}
