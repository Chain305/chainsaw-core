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
			Error:     fmt.Sprintf("artifact too large to verify (> %d bytes); range-GET path is a follow-up", nupkgSizeCap),
		}
	}
	pkgBytes, status, err := fetchBytes(ctx, c.client, pkgURL, nupkgSizeCap)
	if err != nil {
		if isNotFound(status) {
			return Result{Status: StatusMissing, Ecosystem: "nuget"}
		}
		return Result{Status: StatusFailed, Ecosystem: "nuget", Error: err.Error()}
	}

	sig, err := extractNupkgSignature(pkgBytes)
	if err != nil {
		return Result{Status: StatusMissing, Ecosystem: "nuget"}
	}

	p7, err := pkcs7.Parse(sig)
	if err != nil {
		return Result{
			Status:          StatusFailed,
			Ecosystem:       "nuget",
			AttestationType: "x509",
			Error:           fmt.Sprintf("parse PKCS#7: %v", err),
		}
	}

	trust, err := c.loadTrustRoots(ctx)
	if err != nil {
		return Result{
			Status:          StatusUnverified,
			Ecosystem:       "nuget",
			AttestationType: "x509",
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
