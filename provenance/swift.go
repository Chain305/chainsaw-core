package provenance

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	swiftformat "github.com/chain305/chainsaw-core/formats/swift"
)

// swiftChecker probes a Swift Package Registry (SE-0292) for SE-0391
// CMS signatures.
//
// Behavior depends on whether full verification is configured (see
// Checker.WithSwiftFullVerify):
//
//   - Without a verifier: StatusUnverified when the registry advertises
//     a CMS signature on the archive, StatusMissing otherwise. This is
//     the default — it skips the cost of fetching the archive bytes.
//   - With a verifier: the probe additionally fetches the archive,
//     pulls the detached signature out of the metadata, and runs full
//     CMS chain + digest verification via swiftformat.Verifier. On
//     success returns StatusVerified with the signer details; on
//     failure returns StatusFailed with the verifier error.
//
// The registry URL and verifier are read lazily via closures so
// operators can mutate them after construction.
type swiftChecker struct {
	client      *http.Client
	logger      *slog.Logger
	registryURL func() string
	verifier    func() *swiftformat.Verifier
}

func newSwiftChecker(
	client *http.Client,
	logger *slog.Logger,
	registryURL func() string,
	verifier func() *swiftformat.Verifier,
) *swiftChecker {
	return &swiftChecker{
		client:      client,
		logger:      logger,
		registryURL: registryURL,
		verifier:    verifier,
	}
}

// maxSwiftArchiveBytes bounds the in-memory archive size during full
// verification. Real SE-0391 archives are tens of MB; 256 MB leaves
// plenty of headroom while preventing OOM on a malicious oversized
// response.
const maxSwiftArchiveBytes = 256 << 20

func (c *swiftChecker) Ecosystem() string { return "swift" }

func (c *swiftChecker) Check(ctx context.Context, packageName, version string) Result {
	base := ""
	if c.registryURL != nil {
		base = strings.TrimRight(c.registryURL(), "/")
	}
	if base == "" {
		return Result{Status: StatusUnavailable, Ecosystem: "swift"}
	}
	scope, name := splitSwiftPackageName(packageName)
	if scope == "" || name == "" || version == "" {
		return Result{Status: StatusMissing, Ecosystem: "swift"}
	}
	reqURL := fmt.Sprintf("%s/%s/%s/%s",
		base,
		url.PathEscape(scope),
		url.PathEscape(name),
		url.PathEscape(version))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return Result{Status: StatusFailed, Ecosystem: "swift", Error: err.Error()}
	}
	req.Header.Set("Accept", "application/vnd.swift.registry.v1+json")

	resp, err := c.client.Do(req)
	if err != nil {
		return Result{Status: StatusFailed, Ecosystem: "swift", Error: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return Result{Status: StatusMissing, Ecosystem: "swift"}
	}
	if resp.StatusCode != http.StatusOK {
		return Result{Status: StatusFailed, Ecosystem: "swift", Error: fmt.Sprintf("unexpected status %d", resp.StatusCode)}
	}

	var payload struct {
		Resources []struct {
			Name    string `json:"name"`
			Signing *struct {
				SignatureFormat string `json:"signatureFormat"`
				Signature       string `json:"signature"`
			} `json:"signing,omitempty"`
		} `json:"resources"`
		Metadata struct {
			RepositoryURLs []string `json:"repositoryURLs"`
		} `json:"metadata"`
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return Result{Status: StatusFailed, Ecosystem: "swift", Error: err.Error()}
	}
	if err := json.Unmarshal(data, &payload); err != nil {
		return Result{Status: StatusFailed, Ecosystem: "swift", Error: err.Error()}
	}

	// Locate the signed source archive resource (if any).
	var (
		signed         bool
		signatureFmt   string
		signatureB64   string
		archiveResName string
	)
	for _, r := range payload.Resources {
		if r.Signing != nil && r.Signing.SignatureFormat != "" {
			signed = true
			signatureFmt = r.Signing.SignatureFormat
			signatureB64 = r.Signing.Signature
			archiveResName = r.Name
			break
		}
	}
	if !signed {
		return Result{Status: StatusMissing, Ecosystem: "swift"}
	}
	result := Result{
		Status:          StatusUnverified,
		Ecosystem:       "swift",
		AttestationType: "cms-se0391",
	}
	if len(payload.Metadata.RepositoryURLs) > 0 {
		result.SourceRepo = payload.Metadata.RepositoryURLs[0]
	}

	// If full verification is enabled, fetch the archive and run the
	// CMS verifier. Failures fall through to StatusFailed (with the
	// verifier error message) so misbehaving registries are visible
	// rather than silently downgraded to StatusUnverified.
	if v := c.verifier(); v != nil {
		verifyResult, verifyErr := c.runFullVerify(ctx, base, scope, name, version, archiveResName, signatureB64, signatureFmt, v)
		if verifyErr != nil {
			c.logger.Debug("swift cms verification failed",
				"package", scope+"."+name, "version", version, "error", verifyErr)
			result.Status = StatusFailed
			result.Error = verifyErr.Error()
			return result
		}
		result.Status = StatusVerified
		result.BuilderID = verifyResult.Signer
		if verifyResult.SourceRepo != "" {
			// Prefer the cert-bound repo URL over the metadata-declared one.
			result.SourceRepo = verifyResult.SourceRepo
		}
	}
	return result
}

// runFullVerify fetches the source archive and runs CMS signature
// verification. The signature is taken from the metadata response (the
// `signing.signature` field is base64-encoded CMS bytes), so this only
// needs one extra HTTP request — for the archive itself.
func (c *swiftChecker) runFullVerify(
	ctx context.Context,
	base, scope, name, version, archiveName, signatureB64, signatureFmt string,
	verifier *swiftformat.Verifier,
) (swiftformat.VerifyResult, error) {
	if signatureB64 == "" {
		return swiftformat.VerifyResult{}, errors.New("registry advertised signature but signature payload is empty")
	}
	sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return swiftformat.VerifyResult{}, fmt.Errorf("decode signature: %w", err)
	}
	if archiveName == "" {
		archiveName = "source-archive"
	}

	// Fetch the archive. The signed resource is a sibling of the
	// metadata: GET {base}/{scope}/{name}/{version}.zip
	archiveURL := fmt.Sprintf("%s/%s/%s/%s.zip",
		base,
		url.PathEscape(scope),
		url.PathEscape(name),
		url.PathEscape(version))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, archiveURL, nil)
	if err != nil {
		return swiftformat.VerifyResult{}, err
	}
	req.Header.Set("Accept", "application/zip")

	resp, err := c.client.Do(req)
	if err != nil {
		return swiftformat.VerifyResult{}, fmt.Errorf("fetch archive: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return swiftformat.VerifyResult{}, fmt.Errorf("fetch archive: unexpected status %d", resp.StatusCode)
	}

	// LimitReader caps memory; if the archive exceeds the cap we'll
	// see an EOF on the next read attempt. Reading +1 byte past the
	// cap lets us detect oversize responses explicitly.
	archive, err := io.ReadAll(io.LimitReader(resp.Body, maxSwiftArchiveBytes+1))
	if err != nil {
		return swiftformat.VerifyResult{}, fmt.Errorf("read archive: %w", err)
	}
	if len(archive) > maxSwiftArchiveBytes {
		return swiftformat.VerifyResult{}, fmt.Errorf("archive exceeds %d-byte cap", maxSwiftArchiveBytes)
	}

	return verifier.Verify(archive, sigBytes, signatureFmt)
}

// splitSwiftPackageName returns (scope, name) for a normalized
// `scope.name` identifier, or ("", "") for malformed input.
func splitSwiftPackageName(identifier string) (scope, name string) {
	idx := strings.Index(identifier, ".")
	if idx <= 0 || idx == len(identifier)-1 {
		return "", ""
	}
	return identifier[:idx], identifier[idx+1:]
}
