// Package provenance verifies build/artifact provenance attestations for
// packages across supported ecosystems. Ecosystem-specific logic lives in
// its own file (npm.go, pypi.go, ...) behind the EcosystemChecker interface.
package provenance

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	swiftformat "github.com/chain305/chainsaw-core/formats/swift"
	"github.com/chain305/chainsaw-core/httpclient"
	"github.com/chain305/chainsaw-core/provenance/sigstoreverify"
)

// Status represents the provenance verification state of a package.
type Status string

const (
	// StatusVerified means provenance attestation was found and verified.
	StatusVerified Status = "verified"
	// StatusUnverified means attestation was found but could not be verified.
	StatusUnverified Status = "unverified"
	// StatusUnavailable means the ecosystem doesn't support provenance.
	StatusUnavailable Status = "unavailable"
	// StatusMissing means the ecosystem supports provenance but this package has none.
	StatusMissing Status = "missing"
	// StatusFailed means verification was attempted but failed.
	StatusFailed Status = "failed"
)

// Result captures the outcome of a provenance check.
//
// The SLSA-related fields (SLSALevel, SubjectDigest, AttestationBundle,
// BundleFormat, TransparencyLogURL, SourceCommit, VerifiedAt, CacheStale,
// Warnings) are populated when the underlying ecosystem produces in-toto /
// Sigstore / x509 / GPG attestations the checker can parse. Ecosystems
// without attestation support (rubygems, composer, cargo, ...) leave them
// zero-valued. Result is purely informational — blocking decisions are made
// downstream by the policy engine, not here.
type Result struct {
	Status          Status `json:"status"`
	Ecosystem       string `json:"ecosystem,omitempty"`
	AttestationType string `json:"attestationType,omitempty"` // sigstore, gpg, x509, sumdb, etc.
	SourceRepo      string `json:"sourceRepo,omitempty"`      // linked source repository if found
	BuilderID       string `json:"builderId,omitempty"`       // CI/CD builder identity or signer
	SignerID        string `json:"signerId,omitempty"`        // stable signer key identity (e.g. x509 cert SHA-256 fingerprint)
	Error           string `json:"error,omitempty"`

	// SLSALevel is the SLSA build level (1-4) the verified attestation
	// claims. Zero means "no verified attestation" or "ecosystem can't
	// express SLSA levels" (e.g. APT/YUM gpg-only). Populated only when
	// Status == StatusVerified.
	SLSALevel int `json:"slsaLevel,omitempty"`

	// SubjectDigest is the sha256 of the artifact the attestation binds
	// to (e.g. tarball SHA256 from npm's in-toto subject), prefixed with
	// the digest algorithm: "sha256:abcd..." Empty when the format
	// doesn't carry one.
	SubjectDigest string `json:"subjectDigest,omitempty"`

	// AttestationBundle is the raw bytes of the verified attestation
	// (in-toto envelope, Sigstore bundle, CMS blob, or GPG signature).
	// Stored verbatim so downstream code can re-verify or surface the
	// full chain in audit/dashboard views without round-tripping to the
	// upstream registry.
	AttestationBundle []byte `json:"-"`

	// BundleFormat names the wire format of AttestationBundle. One of:
	// "in-toto", "sigstore-bundle", "cms", "gpg-detached", "sumdb-note".
	BundleFormat string `json:"bundleFormat,omitempty"`

	// TransparencyLogURL is the Rekor (or equivalent) entry URL for the
	// attestation, when one exists.
	TransparencyLogURL string `json:"transparencyLogUrl,omitempty"`

	// SourceCommit is the git commit SHA the attestation predicate
	// claims as the source of the build. Populated for in-toto SLSA
	// predicates that include resolvedDependencies / materials.
	SourceCommit string `json:"sourceCommit,omitempty"`

	// VerifiedAt records when the verification result was produced.
	// Used by callers (storage, cache) to age out stale results.
	VerifiedAt time.Time `json:"verifiedAt,omitempty"`

	// CacheStale is true when this Result was served from the Sigstore
	// cache past its TTL because Rekor/Fulcio was unreachable. Lets the
	// policy engine refuse decisions made on stale data via the
	// ForbidCacheStale condition.
	CacheStale bool `json:"cacheStale,omitempty"`

	// Warnings collects non-fatal verification notes (e.g. "rekor
	// unreachable, served from cache", "subject digest mismatch with
	// registry-reported sha"). Empty for clean verifications.
	Warnings []string `json:"warnings,omitempty"`
}

// Checker dispatches provenance checks to per-ecosystem implementations.
type Checker struct {
	client   *http.Client
	logger   *slog.Logger
	checkers map[string]EcosystemChecker
	// swiftRegistryURL is an optional SE-0292 registry base URL used by
	// the Swift provenance probe. When empty, the swift checker returns
	// StatusUnavailable. Mutated by WithSwiftRegistryURL.
	swiftRegistryURL string
	// swiftVerifier is non-nil when full SE-0391 CMS verification is
	// enabled. The Swift probe reads it lazily on each Check.
	swiftVerifier *swiftformat.Verifier
	// sigstoreCache is the on-disk Sigstore-bundle verification cache,
	// shared across per-ecosystem checkers that crypto-verify bundles
	// (npm, PyPI, Maven). nil means "no caching" — every bundle is
	// re-verified against Rekor/Fulcio. Configured via
	// WithSigstoreCache; the offline-fallback "last-known-good" behavior
	// only kicks in when this is non-nil.
	sigstoreCache *sigstoreverify.BundleCache
}

// CheckerOption configures a Checker at construction time. Typically
// threaded through from application config — see WithDisabledEcosystems
// and WithOfflineMode for the common cases.
type CheckerOption func(*Checker)

// WithDisabledEcosystems removes the named ecosystems from the checker's
// dispatch table so their Check calls return StatusUnavailable without
// doing any network work. Useful when a deployment can't reach specific
// upstream hosts (e.g. blocked egress to keys.openpgp.org).
func WithDisabledEcosystems(ecos ...string) CheckerOption {
	return func(c *Checker) {
		for _, e := range ecos {
			delete(c.checkers, strings.ToLower(e))
		}
	}
}

// WithOfflineMode strips every ecosystem checker so every Check call
// returns StatusUnavailable. Use for egress-restricted deployments where
// provenance verification is not possible at all.
func WithOfflineMode() CheckerOption {
	return func(c *Checker) {
		c.checkers = map[string]EcosystemChecker{}
	}
}

// WithSigstoreCache attaches a per-bundle verification cache used by the
// Sigstore-aware ecosystem checkers (npm, PyPI, Maven). Pass nil to
// disable caching. Without a cache, Sigstore verification still runs but
// every artifact incurs a full Rekor/Fulcio round-trip and there is no
// last-known-good fallback when the transparency log is unreachable.
func WithSigstoreCache(cache *sigstoreverify.BundleCache) CheckerOption {
	return func(c *Checker) {
		c.sigstoreCache = cache
	}
}

// WithHTTPClient overrides the default *http.Client used by every
// per-ecosystem provenance sub-checker. The intended caller is
// chainsaw-proxy bootstrap, which threads an internal/upstreamhttp
// shared client in so registry fetches pick up per-host rate
// limiting + 429 retry. Must be applied *before* sub-checkers are
// registered — NewChecker calls it early so this option works
// regardless of ordering. Nil is a no-op (keeps the default client).
func WithHTTPClient(client *http.Client) CheckerOption {
	return func(c *Checker) {
		if client != nil {
			c.client = client
		}
	}
}

// NewChecker creates a provenance checker with all built-in ecosystem
// checkers registered. Pass options to disable specific ecosystems or
// enable offline mode.
func NewChecker(logger *slog.Logger, opts ...CheckerOption) *Checker {
	if logger == nil {
		logger = slog.Default()
	}
	c := &Checker{
		client:   httpclient.New(httpclient.WithTimeout(15 * time.Second)),
		logger:   logger,
		checkers: map[string]EcosystemChecker{},
	}
	// Apply options early so WithHTTPClient can swap c.client before
	// the per-ecosystem sub-checkers capture a reference to it. The
	// c.checkers-mutating options (WithOfflineMode,
	// WithDisabledEcosystems) are effectively no-ops here because the
	// map is still empty; they are applied again after registration
	// below to prune the populated dispatch table.
	for _, opt := range opts {
		opt(c)
	}
	c.register(newNPMChecker(c.client, logger, func() *sigstoreverify.BundleCache { return c.sigstoreCache }), "npm")
	c.register(newPyPIChecker(c.client, logger), "pip", "pypi")
	c.register(newMavenChecker(c.client, logger), "maven")
	c.register(newGradleChecker(c.client, logger), "gradle")
	c.register(newRubyGemsChecker(c.client, logger), "rubygems", "gem")
	c.register(newGomodChecker(c.client, logger), "go", "gomod")
	c.register(newOCIChecker(c.client, logger), "docker", "oci")
	c.register(newNuGetChecker(c.client, logger), "nuget")
	c.register(newHuggingFaceChecker(c.client, logger), "huggingface")
	c.register(newAPTChecker(c.client, logger), "apt")
	c.register(newDNFChecker(c.client, logger), "dnf")
	c.register(newYUMChecker(c.client, logger), "yum")
	c.register(newCargoChecker(c.client, logger), "cargo")
	c.register(newComposerChecker(c.client, logger), "composer")
	c.register(newCocoaPodsChecker(c.client, logger), "cocoapods")
	// Swift checker reads the registry URL and verifier lazily via
	// closures so WithSwiftRegistryURL / WithSwiftFullVerify can mutate
	// them after construction.
	c.register(newSwiftChecker(
		c.client, logger,
		func() string { return c.swiftRegistryURL },
		func() *swiftformat.Verifier { return c.swiftVerifier },
	), "swift")
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// register adds an EcosystemChecker under one or more ecosystem aliases.
func (c *Checker) register(eco EcosystemChecker, aliases ...string) {
	for _, a := range aliases {
		c.checkers[strings.ToLower(a)] = eco
	}
}

// WithSwiftRegistryURL configures the base URL used by the Swift
// provenance probe. Returns the receiver for chaining.
func (c *Checker) WithSwiftRegistryURL(url string) *Checker {
	if c != nil {
		c.swiftRegistryURL = strings.TrimRight(url, "/")
	}
	return c
}

// WithSwiftFullVerify enables full SE-0391 CMS cryptographic
// verification in the Swift provenance probe. Pass the trust pool used
// to validate signing-cert chains; nil means "use the system trust
// pool". Without this option the Swift probe stops at signature
// presence detection (StatusUnverified) — see internal/provenance/swift.go
// for the rationale.
func (c *Checker) WithSwiftFullVerify(roots *x509.CertPool) *Checker {
	if c != nil {
		c.swiftVerifier = swiftformat.NewVerifier(roots)
	}
	return c
}

// Check verifies provenance for a package. This is designed to be called
// asynchronously after the artifact is cached.
func (c *Checker) Check(ctx context.Context, ecosystem, packageName, version string) Result {
	return c.CheckWithSource(ctx, ecosystem, packageName, version, "")
}

// CheckWithSource is Check with an additional sourceURL hint used by
// ecosystems where (name, version) alone don't identify the trust domain
// (APT/DNF/YUM repos, custom registries). Pass "" to fall back to the
// ecosystem's default.
func (c *Checker) CheckWithSource(ctx context.Context, ecosystem, packageName, version, sourceURL string) Result {
	ecosystem = strings.ToLower(ecosystem)
	checker, ok := c.checkers[ecosystem]
	if !ok {
		return Result{Status: StatusUnavailable, Ecosystem: ecosystem}
	}
	if sac, ok := checker.(SourceAwareChecker); ok {
		return sac.CheckWithSource(ctx, packageName, version, sourceURL)
	}
	return checker.Check(ctx, packageName, version)
}

// SupportsProvenance returns true if the ecosystem has a registered checker
// that can attempt real verification (as opposed to always returning
// StatusUnavailable).
func SupportsProvenance(ecosystem string) bool {
	switch strings.ToLower(ecosystem) {
	case "npm", "pip", "pypi", "maven", "gradle", "rubygems", "gem",
		"go", "gomod", "docker", "oci", "nuget", "huggingface", "swift",
		"apt", "yum", "dnf":
		return true
	default:
		return false
	}
}

// fetchJSON performs a GET and decodes the response as JSON. Shared across
// ecosystem checkers.
func fetchJSON(ctx context.Context, client *http.Client, url string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("404 not found")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5 MiB limit
	if err != nil {
		return nil, err
	}

	var result map[string]any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}
	return result, nil
}
