// Package sigstoreverify is a thin wrapper around sigstore-go that verifies
// a Sigstore bundle against the live Sigstore trust root and extracts the
// OIDC identity of the signer.
//
// A single Verifier (with a cached trusted root) is shared across all
// provenance checks via the package-level Default() accessor. Tests can
// substitute their own Verifier.
package sigstoreverify

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jonboulle/clockwork"
	fulciocert "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// Identity is the subset of Sigstore verification output the provenance
// system cares about.
type Identity struct {
	// SourceRepo is the URL of the source repository the build originated
	// from (e.g. "https://github.com/foo/bar"). Empty if not discoverable.
	SourceRepo string
	// BuilderID is the OIDC subject (workflow URL for GitHub Actions,
	// equivalent for GitLab/Buildkite) — the closest thing to a "who built
	// this" identity that Sigstore gives us.
	BuilderID string
	// Issuer is the OIDC issuer URL that minted the Fulcio cert
	// (e.g. "https://token.actions.githubusercontent.com").
	Issuer string
}

// Verifier wraps a sigstore-go Verifier with the live Sigstore trust root.
type Verifier struct {
	trustedRoot root.TrustedMaterial
}

// NewLiveVerifier fetches the current Sigstore trust root via TUF. This
// performs network I/O. The caller's context can cancel the wait; the
// underlying TUF fetch may continue to completion in the background
// (sigstore-go doesn't expose a cancellable API) but the result is
// discarded.
func NewLiveVerifier(ctx context.Context) (*Verifier, error) {
	type result struct {
		v   *Verifier
		err error
	}
	ch := make(chan result, 1)
	go func() {
		opts := tuf.DefaultOptions()
		tr, err := root.NewLiveTrustedRoot(opts)
		if err != nil {
			ch <- result{nil, fmt.Errorf("fetch sigstore trust root: %w", err)}
			return
		}
		ch <- result{&Verifier{trustedRoot: tr}, nil}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		return r.v, r.err
	}
}

// Verify parses the Sigstore bundle JSON and verifies it against the trust
// root. artifactSHA256 is the expected SHA-256 of the artifact the bundle
// attests to (32 bytes). Identity-of-signer is not constrained — callers
// receive whatever identity the bundle binds to.
func (v *Verifier) Verify(bundleJSON []byte, artifactSHA256 []byte) (*Identity, error) {
	return v.VerifyDigest(bundleJSON, DigestSHA256, artifactSHA256)
}

// DigestAlgorithms are the artifact digest algorithms an in-toto subject may
// bind, and the raw byte length of each.
//
// sha512 is here because npm uses it and ONLY it. Until 2026-09-24 this
// package hardcoded "sha256" into the verification policy, so every npm
// attestation was checked against a digest algorithm its statement does not
// carry: **0 of 1,857 npm sigstore verifications had ever succeeded** in
// production, 1,852 of them recorded as StatusFailed with "provided artifact
// digests does not match digests in statement". A 100% failure rate across 439
// distinct publishers — including plainly legitimate ones like
// radix-ui/primitives — was us, not them.
const (
	DigestSHA256 = "sha256"
	DigestSHA512 = "sha512"
)

var digestLengths = map[string]int{
	DigestSHA256: 32,
	DigestSHA512: 64,
}

// VerifyDigest is Verify with the artifact digest algorithm named explicitly.
// The algorithm must be one the bundle's in-toto subject actually binds —
// sigstore-go matches on the algorithm key, so naming one the statement does
// not carry fails with a digest mismatch rather than an unsupported-algorithm
// error, which is why the npm breakage above read as "the digests differ".
func (v *Verifier) VerifyDigest(bundleJSON []byte, alg string, digest []byte) (*Identity, error) {
	want, ok := digestLengths[alg]
	if !ok {
		return nil, fmt.Errorf("unsupported artifact digest algorithm %q", alg)
	}
	if len(digest) != want {
		return nil, fmt.Errorf("artifact %s digest: want %d bytes, got %d", alg, want, len(digest))
	}
	b, err := parseBundle(bundleJSON)
	if err != nil {
		return nil, err
	}

	vr, err := verify.NewVerifier(
		v.trustedRoot,
		verify.WithObserverTimestamps(1),
		verify.WithTransparencyLog(1),
	)
	if err != nil {
		return nil, fmt.Errorf("build sigstore verifier: %w", err)
	}

	policy := verify.NewPolicy(
		verify.WithArtifactDigest(alg, digest),
		verify.WithoutIdentitiesUnsafe(), // we extract the identity, we don't constrain it
	)

	result, err := vr.Verify(b, policy)
	if err != nil {
		return nil, fmt.Errorf("sigstore verify: %w", err)
	}

	return extractIdentity(result), nil
}

// InspectBundleIdentity parses a Sigstore bundle's JSON form and extracts
// the Fulcio-signed identity (issuer, source repo, builder workflow) WITHOUT
// running the full cryptographic verify pipeline. This is intended for
// callers who hold a bundle but don't have the artifact digest required for
// full verification — notably, model-signing v1 bundles that cover an
// in-toto manifest stored elsewhere. The returned identity is INFORMATIONAL
// ONLY: it has not been checked against the Sigstore trust root, so it does
// not prove that the bundle is authentic. Callers must surface this
// distinction in their result (e.g. StatusUnverified, not StatusVerified).
func InspectBundleIdentity(bundleJSON []byte) (*Identity, error) {
	b, err := parseBundle(bundleJSON)
	if err != nil {
		return nil, err
	}
	vc, err := b.VerificationContent()
	if err != nil {
		return nil, fmt.Errorf("bundle verification content: %w", err)
	}
	cert := vc.Certificate()
	if cert == nil {
		// Public-key bundles (no Fulcio cert) have no OIDC identity to
		// extract — return an empty identity.
		return &Identity{}, nil
	}
	ext, err := fulciocert.ParseExtensions(cert.Extensions)
	if err != nil {
		return nil, fmt.Errorf("parse fulcio extensions: %w", err)
	}
	id := &Identity{
		Issuer:     ext.Issuer,
		SourceRepo: strings.TrimPrefix(ext.SourceRepositoryURI, "git+"),
	}
	if ext.BuildConfigURI != "" {
		id.BuilderID = ext.BuildConfigURI
	} else if len(cert.URIs) > 0 {
		id.BuilderID = cert.URIs[0].String()
	}
	return id, nil
}

// extractIdentity distills the verification result into our minimal
// Identity struct. Fields are best-effort — empty is acceptable.
func extractIdentity(r *verify.VerificationResult) *Identity {
	id := &Identity{}
	if r == nil || r.Signature == nil || r.Signature.Certificate == nil {
		return id
	}
	cert := r.Signature.Certificate
	id.Issuer = cert.Issuer
	id.SourceRepo = cert.SourceRepositoryURI
	// Prefer the build config URI (workflow ref) as BuilderID; fall back to
	// SubjectAlternativeName.
	if cert.BuildConfigURI != "" {
		id.BuilderID = cert.BuildConfigURI
	} else if cert.SubjectAlternativeName != "" {
		id.BuilderID = cert.SubjectAlternativeName
	}
	// Normalize git+https:// prefix sometimes emitted by runners.
	id.SourceRepo = strings.TrimPrefix(id.SourceRepo, "git+")
	return id
}

// Default returns a process-wide shared Verifier, lazily initializing it on
// first call. Successful fetches are cached for trustRootTTL; failures are
// cached for only failureBackoff so that a transient network error doesn't
// permanently disable Sigstore verification.
func Default(ctx context.Context) (*Verifier, error) {
	return defaultCache.get(ctx)
}

const (
	// trustRootTTL is how long a successfully-fetched Sigstore trust root
	// is reused before we refresh it.
	trustRootTTL = 6 * time.Hour
	// failureBackoff is how long a failed fetch is remembered before we
	// retry. Short enough that a transient outage doesn't poison the
	// process for long; long enough to avoid hammering the TUF endpoint
	// during a sustained outage.
	failureBackoff = 1 * time.Minute
)

// cachedVerifier is a TTL-gated singleton around NewLiveVerifier. A success
// is cached for trustRootTTL; a failure for failureBackoff — after which
// the next caller retries.
type cachedVerifier struct {
	mu        sync.Mutex
	clock     clockwork.Clock
	loader    func(context.Context) (*Verifier, error)
	v         *Verifier
	err       error
	expiresAt time.Time
}

var defaultCache = &cachedVerifier{
	clock:  clockwork.NewRealClock(),
	loader: NewLiveVerifier,
}

func (c *cachedVerifier) get(ctx context.Context) (*Verifier, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock.Now()
	if c.v != nil && now.Before(c.expiresAt) {
		return c.v, nil
	}
	if c.err != nil && now.Before(c.expiresAt) {
		return nil, c.err
	}
	v, err := c.loader(ctx)
	if err != nil {
		c.v = nil
		c.err = err
		c.expiresAt = now.Add(failureBackoff)
		return nil, err
	}
	c.v = v
	c.err = nil
	c.expiresAt = now.Add(trustRootTTL)
	return v, nil
}
