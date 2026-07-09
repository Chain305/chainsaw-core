package sigstoreverify

// This file is named *_testing.go (not *_test.go) so it ships in the
// regular package surface and is importable from other packages' tests.
// Production code paths must NOT call these helpers — they exist purely
// to bypass the live TUF trust-root fetch in tests that exercise
// callers of Default(ctx).

import (
	"testing"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
)

// NewVerifierFromTrustedRootForTesting constructs a Verifier around a
// caller-supplied, pinned trusted root instead of the live TUF-fetched
// one. This is the seam that lets a test drive the REAL Verify() crypto
// pipeline OFFLINE: pin a snapshot trusted root (parsed from testdata via
// root.NewTrustedRootFromJSON) and feed it a genuinely-signed bundle, so
// the test exercises Fulcio-cert / Rekor-log / DSSE-or-message-signature
// verification against real bytes — not a stub.
//
// The *testing.T parameter is unused at runtime; it exists so this cannot
// be reached from production code (a *testing.T is only obtainable from
// the testing package). Production paths construct a Verifier via
// NewLiveVerifier / Default, never this.
func NewVerifierFromTrustedRootForTesting(t *testing.T, tr root.TrustedMaterial) *Verifier {
	if t == nil {
		panic("NewVerifierFromTrustedRootForTesting requires a *testing.T")
	}
	if tr == nil {
		panic("NewVerifierFromTrustedRootForTesting requires a non-nil trusted root")
	}
	return &Verifier{trustedRoot: tr}
}

// SetDefaultVerifierForTesting overrides the process-wide cached
// Verifier returned by Default(ctx) with the supplied stub. It returns
// a restore function that the caller MUST invoke (typically via
// t.Cleanup) so the next test that needs the real live trust root is
// not poisoned by the stub.
//
// This is the seam that lets tests for callers of
// sigstoreverify.Default — notably internal/policy/dsl.VerifyBundle —
// run deterministically on a network-isolated CI runner. Without it,
// the first call to Default(ctx) blocks on a live TUF fetch which is
// (a) flaky on CI and (b) provides a weaker security signal because
// failures attribute to "network down" rather than "bundle bytes
// rejected".
//
// Pass nil to install a placeholder Verifier whose Verify method will
// reject any bundle that is not parseable. That is exactly what the
// corrupted-bundle test wants: bundle.UnmarshalJSON runs before the
// trustedRoot is consulted, so a Verifier with a nil trustedRoot
// surfaces the inline parse error rather than the TUF fetch error.
//
// The *testing.T parameter is unused at runtime; it exists so callers
// cannot accidentally invoke this from non-test code (a *testing.T can
// only be obtained from the testing package's test/benchmark hooks).
func SetDefaultVerifierForTesting(t *testing.T, v *Verifier) (restore func()) {
	if t == nil {
		panic("SetDefaultVerifierForTesting requires a *testing.T")
	}
	defaultCache.mu.Lock()
	defer defaultCache.mu.Unlock()

	prevV := defaultCache.v
	prevErr := defaultCache.err
	prevExpires := defaultCache.expiresAt

	if v == nil {
		v = &Verifier{}
	}
	defaultCache.v = v
	defaultCache.err = nil
	// Far-future expiry so the cache never re-invokes the loader during
	// the test. The restore func resets this.
	defaultCache.expiresAt = defaultCache.clock.Now().Add(24 * time.Hour)

	return func() {
		defaultCache.mu.Lock()
		defer defaultCache.mu.Unlock()
		defaultCache.v = prevV
		defaultCache.err = prevErr
		defaultCache.expiresAt = prevExpires
	}
}
