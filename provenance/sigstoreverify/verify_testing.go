package sigstoreverify

// This file is named *_testing.go (not *_test.go) so it ships in the
// regular package surface and is importable from other packages' tests.
// Production code paths must NOT call these helpers — they exist purely
// to bypass the live TUF trust-root fetch in tests that exercise
// callers of Default(ctx).

import (
	"testing"
	"time"
)

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
