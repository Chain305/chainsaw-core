package provenance

// A SOURCE guard, deliberately, and labelled as one.
//
// The property it protects cannot be reached by a behavioural test in this
// repo: proving that npm.go names sha512 at the verify call needs a genuine
// npm sigstore bundle plus a live trust root, and the offline corpus has
// neither. The package's own real-crypto suite proves the VERIFIER honours the
// algorithm it is given (TestRealDSSEVerifyDigestSucceedsOnTheAlgorithmTheSubjectBinds);
// nothing proves npm.go hands it the right one.
//
// That gap is exactly how the original defect survived: **0 of 1,857 npm
// sigstore verifications had ever succeeded** in production, 1,852 of them
// recorded as StatusFailed, across 439 distinct publishers — and every unit
// test in the package was green throughout, because they all assert failures
// and a wrong algorithm still fails.
//
// Mutating `DigestSHA512` to `DigestSHA256` in npm.go survives the entire test
// suite without this. Reading the source is crude; it is also the only thing
// that goes red.

import (
	"os"
	"strings"
	"testing"
)

func TestNpmVerifyCallNamesSHA512(t *testing.T) {
	src, err := os.ReadFile("npm.go")
	if err != nil {
		t.Fatalf("read npm.go: %v", err)
	}
	text := string(src)

	const want = "sigstoreverify.DigestSHA512"
	if !strings.Contains(text, want) {
		t.Fatalf("npm.go does not name %s. npm in-toto subjects bind sha512 and ONLY sha512, so "+
			"any other algorithm makes every npm attestation fail with 'provided artifact digests "+
			"does not match digests in statement' — 1,852 rows in production, 0 successes ever.", want)
	}
	if strings.Contains(text, "sigstoreverify.DigestSHA256") {
		t.Errorf("npm.go names DigestSHA256 somewhere; npm binds sha512 only")
	}
	// And the digest it computes must be a sha512, or naming the algorithm
	// correctly just moves the mismatch.
	if !strings.Contains(text, "sha512.New()") && !strings.Contains(text, "sha512.Sum512") {
		t.Error("npm.go computes no sha512; the fallback hash path must match the algorithm it names")
	}
	if strings.Contains(text, "sha256.New()") {
		t.Error("npm.go still computes a sha256 for the artifact digest")
	}
}
