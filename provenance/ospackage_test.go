package provenance

import (
	"context"
	"strings"
	"testing"
)

// TestOSPackageRequiresSourceURL confirms the CheckWithSource dispatch
// reaches the APT/DNF/YUM checker and that they return a clear,
// non-empty error when no sourceURL is provided.
func TestOSPackageRequiresSourceURL(t *testing.T) {
	c := NewChecker(nil)
	for _, eco := range []string{"apt", "dnf", "yum"} {
		got := c.Check(context.Background(), eco, "anything", "1.0")
		if got.Status != StatusUnavailable {
			t.Errorf("%s: status = %q, want Unavailable", eco, got.Status)
		}
		if got.Ecosystem != eco {
			t.Errorf("%s: ecosystem = %q, want %q", eco, got.Ecosystem, eco)
		}
		if !strings.Contains(got.Error, "source repository URL") {
			t.Errorf("%s: error should mention sourceURL requirement, got %q", eco, got.Error)
		}
	}
}

// TestAbsentEcosystemsExplainThemselves ensures the cargo/composer/
// cocoapods stubs produce a descriptive error rather than the silent
// StatusUnavailable of the old switch.
func TestAbsentEcosystemsExplainThemselves(t *testing.T) {
	c := NewChecker(nil)
	for _, eco := range []string{"cargo", "composer", "cocoapods"} {
		got := c.Check(context.Background(), eco, "anything", "1.0")
		if got.Status != StatusUnavailable {
			t.Errorf("%s: status = %q, want Unavailable", eco, got.Status)
		}
		if got.Error == "" {
			t.Errorf("%s: Error should be populated explaining why no standard exists", eco)
		}
	}
}
