package provenance

import (
	"context"
	"testing"
)

func TestCheckUnknownEcosystemReturnsUnavailable(t *testing.T) {
	c := NewChecker(nil)
	got := c.Check(context.Background(), "bogus", "some-pkg", "1.0.0")
	if got.Status != StatusUnavailable {
		t.Fatalf("unknown ecosystem: got %q, want %q", got.Status, StatusUnavailable)
	}
	if got.Ecosystem != "bogus" {
		t.Fatalf("ecosystem field: got %q, want %q", got.Ecosystem, "bogus")
	}
}

func TestCheckEcosystemAliases(t *testing.T) {
	c := NewChecker(nil)
	// Both "pip" and "pypi" must route to the same checker. We can't hit the
	// network here, so we just assert the dispatcher finds a registered
	// checker (not StatusUnavailable) for each alias.
	for _, eco := range []string{"npm", "pip", "pypi", "NPM", "PyPI", "maven", "gradle", "rubygems", "gem"} {
		if _, ok := c.checkers[lowerForTest(eco)]; !ok {
			t.Errorf("alias %q: not registered", eco)
		}
	}
}

func TestSupportsProvenance(t *testing.T) {
	cases := map[string]bool{
		"npm":         true,
		"pip":         true,
		"pypi":        true,
		"PyPI":        true,
		"maven":       true,
		"gradle":      true,
		"rubygems":    true,
		"gem":         true,
		"go":          true,
		"gomod":       true,
		"docker":      true,
		"nuget":       true,
		"huggingface": true,
		"cargo":       false,
		"anything":    false,
	}
	for eco, want := range cases {
		if got := SupportsProvenance(eco); got != want {
			t.Errorf("SupportsProvenance(%q) = %v, want %v", eco, got, want)
		}
	}
}

func TestNewCheckerWithOfflineMode(t *testing.T) {
	c := NewChecker(nil, WithOfflineMode())
	for _, eco := range []string{"npm", "maven", "docker", "huggingface"} {
		got := c.Check(context.Background(), eco, "pkg", "1.0.0")
		if got.Status != StatusUnavailable {
			t.Errorf("offline mode %q: want StatusUnavailable, got %+v", eco, got)
		}
	}
}

func TestNewCheckerWithDisabledEcosystem(t *testing.T) {
	c := NewChecker(nil, WithDisabledEcosystems("maven", "DOCKER"))
	// Disabled ecosystems → unavailable.
	if got := c.Check(context.Background(), "maven", "org.ex:foo", "1.0.0"); got.Status != StatusUnavailable {
		t.Errorf("disabled maven: want StatusUnavailable, got %+v", got)
	}
	if got := c.Check(context.Background(), "docker", "nginx", "latest"); got.Status != StatusUnavailable {
		t.Errorf("disabled docker (case-insensitive): want StatusUnavailable, got %+v", got)
	}
	// Unlisted ecosystem still registered.
	if _, ok := c.checkers["rubygems"]; !ok {
		t.Error("rubygems should remain registered when only maven+docker are disabled")
	}
}

// lowerForTest mirrors the normalization in Checker.register.
func lowerForTest(s string) string {
	b := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		b[i] = c
	}
	return string(b)
}
