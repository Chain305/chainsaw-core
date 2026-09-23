package intelligence

// The bare-version case is the whole point of this file. It is not an edge
// case: 6,093 of 6,139 stored Go reports in production carry a bare version,
// because both Go lockfile parsers strip the leading "v". Every one of them
// built a URL the module proxy answers with 404, which is why Go had 4
// artifact scans against 6,139 packages.

import "testing"

func TestGoModuleZipPath(t *testing.T) {
	cases := []struct {
		name, pkg, ver, want string
		ok                   bool
	}{
		// The 6,093. A bare version MUST come back v-prefixed.
		{"bare version gets its v back", "rsc.io/sampler", "1.3.0",
			"rsc.io/sampler/@v/v1.3.0.zip", true},
		{"bare, multi-segment module", "cloud.google.com/go/webrisk", "1.9.6",
			"cloud.google.com/go/webrisk/@v/v1.9.6.zip", true},

		// The 46 that already worked must keep working — idempotent prefix.
		{"already v-prefixed is untouched", "rsc.io/quote", "v1.5.2",
			"rsc.io/quote/@v/v1.5.2.zip", true},
		{"+incompatible survives", "github.com/dgrijalva/jwt-go", "v3.2.0+incompatible",
			"github.com/dgrijalva/jwt-go/@v/v3.2.0+incompatible.zip", true},

		// Case-escaping: the proxy lowercases with a "!" sentinel. Missing
		// this was the second half of the same defect.
		{"uppercase in the module path", "github.com/Sirupsen/logrus", "1.0.6",
			"github.com/!sirupsen/logrus/@v/v1.0.6.zip", true},
		{"uppercase in the version", "example.com/m", "1.0.0-RC1",
			"example.com/m/@v/v1.0.0-!r!c1.zip", true},

		// Refuse rather than guess: an unusable coordinate must not spend an
		// upstream request on a guaranteed 404 against a rate-limited proxy.
		{"empty module", "", "1.0.0", "", false},
		{"empty version", "rsc.io/quote", "", "", false},
		{"not semver", "rsc.io/quote", "latest", "", false},
		{"pseudo-ish garbage", "rsc.io/quote", "not-a-version", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, ok := GoModuleZipPath(c.pkg, c.ver)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v (got path %q)", ok, c.ok, got)
			}
			if got != c.want {
				t.Errorf("path = %q, want %q", got, c.want)
			}
		})
	}
}

// TestGoModuleZipPathLeadingSlash — the old inline version trimmed a leading
// "/" off the module path, so something upstream produces one. Keep handling
// it, or this fix would regress a case the buggy code got right.
func TestGoModuleZipPathLeadingSlash(t *testing.T) {
	got, ok := GoModuleZipPath("/rsc.io/sampler", "1.3.0")
	if !ok || got != "rsc.io/sampler/@v/v1.3.0.zip" {
		t.Fatalf("GoModuleZipPath with a leading slash = %q, %v", got, ok)
	}
}
