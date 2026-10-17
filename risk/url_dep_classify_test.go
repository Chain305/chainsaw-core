package risk

import "testing"

func TestClassifyDepURL(t *testing.T) {
	tests := []struct {
		version string
		want    DepURLKind
	}{
		// Registry (semver, tags, dist-tags)
		{"^1.2.3", DepURLRegistry},
		{"~0.5.0", DepURLRegistry},
		{"1.0.0", DepURLRegistry},
		{"latest", DepURLRegistry},
		{">=2.0.0 <3.0.0", DepURLRegistry},
		{"*", DepURLRegistry},
		{"", DepURLRegistry},

		// Known registry mirrors → DepURLRegistry (not HTTP)
		{"https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz", DepURLRegistry},
		{"https://registry.yarnpkg.com/pkg/-/pkg-1.0.0.tgz", DepURLRegistry},

		// Git URL forms
		{"git+https://github.com/org/repo.git", DepURLGit},
		{"git+ssh://git@github.com/org/repo.git", DepURLGit},
		{"git://github.com/org/repo.git", DepURLGit},
		{"git@github.com:org/repo.git", DepURLGit},

		// Git shorthands
		{"github:user/repo", DepURLGit},
		{"github:user/repo#main", DepURLGit},
		{"bitbucket:user/repo", DepURLGit},
		{"gitlab:user/repo", DepURLGit},
		{"gist:abc123", DepURLGit},

		// HTTP tarball (non-registry host)
		{"https://example.com/archive.tgz", DepURLHTTP},
		{"http://internal.corp/packages/pkg-1.0.0.tar.gz", DepURLHTTP},
		{"https://s3.amazonaws.com/bucket/pkg.tgz", DepURLHTTP},

		// Other non-registry non-git
		{"file:../local-pkg", DepURLOther},
		{"file:./relative-path", DepURLOther},
		{"npm:some-other-pkg@1.0.0", DepURLOther},
		{"workspace:*", DepURLOther},
		{"link:../sibling", DepURLOther},
	}

	for _, tt := range tests {
		got := ClassifyDepURL(tt.version)
		if got != tt.want {
			t.Errorf("ClassifyDepURL(%q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

// npm reads a bare user/repo[#ref] as a GitHub dependency (attack 31's
// owner/repo#sha form); every other ecosystem keeps ClassifyDepURL's answer.
func TestClassifyNPMDepURL(t *testing.T) {
	for spec, want := range map[string]DepURLKind{
		"tanstack/router#79ac49ee":      DepURLGit,
		"user/repo":                     DepURLGit,
		" user/repo.js#v1.2.0 ":         DepURLGit,
		"github:user/repo":              DepURLGit,
		"^1.2.3":                        DepURLRegistry,
		"latest":                        DepURLRegistry,
		"@scope/pkg":                    DepURLRegistry,
		"./local/dir":                   DepURLRegistry,
		"file:../x":                     DepURLOther,
		"dist/foo.tgz":                  DepURLRegistry,
		"vendor/pkg-1.0.0.tar.gz":       DepURLRegistry,
		"https://example.invalid/x.tgz": DepURLHTTP,
	} {
		if got := ClassifyNPMDepURL(spec); got != want {
			t.Errorf("ClassifyNPMDepURL(%q) = %v, want %v", spec, got, want)
		}
	}
	// The shared classifier must not read a Composer-style branch as git.
	if got := ClassifyDepURL("dev-feature/x"); got != DepURLRegistry {
		t.Errorf("ClassifyDepURL(dev-feature/x) = %v, want registry", got)
	}
}
