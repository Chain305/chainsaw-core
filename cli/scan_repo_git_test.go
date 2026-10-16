package cli

import (
	"strings"
	"testing"
)

func scanRepoRules(findings []scanFinding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		out[f.Rule]++
	}
	return out
}

// TestInspectFileFlagsGitDependencies: a git dependency is fetched straight
// from the repository, never through the Chainsaw proxy — the same bypass
// class as an index-url override.
func TestInspectFileFlagsGitDependencies(t *testing.T) {
	cases := []struct {
		base, text, rule string
		want             int
	}{
		{"requirements.txt", strings.Join([]string{
			"requests==2.31.0",
			"-e git+https://github.com/victim/alpha#egg=alpha",
			"beta @ git+https://github.com/victim/beta@v1.0",
			"git+ssh://git@github.com/victim/gamma.git",
			"-e .",
			"./libs/local",
			"# git+https://github.com/commented/out",
		}, "\n"), "requirements-git-dependency", 3},
		{"pyproject.toml", "[project]\ndependencies = [\n  \"requests>=2\",\n  \"beta @ git+https://github.com/victim/beta\",\n]\n", "pyproject-git-dependency", 1},
		{"pyproject.toml", "[tool.poetry.dependencies]\nalpha = { git = \"https://github.com/victim/alpha.git\", rev = \"main\" }\n", "pyproject-git-dependency", 1},
		{"pyproject.toml", "[tool.poetry.dependencies]\nrequests = \"^2.31\"\n", "pyproject-git-dependency", 0},
		{"package.json", `{"dependencies":{"lodash":"^4.17.21","alpha":"github:victim/alpha","local":"file:../local"},"devDependencies":{"beta":"git+https://github.com/victim/beta.git","gamma":"victim/gamma"}}`, "package-json-git-dependency", 3},
		{"package.json", `{"dependencies":{"lodash":"^4.17.21","tar":"https://cdn.example.com/x-1.0.0.tgz","alias":"npm:lodash@4"}}`, "package-json-git-dependency", 0},
		{"package.json", `not json`, "package-json-git-dependency", 0},
	}
	for _, tc := range cases {
		got := inspectFile(tc.base, tc.base, tc.text)
		if n := scanRepoRules(got)[tc.rule]; n != tc.want {
			t.Errorf("%s: %s findings = %d, want %d: %+v", tc.base, tc.rule, n, tc.want, got)
		}
		for _, f := range got {
			if f.Rule == tc.rule && !strings.Contains(f.Detail, "proxy") {
				t.Errorf("%s: detail must say why it matters and what to do: %q", tc.base, f.Detail)
			}
		}
	}
	if !isScanRepoCandidate("package.json") {
		t.Error("package.json must be read by scan-repo now that a rule applies to it")
	}
}
