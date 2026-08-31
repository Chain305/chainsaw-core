package config

import "testing"

// TestNPMRegistryURL pins the resolution order the npm provenance probe
// depends on. The probe's answer is only ever about the registry it
// asked, so picking the wrong upstream here does not degrade a verdict —
// it makes it a statement about the wrong registry.
func TestNPMRegistryURL(t *testing.T) {
	const mirror = "https://npm.mirror.internal.example"

	cases := []struct {
		name string
		cfg  *Config
		want string
	}{
		{
			name: "nil config",
			cfg:  nil,
			want: "",
		},
		{
			name: "nothing configured",
			cfg:  &Config{},
			want: "",
		},
		{
			// The format default, used when no npm repository declares
			// its own remote.
			name: "remotes default",
			cfg: &Config{
				Remotes: map[string]RemoteDefaults{"npm": {URL: mirror}},
			},
			want: mirror,
		},
		{
			// The important case: normalize() only copies the format
			// default into an EMPTY repo remote, never the reverse, so a
			// repository-level mirror must win or it is invisible here.
			name: "repository remote beats the format default",
			cfg: &Config{
				Repositories: []RepositoryConfig{
					{Name: "npmjs", Format: "npm", Type: "proxy", Remote: RemoteConfig{URL: mirror}},
				},
				Remotes: map[string]RemoteDefaults{"npm": {URL: "https://registry.npmjs.org"}},
			},
			want: mirror,
		},
		{
			// A hosted npm repo has no upstream to attest against, and a
			// disabled one is not serving anything. Neither may shadow a
			// real proxy upstream.
			name: "hosted and disabled npm repositories are skipped",
			cfg: &Config{
				Repositories: []RepositoryConfig{
					{Name: "npm-private", Format: "npm", Type: "hosted", Remote: RemoteConfig{URL: "https://hosted.invalid"}},
					{Name: "npm-off", Format: "npm", Type: "proxy", Enabled: boolPtr(false), Remote: RemoteConfig{URL: "https://off.invalid"}},
					{Name: "npmjs", Format: "npm", Type: "proxy", Remote: RemoteConfig{URL: mirror}},
				},
			},
			want: mirror,
		},
		{
			// yarn and bun proxy npm packages but are not registered as
			// aliases of the npm provenance checker, so they must not be
			// mistaken for the npm upstream.
			name: "non-npm formats are ignored",
			cfg: &Config{
				Repositories: []RepositoryConfig{
					{Name: "yarn", Format: "yarn", Type: "proxy", Remote: RemoteConfig{URL: "https://registry.yarnpkg.com"}},
				},
				Remotes: map[string]RemoteDefaults{"npm": {URL: mirror}},
			},
			want: mirror,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.NPMRegistryURL(); got != tc.want {
				t.Fatalf("NPMRegistryURL() = %q, want %q", got, tc.want)
			}
		})
	}
}
