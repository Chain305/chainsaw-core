package config

// clone.go provides the deep copy OverlayFromStoreForOrg needs.
//
// The overlay writes the settings table onto a caller-supplied base
// config. cmd/chainsaw-proxy passes the live boot config as that base
// and initRepositories passes it once PER ORG, so mutating it in place
// would leak one org's persisted settings into the next org's overlay.
// Copying is cheap (one Config, a handful of small maps/slices) and
// removes the aliasing question entirely.

// clone returns a deep copy of c. Safe on a nil receiver: a nil *Config
// clones to an empty &Config{}, which is what "no base" means to
// OverlayFromStoreForOrg.
func (c *Config) clone() *Config {
	if c == nil {
		return &Config{}
	}
	cp := *c

	cp.BlockingMode = cloneBoolPtr(c.BlockingMode)
	cp.RepositoryAnonymousAccess = cloneBoolPtr(c.RepositoryAnonymousAccess)
	cp.ClamAV.Enabled = cloneBoolPtr(c.ClamAV.Enabled)
	cp.Malware.EnableGHSA = cloneBoolPtr(c.Malware.EnableGHSA)
	cp.Coverage.Enabled = cloneBoolPtr(c.Coverage.Enabled)
	cp.Policy.EvalCacheTTLSeconds = cloneIntPtr(c.Policy.EvalCacheTTLSeconds)

	cp.DataSources.OpenSSF = cloneDataSource(c.DataSources.OpenSSF)
	cp.DataSources.TrivyDB = cloneDataSource(c.DataSources.TrivyDB)
	cp.DataSources.EPSS = cloneDataSource(c.DataSources.EPSS)
	cp.DataSources.ClamAVDB = cloneDataSource(c.DataSources.ClamAVDB)

	cp.Provenance.DisabledEcosystems = cloneStrings(c.Provenance.DisabledEcosystems)
	cp.Swift.GitHubOrgAllowList = cloneStrings(c.Swift.GitHubOrgAllowList)

	if len(c.Policies) > 0 {
		cp.Policies = append(cp.Policies[:0:0], c.Policies...)
	}
	cp.Repositories = cloneRepositoryConfigsDeep(c.Repositories)
	cp.Remotes = cloneRemoteDefaults(c.Remotes)

	if len(c.explicitKeys) > 0 {
		ek := make(map[string]bool, len(c.explicitKeys))
		for k, v := range c.explicitKeys {
			ek[k] = v
		}
		cp.explicitKeys = ek
	}
	return &cp
}

func cloneBoolPtr(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneIntPtr(p *int) *int {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	return append(make([]string, 0, len(s)), s...)
}

func cloneDataSource(ds DataSourceRuntimeConfig) DataSourceRuntimeConfig {
	cp := ds
	cp.Enabled = cloneBoolPtr(ds.Enabled)
	cp.StartupSync = cloneBoolPtr(ds.StartupSync)
	return cp
}

func cloneRemoteDefaults(m map[string]RemoteDefaults) map[string]RemoteDefaults {
	if m == nil {
		return nil
	}
	out := make(map[string]RemoteDefaults, len(m))
	for k, v := range m {
		v.Headers = cloneMap(v.Headers)
		out[k] = v
	}
	return out
}

// cloneRepositoryConfigsDeep differs from the older
// cloneRepositoryConfigs (used to seed the builtin list) in that it also
// copies the optional apt/yum sub-blocks and the AnonymousAccess
// pointer. Those are exactly the fields that used to be dropped, so the
// clone used by the overlay must not drop them again.
func cloneRepositoryConfigsDeep(src []RepositoryConfig) []RepositoryConfig {
	if src == nil {
		return nil
	}
	out := make([]RepositoryConfig, len(src))
	for i, repo := range src {
		cp := repo
		cp.Enabled = cloneBoolPtr(repo.Enabled)
		cp.AnonymousAccess = cloneBoolPtr(repo.AnonymousAccess)
		cp.Remote = cloneRemoteConfig(repo.Remote)
		if repo.APT != nil {
			apt := *repo.APT
			apt.Suites = cloneStrings(repo.APT.Suites)
			apt.Components = cloneStrings(repo.APT.Components)
			apt.Architectures = cloneStrings(repo.APT.Architectures)
			cp.APT = &apt
		}
		if repo.Yum != nil {
			yum := *repo.Yum
			cp.Yum = &yum
		}
		out[i] = cp
	}
	return out
}
