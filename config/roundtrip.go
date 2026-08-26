package config

// roundtrip.go — the completeness registry for the config round trip.
//
// Every proxy deployment is DB-backed (initDatabase is mandatory and
// fatal), so at boot the YAML is imported into the settings table and
// the config the process actually runs on is read back out of the
// database. Anything the store does not carry is therefore not a
// "YAML-only" setting — it is a setting that gets DISCARDED.
//
// That failure has happened twice. Wave AA fixed it for the `swift:`
// block by adding seven keys to LoadFromStoreForOrg's hand-written
// Config literal. The literal then fell behind the struct again, and by
// the time anyone looked, twelve more blocks were being dropped on every
// boot — including `runtime.offline`, which meant the startup log
// asserted "Offline mode active" while every subsystem it names saw
// online.
//
// Adding more entries to a hand-maintained list is the approach we KNOW
// fails, so the list is no longer maintained by hand alone: the two maps
// below are checked against reflect.TypeOf(Config{}) by
// TestConfigRoundTripCompleteness. A thirteenth block fails CI until
// someone classifies it. Same ratchet shape as
// core/policy/proxy_matrix.go and the warn-code drift test in
// core/intelligence.
//
// The map VALUE for settingsBackedFields names the durable home of the
// field, so a reader can jump straight to it: a settings key like
// "provenance.offline", or "repositories.<column>" for the columns of
// the repositories table.

// settingsBackedFields maps a Config leaf-field path (as produced by the
// reflection walker in roundtrip_test.go) to the storage that carries it
// across the YAML → settings-table → memory round trip.
var settingsBackedFields = map[string]string{
	// runtime.* — cross-cutting knobs, all with env-var twins that still
	// win at read time.
	"Runtime.Offline":                     settingRuntimeOffline,
	"Runtime.AllowInsecureTLS":            settingRuntimeAllowInsecureTLS,
	"Runtime.IntelBundlePath":             settingRuntimeIntelBundlePath,
	"Runtime.OfflineFailMode":             settingRuntimeOfflineFailMode,
	"Runtime.WebhookLegacyPerUserRouting": settingRuntimeWebhookLegacyPerUser,
	"Runtime.MalwareTestOverrides":        settingRuntimeMalwareTestOverrides,

	// server / http client / paths
	"Server.Listen":             settingServerListen,
	"Server.Admin.Username":     settingAdminUsername,
	"Server.TLS.CertFile":       settingServerTLSCertFile,
	"Server.TLS.KeyFile":        settingServerTLSKeyFile,
	"Server.TLS.MinVersion":     settingServerTLSMinVersion,
	"BlobStore.Root":            settingBlobRoot,
	"HTTPClient.TimeoutSeconds": settingHTTPTimeout,
	"HTTPClient.TLSInsecure":    settingHTTPTLSInsecure,
	"HTTPClient.MaxIdleConns":   settingHTTPMaxIdle,
	"Index.Path":                settingIndexPath,
	"Exceptions.Path":           settingExceptionsPath,
	"Exceptions.AgeDays":        settingExceptionAge,
	"GeoIP.DBPath":              settingGeoIPDBPath,

	// hooks
	"Hooks.RequestScript":              settingHookScript,
	"Hooks.TimeoutSeconds":             settingHookTimeout,
	"Hooks.Trivial.BinaryPath":         settingTrivialBinary,
	"Hooks.Trivial.DBPath":             settingTrivialDB,
	"Hooks.Trivial.TimeoutSeconds":     settingTrivialTimeout,
	"Hooks.Trivial.MaxConcurrentScans": settingTrivialMaxConcurrentScans,
	"Hooks.DockerLayer.Mode":           settingDockerLayerMode,
	"Hooks.DockerLayer.SizeCapBytes":   settingDockerLayerSizeCapBytes,
	"Hooks.DockerLayer.TimeoutSeconds": settingDockerLayerTimeoutSeconds,

	// clamav + shared data sources
	"ClamAV.Enabled":                              settingClamAVEnabled,
	"ClamAV.SocketPath":                           settingClamAVSocketPath,
	"ClamAV.TimeoutSeconds":                       settingClamAVTimeout,
	"ClamAV.MaxStreamBytes":                       settingClamAVMaxStream,
	"DataSources.OpenSSF.Enabled":                 settingDataSourceOpenSSFEnabled,
	"DataSources.OpenSSF.RefreshIntervalSeconds":  settingDataSourceOpenSSFRefresh,
	"DataSources.OpenSSF.StartupSync":             settingDataSourceOpenSSFStartup,
	"DataSources.OpenSSF.TimeoutSeconds":          settingDataSourceOpenSSFTimeout,
	"DataSources.OpenSSF.JitterPercent":           settingDataSourceOpenSSFJitter,
	"DataSources.TrivyDB.Enabled":                 settingDataSourceTrivyEnabled,
	"DataSources.TrivyDB.RefreshIntervalSeconds":  settingDataSourceTrivyRefresh,
	"DataSources.TrivyDB.StartupSync":             settingDataSourceTrivyStartup,
	"DataSources.TrivyDB.TimeoutSeconds":          settingDataSourceTrivyTimeout,
	"DataSources.TrivyDB.JitterPercent":           settingDataSourceTrivyJitter,
	"DataSources.EPSS.Enabled":                    settingDataSourceEPSSEnabled,
	"DataSources.EPSS.RefreshIntervalSeconds":     settingDataSourceEPSSRefresh,
	"DataSources.EPSS.StartupSync":                settingDataSourceEPSSStartup,
	"DataSources.EPSS.TimeoutSeconds":             settingDataSourceEPSSTimeout,
	"DataSources.EPSS.JitterPercent":              settingDataSourceEPSSJitter,
	"DataSources.ClamAVDB.Enabled":                settingDataSourceClamAVEnabled,
	"DataSources.ClamAVDB.RefreshIntervalSeconds": settingDataSourceClamAVRefresh,
	"DataSources.ClamAVDB.StartupSync":            settingDataSourceClamAVStartup,
	"DataSources.ClamAVDB.TimeoutSeconds":         settingDataSourceClamAVTimeout,
	"DataSources.ClamAVDB.JitterPercent":          settingDataSourceClamAVJitter,

	// provenance (air-gap kill-switches)
	"Provenance.Offline":            settingProvenanceOffline,
	"Provenance.DisabledEcosystems": settingProvenanceDisabledEcosystems,
	"Provenance.SwiftFullVerify":    settingProvenanceSwiftFullVerify,
	"Provenance.SwiftRegistryURL":   settingProvenanceSwiftRegistryURL,

	// optional feature blocks
	"Malware.EnableGHSA":         settingMalwareEnableGHSA,
	"SBOM.AttributionEnabled":    settingSBOMAttributionEnabled,
	"SBOM.AttributionWindowDays": settingSBOMAttributionWindowDays,
	"Correlation.Enabled":        settingCorrelationEnabled,
	"Coverage.Enabled":           settingCoverageEnabled,
	"Policy.EvalCacheTTLSeconds": settingPolicyEvalCacheTTLSeconds,

	// swift
	"Swift.GitFallbackEnabled":  settingSwiftGitFallbackEnabled,
	"Swift.IdentifierMapPath":   settingSwiftIdentifierMapPath,
	"Swift.GitCacheDir":         settingSwiftGitCacheDir,
	"Swift.GitHubConvention":    settingSwiftGitHubConvention,
	"Swift.GitHubOrgAllowList":  settingSwiftGitHubOrgAllowList,
	"Swift.TrustRootBundlePath": settingSwiftTrustRootBundlePath,
	"Swift.TrustSwiftRoot":      settingSwiftTrustSwiftRoot,

	// misc scalars
	"ReleasePolicy.MinAgeDays":  settingReleaseMinAgeDays,
	"BlockingMode":              settingBlockingMode,
	"RepositoryAnonymousAccess": settingRepositoryAllowAnonymous,

	// remotes: the whole map in one JSON row.
	"Remotes[].URL":            settingRemoteDefaults,
	"Remotes[].TimeoutSeconds": settingRemoteDefaults,
	"Remotes[].Headers":        settingRemoteDefaults,

	// repositories: columns of the repositories table, not settings kv.
	"Repositories[].Name":                     "repositories.name",
	"Repositories[].Format":                   "repositories.format",
	"Repositories[].Type":                     "repositories.type",
	"Repositories[].Enabled":                  "repositories.enabled",
	"Repositories[].AnonymousAccess":          "repositories.anonymous_access",
	"Repositories[].Remote.URL":               "repositories.remote_url",
	"Repositories[].Remote.ProxyURL":          "repositories.remote_proxy_url",
	"Repositories[].Remote.SkipTLSVerify":     "repositories.remote_skip_tls",
	"Repositories[].Remote.TimeoutSeconds":    "repositories.remote_timeout_seconds",
	"Repositories[].Remote.Headers":           "repositories.remote_headers",
	"Repositories[].Cache.NegativeTTLSeconds": "repositories.cache_negative_ttl_seconds",
	"Repositories[].ClientConfigurationGuide": "repositories.client_configuration_guide_template",
	"Repositories[].PublicBaseURL":            "repositories.public_base_url",
	"Repositories[].APT.Suites":               "repositories.format_options",
	"Repositories[].APT.Components":           "repositories.format_options",
	"Repositories[].APT.Architectures":        "repositories.format_options",
	"Repositories[].APT.Origin":               "repositories.format_options",
	"Repositories[].APT.Label":                "repositories.format_options",
	"Repositories[].APT.Codename":             "repositories.format_options",
	"Repositories[].APT.Description":          "repositories.format_options",
	"Repositories[].Yum.Origin":               "repositories.format_options",
	"Repositories[].Yum.Label":                "repositories.format_options",
	"Repositories[].Yum.Description":          "repositories.format_options",
	"Repositories[].Yum.Revision":             "repositories.format_options",
}

// ephemeralFields names the Config leaves that deliberately do NOT
// survive the settings round trip, each with the reason. Keep this list
// short and keep the reasons concrete: "we didn't get to it" is not a
// reason, it is the bug.
var ephemeralFields = map[string]string{
	// P8-28. This list is read once at boot, by backfillRepositoryGuides,
	// to hand the guide backfill replacement prose for repositories that
	// are no longer seeded. It describes rows that already exist rather
	// than creating any, so there is nothing to persist: round-tripping it
	// through settings would mint a second copy that could disagree with
	// configs/seed.yaml, which is the single source for guide prose.
	"RetiredRepositoryGuides[].Name": "retired-guide list is a boot-time input to the " +
		"guide backfill (core/pgstore/migrate_repo_guides.go), never a settings row; " +
		"configs/seed.yaml is the single source and a persisted copy could drift from it.",
	"RetiredRepositoryGuides[].Reason": "documentation for the next reader of " +
		"configs/seed.yaml; nothing reads it at runtime.",
	"RetiredRepositoryGuides[].ClientConfigurationGuide": "the replacement prose the " +
		"backfill writes INTO repositories.client_configuration_guide_template; it is " +
		"the source of that column, not a column itself.",

	"Policies": "policy documents are stored in their own table by core/policy " +
		"(NormalizePolicy + the policy store), not as settings kv rows. The YAML " +
		"`policies:` block is a first-boot seed: cmd/chainsaw-proxy captures it " +
		"before the store load and re-applies it afterwards (seedPolicies), which " +
		"is why the round trip through settings is neither needed nor wanted here " +
		"— persisting it twice would let the two copies disagree.",
}
