package config

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/tenancy"
)

const (
	settingServerListen             = "server.listen"
	settingServerTLSCertFile        = "server.tls.cert_file"
	settingServerTLSKeyFile         = "server.tls.key_file"
	settingServerTLSMinVersion      = "server.tls.min_version"
	settingAdminUsername            = "admin.username"
	settingAdminPassword            = "admin.password"
	settingAdminPasswordHash        = "admin.password_hash"
	settingBlobRoot                 = "blob.root"
	settingHTTPTimeout              = "http.timeout_seconds"
	settingHTTPTLSInsecure          = "http.tls_insecure"
	settingHTTPMaxIdle              = "http.max_idle_conns"
	settingHookScript               = "hooks.request_script"
	settingHookTimeout              = "hooks.timeout_seconds"
	settingTrivialBinary            = "hooks.trivial.binary_path"
	settingTrivialDB                = "hooks.trivial.db_path"
	settingTrivialTimeout           = "hooks.trivial.timeout_seconds"
	settingClamAVEnabled            = "clamav.enabled"
	settingClamAVSocketPath         = "clamav.socket_path"
	settingClamAVTimeout            = "clamav.timeout_seconds"
	settingClamAVMaxStream          = "clamav.max_stream_bytes"
	settingDataSourceOpenSSFEnabled = "data_sources.openssf.enabled"
	settingDataSourceOpenSSFRefresh = "data_sources.openssf.refresh_interval_seconds"
	settingDataSourceOpenSSFStartup = "data_sources.openssf.startup_sync"
	settingDataSourceOpenSSFTimeout = "data_sources.openssf.timeout_seconds"
	settingDataSourceOpenSSFJitter  = "data_sources.openssf.jitter_percent"
	settingDataSourceTrivyEnabled   = "data_sources.trivy_db.enabled"
	settingDataSourceTrivyRefresh   = "data_sources.trivy_db.refresh_interval_seconds"
	settingDataSourceTrivyStartup   = "data_sources.trivy_db.startup_sync"
	settingDataSourceTrivyTimeout   = "data_sources.trivy_db.timeout_seconds"
	settingDataSourceTrivyJitter    = "data_sources.trivy_db.jitter_percent"
	settingDataSourceEPSSEnabled    = "data_sources.epss.enabled"
	settingDataSourceEPSSRefresh    = "data_sources.epss.refresh_interval_seconds"
	settingDataSourceEPSSStartup    = "data_sources.epss.startup_sync"
	settingDataSourceEPSSTimeout    = "data_sources.epss.timeout_seconds"
	settingDataSourceEPSSJitter     = "data_sources.epss.jitter_percent"
	settingDataSourceClamAVEnabled  = "data_sources.clamav_db.enabled"
	settingDataSourceClamAVRefresh  = "data_sources.clamav_db.refresh_interval_seconds"
	settingDataSourceClamAVStartup  = "data_sources.clamav_db.startup_sync"
	settingDataSourceClamAVTimeout  = "data_sources.clamav_db.timeout_seconds"
	settingDataSourceClamAVJitter   = "data_sources.clamav_db.jitter_percent"
	settingBlockingMode             = "blocking.mode"
	settingRepositoryAllowAnonymous = "repository.allow_anonymous"
	settingReleaseMinAgeDays        = "release.min_age_days"
	settingIndexPath                = "index.path"
	settingExceptionsPath           = "exceptions.path"
	settingExceptionAge             = "exception.age"
	settingGeoIPDBPath              = "geoip.db_path"
	// settingBlockContactEmail is the explicit per-org override used in
	// block responses. When empty the server falls back to the org owner's
	// email and then to a generic "your organization administrator" string.
	// This closes C5 — the original hardcoded personal email was removed in
	// server.go alone and left five other surfaces (README, scripts, docs)
	// leaking; a configurable per-org setting plus a generic fallback is the
	// durable fix.
	settingBlockContactEmail = "block.contact_email"
	// settingYAMLImportPath / settingYAMLImportedAt record the absolute
	// path of the most recently imported YAML config file and the RFC3339
	// timestamp at which the import happened. They power the P1.4 startup
	// warning that catches operators who edit a YAML file in-place
	// expecting the changes to take effect on next boot — they don't,
	// because the YAML is imported into Postgres on first boot and the
	// DB row is authoritative thereafter (see README "Configuration
	// precedence"). When the on-disk mtime exceeds the recorded import
	// time we emit a clearly worded warning so the silent footgun stops
	// being silent.
	settingYAMLImportPath = "yaml.import_path"
	settingYAMLImportedAt = "yaml.imported_at"
	// Swift settings (Wave AA): every field of SwiftConfig persisted as
	// a settings kv row so the YAML→DB→memory round-trip preserves the
	// value. Before this, only the YAML-derived `cfg.Swift` existed; the
	// DB-loaded copy that main.go reassigns at boot zeroed Swift back to
	// defaults, which made `git_fallback_enabled: true` unreachable in
	// any DB-backed deployment. See BUG_REPORT_swift_not_resolvable.md.
	settingSwiftGitFallbackEnabled  = "swift.git_fallback_enabled"
	settingSwiftIdentifierMapPath   = "swift.identifier_map_path"
	settingSwiftGitCacheDir         = "swift.git_cache_dir"
	settingSwiftGitHubConvention    = "swift.github_convention"
	settingSwiftGitHubOrgAllowList  = "swift.github_org_allowlist"
	settingSwiftTrustRootBundlePath = "swift.trust_root_bundle_path"
	settingSwiftTrustSwiftRoot      = "swift.trust_swift_root"
	// The keys below close the twelve YAML blocks that Wave AA's Swift
	// fix did not cover. Every one of them was declared in Config,
	// accepted by the YAML parser, honoured by whatever ran before
	// main.go swapped cfg for the store-loaded copy — and then zeroed,
	// because LoadFromStoreForOrg rebuilt Config from an explicit key
	// list and anything absent from that list was re-defaulted.
	//
	// The completeness ratchet in roundtrip.go is what keeps this list
	// from falling behind Config again; adding a field without a key
	// here (or an ephemeralFields entry) fails CI.
	settingRuntimeOffline               = "runtime.offline"
	settingRuntimeAllowInsecureTLS      = "runtime.allow_insecure_tls"
	settingRuntimeIntelBundlePath       = "runtime.intel_bundle_path"
	settingRuntimeOfflineFailMode       = "runtime.offline_fail_mode"
	settingRuntimeWebhookLegacyPerUser  = "runtime.webhook_legacy_peruser_routing"
	settingRuntimeMalwareTestOverrides  = "runtime.malware_test_overrides"
	settingProvenanceOffline            = "provenance.offline"
	settingProvenanceDisabledEcosystems = "provenance.disabled_ecosystems"
	settingProvenanceSwiftFullVerify    = "provenance.swift_full_verify"
	settingProvenanceSwiftRegistryURL   = "provenance.swift_registry_url"
	settingMalwareEnableGHSA            = "malware.enable_ghsa"
	settingSBOMAttributionEnabled       = "sbom.attribution_enabled"
	settingSBOMAttributionWindowDays    = "sbom.attribution_window_days"
	settingCorrelationEnabled           = "correlation.enabled"
	settingCoverageEnabled              = "coverage.enabled"
	settingPolicyEvalCacheTTLSeconds    = "policy.eval_cache_ttl_seconds"
	settingDockerLayerMode              = "hooks.docker_layer.mode"
	settingDockerLayerSizeCapBytes      = "hooks.docker_layer.size_cap_bytes"
	settingDockerLayerTimeoutSeconds    = "hooks.docker_layer.timeout_seconds"
	settingTrivialMaxConcurrentScans    = "hooks.trivial.max_concurrent_scans"
	// settingRemoteDefaults carries the whole `remotes:` map as one JSON
	// row. Per-format keys would multiply with every new ecosystem and
	// the map is small (17 entries, ~1 KB) and always fully populated by
	// applyDefaults, so a single blob is both lossless and stable.
	settingRemoteDefaults = "remotes"
)

// RepositoryUpdate captures mutable fields exposed via the UI.
type RepositoryUpdate struct {
	Enabled                 *bool
	AnonymousAccess         *bool
	RemoteURL               string
	CacheNegativeTTLSeconds *int
}

// LoadFromStoreForOrg hydrates a Config for an org purely from the
// database store. The returned boolean indicates whether any
// repositories already existed in the database.
//
// This is the "no base" entry point, for callers that want the store's
// own view of a setting and nothing else — the per-org readers in
// internal/server (clamAVConfigForOrg, dataSourceConfigForOrg, the
// runtime settings API). Boot uses OverlayFromStoreForOrg instead so
// YAML-only blocks are not zeroed; see that function for the precedence
// rule.
func LoadFromStoreForOrg(store *pgstore.Store, orgID string) (*Config, bool, error) {
	return OverlayFromStoreForOrg(store, orgID, nil)
}

// OverlayFromStoreForOrg layers the settings the database owns on top of
// base and returns the merged config. base is never mutated; a nil base
// means "start from the zero Config", which reproduces the historical
// load-from-scratch behaviour exactly.
//
// PRECEDENCE (highest first) — implemented here, documented in
// docs/CONFIG_REFERENCE.md:
//
//	env var > explicit CLI flag > settings table > YAML > built-in default
//
// The settings table beats YAML because that is where the admin UI and
// the runtime settings API write: an operator who toggles blocking mode
// in the dashboard must not have it reverted by the next restart. But
// the table only wins for keys it actually HOLDS. A key with no row is
// a key the store does not own yet, and base's value stands.
//
// That single distinction is the fix. Before it, this function built a
// Config literal naming every key it knew and left everything else at
// the Go zero value, so twelve YAML blocks — runtime.*, provenance.*,
// coverage, correlation, policy.eval_cache_ttl_seconds, remotes.*,
// repositories[].apt/yum, malware, sbom, hooks.docker_layer,
// hooks.trivial.max_concurrent_scans — were silently discarded on every
// boot of every DB-backed deployment (which is all of them: initDatabase
// is mandatory and fatal). Wave AA patched the same hole for Swift by
// adding keys to the literal; the hole reopened because nothing checked
// the list against the struct. roundtrip.go now does.
//
// Env vars and CLI flags sit above the store because they are stated by
// the operator on THIS boot. cmd/chainsaw-proxy re-applies the flag
// overrides after this call so their precedence does not depend on
// whether the settings table happened to carry the key.
func OverlayFromStoreForOrg(store *pgstore.Store, orgID string, base *Config) (*Config, bool, error) {
	if store == nil {
		return nil, false, errors.New("database store is required")
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	settings, err := fetchSettings(store.DB(), orgID)
	if err != nil {
		return nil, false, err
	}
	repos, hasRepos, err := fetchRepositories(store.DB(), orgID)
	if err != nil {
		return nil, false, err
	}

	cfg := base.clone()
	applySettingsOverlay(cfg, settings)
	if hasRepos {
		// Repository rows are wholly store-owned: every field of
		// RepositoryConfig has a column, including the apt/yum metadata
		// blocks (format_options). So a populated table replaces base's
		// list rather than merging into it.
		cfg.Repositories = repos
	}
	cfg.applyDefaults("")
	return cfg, hasRepos, nil
}

// OverlayFromStore is OverlayFromStoreForOrg for the default org.
func OverlayFromStore(store *pgstore.Store, base *Config) (*Config, bool, error) {
	return OverlayFromStoreForOrg(store, tenancy.DefaultOrgID, base)
}

// applySettingsOverlay writes every settings row the store holds onto
// cfg. Absent rows leave cfg alone — see OverlayFromStoreForOrg.
func applySettingsOverlay(cfg *Config, settings settingMap) {
	// runtime.* — the air-gap umbrella flag and its neighbours. Dropping
	// runtime.offline was the worst of the twelve: the boot log asserted
	// "Offline mode active" while StartDataSources, Billy, auth_cli and
	// the trivy-db updater all saw online, so only CHAINSAW_OFFLINE=1
	// ever truly gated anything.
	settings.overlayBool(settingRuntimeOffline, &cfg.Runtime.Offline)
	settings.overlayBool(settingRuntimeAllowInsecureTLS, &cfg.Runtime.AllowInsecureTLS)
	settings.overlayString(settingRuntimeIntelBundlePath, &cfg.Runtime.IntelBundlePath)
	settings.overlayString(settingRuntimeOfflineFailMode, &cfg.Runtime.OfflineFailMode)
	settings.overlayBool(settingRuntimeWebhookLegacyPerUser, &cfg.Runtime.WebhookLegacyPerUserRouting)
	settings.overlayString(settingRuntimeMalwareTestOverrides, &cfg.Runtime.MalwareTestOverrides)

	// server / http client / paths
	settings.overlayString(settingServerListen, &cfg.Server.Listen)
	settings.overlayString(settingAdminUsername, &cfg.Server.Admin.Username)
	settings.overlayString(settingServerTLSCertFile, &cfg.Server.TLS.CertFile)
	settings.overlayString(settingServerTLSKeyFile, &cfg.Server.TLS.KeyFile)
	settings.overlayString(settingServerTLSMinVersion, &cfg.Server.TLS.MinVersion)
	settings.overlayString(settingBlobRoot, &cfg.BlobStore.Root)
	settings.overlayInt(settingHTTPTimeout, &cfg.HTTPClient.TimeoutSeconds)
	settings.overlayBool(settingHTTPTLSInsecure, &cfg.HTTPClient.TLSInsecure)
	settings.overlayInt(settingHTTPMaxIdle, &cfg.HTTPClient.MaxIdleConns)
	settings.overlayString(settingIndexPath, &cfg.Index.Path)
	settings.overlayString(settingExceptionsPath, &cfg.Exceptions.Path)
	settings.overlayInt(settingExceptionAge, &cfg.Exceptions.AgeDays)
	settings.overlayString(settingGeoIPDBPath, &cfg.GeoIP.DBPath)

	// hooks
	settings.overlayString(settingHookScript, &cfg.Hooks.RequestScript)
	settings.overlayInt(settingHookTimeout, &cfg.Hooks.TimeoutSeconds)
	settings.overlayString(settingTrivialBinary, &cfg.Hooks.Trivial.BinaryPath)
	settings.overlayString(settingTrivialDB, &cfg.Hooks.Trivial.DBPath)
	settings.overlayInt(settingTrivialTimeout, &cfg.Hooks.Trivial.TimeoutSeconds)
	settings.overlayInt(settingTrivialMaxConcurrentScans, &cfg.Hooks.Trivial.MaxConcurrentScans)
	settings.overlayString(settingDockerLayerMode, &cfg.Hooks.DockerLayer.Mode)
	settings.overlayInt64(settingDockerLayerSizeCapBytes, &cfg.Hooks.DockerLayer.SizeCapBytes)
	settings.overlayInt(settingDockerLayerTimeoutSeconds, &cfg.Hooks.DockerLayer.TimeoutSeconds)

	// clamav + shared data sources
	settings.overlayBoolPtr(settingClamAVEnabled, &cfg.ClamAV.Enabled)
	settings.overlayString(settingClamAVSocketPath, &cfg.ClamAV.SocketPath)
	settings.overlayInt(settingClamAVTimeout, &cfg.ClamAV.TimeoutSeconds)
	settings.overlayInt64(settingClamAVMaxStream, &cfg.ClamAV.MaxStreamBytes)
	overlayDataSource(settings, openSSFKeys, &cfg.DataSources.OpenSSF)
	overlayDataSource(settings, trivyKeys, &cfg.DataSources.TrivyDB)
	overlayDataSource(settings, epssKeys, &cfg.DataSources.EPSS)
	overlayDataSource(settings, clamAVDBKeys, &cfg.DataSources.ClamAVDB)

	// provenance — air-gapped deployments set these to stop the proxy
	// dialling keys.openpgp.org, sum.golang.org, the Sigstore TUF CDN
	// and Docker Hub. Zeroing them kept every one of those calls alive.
	settings.overlayBool(settingProvenanceOffline, &cfg.Provenance.Offline)
	settings.overlayCommaList(settingProvenanceDisabledEcosystems, &cfg.Provenance.DisabledEcosystems)
	settings.overlayBool(settingProvenanceSwiftFullVerify, &cfg.Provenance.SwiftFullVerify)
	settings.overlayString(settingProvenanceSwiftRegistryURL, &cfg.Provenance.SwiftRegistryURL)

	// optional feature blocks
	settings.overlayBoolPtr(settingMalwareEnableGHSA, &cfg.Malware.EnableGHSA)
	settings.overlayBool(settingSBOMAttributionEnabled, &cfg.SBOM.AttributionEnabled)
	settings.overlayInt(settingSBOMAttributionWindowDays, &cfg.SBOM.AttributionWindowDays)
	settings.overlayBool(settingCorrelationEnabled, &cfg.Correlation.Enabled)
	settings.overlayBoolPtr(settingCoverageEnabled, &cfg.Coverage.Enabled)
	settings.overlayIntPtr(settingPolicyEvalCacheTTLSeconds, &cfg.Policy.EvalCacheTTLSeconds)

	// swift — Wave AA/AF semantics preserved exactly. These two knobs
	// carry DB-backed defaults that differ from the Go zero value, so an
	// ABSENT row resolves to the documented default rather than to base:
	//
	// GitFallbackEnabled = "clone a URL the operator explicitly supplied"
	// (via swift.identifier_map_path). Defaults TRUE; turning it off
	// disables Swift resolution entirely.
	//
	// GitHubConvention = "GUESS a URL from a package name"
	// (`acme.utils` → github.com/acme/utils). Defaults FALSE, because
	// nothing binds an SPM identifier to a repository and whoever
	// registers the org `acme` on GitHub would get their code served as
	// the legitimate package — by the security proxy itself. Enabling it
	// requires a non-empty swift.github_org_allowlist; boot fails loudly
	// otherwise (SwiftConfig.ValidateForRuntime).
	//
	// They are DIFFERENT risks and deliberately do NOT share a default.
	// Do not "helpfully" align them.
	cfg.Swift.GitFallbackEnabled = settings.getBoolDefault(settingSwiftGitFallbackEnabled, true)
	cfg.Swift.GitHubConvention = settings.getBoolDefault(settingSwiftGitHubConvention, false)
	settings.overlayString(settingSwiftIdentifierMapPath, &cfg.Swift.IdentifierMapPath)
	settings.overlayString(settingSwiftGitCacheDir, &cfg.Swift.GitCacheDir)
	settings.overlayCommaList(settingSwiftGitHubOrgAllowList, &cfg.Swift.GitHubOrgAllowList)
	settings.overlayString(settingSwiftTrustRootBundlePath, &cfg.Swift.TrustRootBundlePath)
	settings.overlayBool(settingSwiftTrustSwiftRoot, &cfg.Swift.TrustSwiftRoot)

	// misc
	settings.overlayInt(settingReleaseMinAgeDays, &cfg.ReleasePolicy.MinAgeDays)
	settings.overlayBoolPtr(settingBlockingMode, &cfg.BlockingMode)
	settings.overlayBoolPtr(settingRepositoryAllowAnonymous, &cfg.RepositoryAnonymousAccess)
	settings.overlayRemoteDefaults(settingRemoteDefaults, &cfg.Remotes)
}

func overlayDataSource(settings settingMap, keys dataSourceKeys, ds *DataSourceRuntimeConfig) {
	settings.overlayBoolPtr(keys.enabled, &ds.Enabled)
	settings.overlayInt(keys.refresh, &ds.RefreshIntervalSeconds)
	settings.overlayBoolPtr(keys.startupSync, &ds.StartupSync)
	settings.overlayInt(keys.timeout, &ds.TimeoutSeconds)
	settings.overlayInt(keys.jitter, &ds.JitterPercent)
}

// LoadFromStore hydrates a Config from the database store for the default org. The returned
// boolean indicates whether any repositories already existed in the database.
func LoadFromStore(store *pgstore.Store) (*Config, bool, error) {
	return LoadFromStoreForOrg(store, tenancy.DefaultOrgID)
}

// settingSetter persists a single (key, value) pair inside an active
// transaction. The value is trimmed before insertion.
type settingSetter func(key, value string) error

// dataSourceKeys captures the per-source setting keys so the four
// DataSource structs can share a single save helper.
type dataSourceKeys struct {
	enabled     string
	refresh     string
	startupSync string
	timeout     string
	jitter      string
}

var (
	openSSFKeys = dataSourceKeys{
		enabled:     settingDataSourceOpenSSFEnabled,
		refresh:     settingDataSourceOpenSSFRefresh,
		startupSync: settingDataSourceOpenSSFStartup,
		timeout:     settingDataSourceOpenSSFTimeout,
		jitter:      settingDataSourceOpenSSFJitter,
	}
	trivyKeys = dataSourceKeys{
		enabled:     settingDataSourceTrivyEnabled,
		refresh:     settingDataSourceTrivyRefresh,
		startupSync: settingDataSourceTrivyStartup,
		timeout:     settingDataSourceTrivyTimeout,
		jitter:      settingDataSourceTrivyJitter,
	}
	epssKeys = dataSourceKeys{
		enabled:     settingDataSourceEPSSEnabled,
		refresh:     settingDataSourceEPSSRefresh,
		startupSync: settingDataSourceEPSSStartup,
		timeout:     settingDataSourceEPSSTimeout,
		jitter:      settingDataSourceEPSSJitter,
	}
	clamAVDBKeys = dataSourceKeys{
		enabled:     settingDataSourceClamAVEnabled,
		refresh:     settingDataSourceClamAVRefresh,
		startupSync: settingDataSourceClamAVStartup,
		timeout:     settingDataSourceClamAVTimeout,
		jitter:      settingDataSourceClamAVJitter,
	}
)

// captureExplicitRuntimeKeys records which runtime-managed settings the
// YAML declared, by inspecting the nilness of their pointer fields. MUST be
// called right after YAML decode and BEFORE applyDefaults (which fills the
// pointers, erasing the omitted-vs-set distinction). Setting-key → declared.
func (c *Config) captureExplicitRuntimeKeys() {
	ek := map[string]bool{
		settingClamAVEnabled:            c.ClamAV.Enabled != nil,
		settingBlockingMode:             c.BlockingMode != nil,
		settingRepositoryAllowAnonymous: c.RepositoryAnonymousAccess != nil,
	}
	dsRefs := []struct {
		keys dataSourceKeys
		ds   DataSourceRuntimeConfig
	}{
		{openSSFKeys, c.DataSources.OpenSSF},
		{trivyKeys, c.DataSources.TrivyDB},
		{epssKeys, c.DataSources.EPSS},
		{clamAVDBKeys, c.DataSources.ClamAVDB},
	}
	for _, r := range dsRefs {
		ek[r.keys.enabled] = r.ds.Enabled != nil
		ek[r.keys.startupSync] = r.ds.StartupSync != nil
	}
	c.explicitKeys = ek
}

// SaveToStoreForOrg persists the supplied configuration into the database for the provided org.
// When replaceRepos is true, repository rows are replaced with the provided list.
func SaveToStoreForOrg(store *pgstore.Store, cfg *Config, orgID string, replaceRepos bool) error {
	if store == nil || cfg == nil {
		return errors.New("store and config required")
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	return store.WithTx(context.Background(), func(tx *sql.Tx) error {
		set := func(key, value string) error {
			value = strings.TrimSpace(value)
			_, err := tx.Exec(`INSERT INTO settings(key,value,org_id) VALUES(?,?,?)
				ON CONFLICT(org_id, key) DO UPDATE SET value=excluded.value`, key, value, orgID)
			return err
		}
		// setIfAbsent seeds a value only when no row exists yet — it never
		// overwrites. Used for runtime-managed keys the YAML did not declare,
		// so a boot-time re-import can't wipe a UI/API-set value.
		setIfAbsent := func(key, value string) error {
			value = strings.TrimSpace(value)
			_, err := tx.Exec(`INSERT INTO settings(key,value,org_id) VALUES(?,?,?)
				ON CONFLICT(org_id, key) DO NOTHING`, key, value, orgID)
			return err
		}
		// putRuntime overwrites when the operator declared the key in YAML
		// (YAML stays authoritative for what it sets), else seeds-if-absent.
		putRuntime := func(key, value string) error {
			if cfg.explicitKeys[key] {
				return set(key, value)
			}
			return setIfAbsent(key, value)
		}
		if err := saveServerSettings(set, cfg); err != nil {
			return err
		}
		if err := saveHookSettings(set, cfg); err != nil {
			return err
		}
		if err := saveClamAVSettings(set, putRuntime, cfg); err != nil {
			return err
		}
		if err := saveAllDataSourceSettings(set, putRuntime, cfg); err != nil {
			return err
		}
		if err := saveSwiftSettings(set, cfg); err != nil {
			return err
		}
		if err := saveRuntimeSettings(set, cfg); err != nil {
			return err
		}
		if err := saveProvenanceSettings(set, cfg); err != nil {
			return err
		}
		if err := saveFeatureSettings(set, cfg); err != nil {
			return err
		}
		if err := saveMiscSettings(set, putRuntime, cfg); err != nil {
			return err
		}
		return saveRepositoriesTx(tx, orgID, cfg.Repositories, replaceRepos)
	})
}

// saveSwiftSettings persists the per-org Swift block. Wave AA bug fix:
// before this, SwiftConfig was YAML-only — SaveToStore dropped it
// silently and LoadFromStore returned the zero value, which made
// `cfg.Swift.GitFallbackEnabled` permanently false in any DB-backed
// deployment. Every field is round-tripped so operators can configure
// the git-translation fallback (and the rest) from YAML at first boot
// or via a future settings API.
func saveSwiftSettings(set settingSetter, cfg *Config) error {
	if err := set(settingSwiftGitFallbackEnabled, boolString(cfg.Swift.GitFallbackEnabled)); err != nil {
		return err
	}
	if err := set(settingSwiftIdentifierMapPath, cfg.Swift.IdentifierMapPath); err != nil {
		return err
	}
	if err := set(settingSwiftGitCacheDir, cfg.Swift.GitCacheDir); err != nil {
		return err
	}
	if err := set(settingSwiftGitHubConvention, boolString(cfg.Swift.GitHubConvention)); err != nil {
		return err
	}
	if err := set(settingSwiftGitHubOrgAllowList, joinCommaList(cfg.Swift.GitHubOrgAllowList)); err != nil {
		return err
	}
	if err := set(settingSwiftTrustRootBundlePath, cfg.Swift.TrustRootBundlePath); err != nil {
		return err
	}
	return set(settingSwiftTrustSwiftRoot, boolString(cfg.Swift.TrustSwiftRoot))
}

// saveRuntimeSettings persists the `runtime:` block. Every field here
// has an env-var twin that still wins at read time (see offline.go) —
// what changes is that the YAML value now survives the DB round trip
// instead of being zeroed, so `runtime.offline: true` gates the same
// subsystems the boot log claims it gates.
//
// These keys use plain `set` rather than putRuntime because nothing but
// the YAML importer writes them: there is no admin-UI surface for the
// runtime block, so there is no UI value to protect from a re-import.
func saveRuntimeSettings(set settingSetter, cfg *Config) error {
	if err := set(settingRuntimeOffline, boolString(cfg.Runtime.Offline)); err != nil {
		return err
	}
	if err := set(settingRuntimeAllowInsecureTLS, boolString(cfg.Runtime.AllowInsecureTLS)); err != nil {
		return err
	}
	if err := set(settingRuntimeIntelBundlePath, cfg.Runtime.IntelBundlePath); err != nil {
		return err
	}
	if err := set(settingRuntimeOfflineFailMode, cfg.Runtime.OfflineFailMode); err != nil {
		return err
	}
	if err := set(settingRuntimeWebhookLegacyPerUser, boolString(cfg.Runtime.WebhookLegacyPerUserRouting)); err != nil {
		return err
	}
	return set(settingRuntimeMalwareTestOverrides, cfg.Runtime.MalwareTestOverrides)
}

// saveProvenanceSettings persists the `provenance:` kill-switches. These
// are the air-gap knobs: with them zeroed, a deployment that had
// declared `provenance.offline: true` kept dialling keys.openpgp.org,
// sum.golang.org, the Sigstore TUF CDN and Docker Hub, and
// swift_full_verify never engaged SE-0391 CMS verification.
func saveProvenanceSettings(set settingSetter, cfg *Config) error {
	if err := set(settingProvenanceOffline, boolString(cfg.Provenance.Offline)); err != nil {
		return err
	}
	if err := set(settingProvenanceDisabledEcosystems, joinCommaList(cfg.Provenance.DisabledEcosystems)); err != nil {
		return err
	}
	if err := set(settingProvenanceSwiftFullVerify, boolString(cfg.Provenance.SwiftFullVerify)); err != nil {
		return err
	}
	return set(settingProvenanceSwiftRegistryURL, cfg.Provenance.SwiftRegistryURL)
}

// saveFeatureSettings persists the optional feature blocks: malware,
// sbom, correlation, coverage, the policy evaluation cache, the
// docker-layer hook, and the per-format remote defaults.
//
// Pointer-valued knobs are written only when non-nil. An absent row is
// meaningful for them — it means "operator never said", which the load
// side resolves to the documented default (coverage on, GHSA on, 60s
// policy cache). Writing a materialised default instead would make a
// later change to that default unreachable for existing deployments.
func saveFeatureSettings(set settingSetter, cfg *Config) error {
	if cfg.Malware.EnableGHSA != nil {
		if err := set(settingMalwareEnableGHSA, boolString(*cfg.Malware.EnableGHSA)); err != nil {
			return err
		}
	}
	if err := set(settingSBOMAttributionEnabled, boolString(cfg.SBOM.AttributionEnabled)); err != nil {
		return err
	}
	if err := set(settingSBOMAttributionWindowDays, strconv.Itoa(cfg.SBOM.AttributionWindowDays)); err != nil {
		return err
	}
	// correlation.enabled is the ONLY surface internal/deploycorr has —
	// no env var, no admin API — so dropping it made the feature
	// impossible to turn on at all.
	if err := set(settingCorrelationEnabled, boolString(cfg.Correlation.Enabled)); err != nil {
		return err
	}
	if cfg.Coverage.Enabled != nil {
		if err := set(settingCoverageEnabled, boolString(*cfg.Coverage.Enabled)); err != nil {
			return err
		}
	}
	if cfg.Policy.EvalCacheTTLSeconds != nil {
		if err := set(settingPolicyEvalCacheTTLSeconds, strconv.Itoa(*cfg.Policy.EvalCacheTTLSeconds)); err != nil {
			return err
		}
	}
	if err := set(settingDockerLayerMode, cfg.Hooks.DockerLayer.Mode); err != nil {
		return err
	}
	if err := set(settingDockerLayerSizeCapBytes, strconv.FormatInt(cfg.Hooks.DockerLayer.SizeCapBytes, 10)); err != nil {
		return err
	}
	if err := set(settingDockerLayerTimeoutSeconds, strconv.Itoa(cfg.Hooks.DockerLayer.TimeoutSeconds)); err != nil {
		return err
	}
	if err := set(settingTrivialMaxConcurrentScans, strconv.Itoa(cfg.Hooks.Trivial.MaxConcurrentScans)); err != nil {
		return err
	}
	remotes := ""
	if len(cfg.Remotes) > 0 {
		encoded, err := json.Marshal(cfg.Remotes)
		if err != nil {
			return fmt.Errorf("encode remotes: %w", err)
		}
		remotes = string(encoded)
	}
	return set(settingRemoteDefaults, remotes)
}

// saveServerSettings persists server, HTTP-client, blob, index,
// exceptions, and geoip settings.
func saveServerSettings(set settingSetter, cfg *Config) error {
	if err := set(settingServerListen, cfg.Server.Listen); err != nil {
		return err
	}
	if err := set(settingServerTLSCertFile, cfg.Server.TLS.CertFile); err != nil {
		return err
	}
	if err := set(settingServerTLSKeyFile, cfg.Server.TLS.KeyFile); err != nil {
		return err
	}
	if err := set(settingServerTLSMinVersion, cfg.Server.TLS.MinVersion); err != nil {
		return err
	}
	if err := set(settingAdminUsername, cfg.Server.Admin.Username); err != nil {
		return err
	}
	if err := set(settingBlobRoot, cfg.BlobStore.Root); err != nil {
		return err
	}
	if err := set(settingHTTPTimeout, strconv.Itoa(cfg.HTTPClient.TimeoutSeconds)); err != nil {
		return err
	}
	if err := set(settingHTTPTLSInsecure, boolString(cfg.HTTPClient.TLSInsecure)); err != nil {
		return err
	}
	if err := set(settingHTTPMaxIdle, strconv.Itoa(cfg.HTTPClient.MaxIdleConns)); err != nil {
		return err
	}
	if err := set(settingIndexPath, cfg.Index.Path); err != nil {
		return err
	}
	if err := set(settingExceptionsPath, cfg.Exceptions.Path); err != nil {
		return err
	}
	return set(settingGeoIPDBPath, cfg.GeoIP.DBPath)
}

// saveHookSettings persists request-hook and trivial-hook settings.
func saveHookSettings(set settingSetter, cfg *Config) error {
	if err := set(settingHookScript, cfg.Hooks.RequestScript); err != nil {
		return err
	}
	if err := set(settingHookTimeout, strconv.Itoa(cfg.Hooks.TimeoutSeconds)); err != nil {
		return err
	}
	if err := set(settingTrivialBinary, cfg.Hooks.Trivial.BinaryPath); err != nil {
		return err
	}
	if err := set(settingTrivialDB, cfg.Hooks.Trivial.DBPath); err != nil {
		return err
	}
	return set(settingTrivialTimeout, strconv.Itoa(cfg.Hooks.Trivial.TimeoutSeconds))
}

// saveClamAVSettings persists ClamAV socket-mode settings.
func saveClamAVSettings(set, putRuntime settingSetter, cfg *Config) error {
	if cfg.ClamAV.Enabled != nil {
		// Runtime-managed: overwrite only if YAML declared clamav.enabled,
		// else seed-if-absent so a UI/API toggle survives a boot re-import.
		if err := putRuntime(settingClamAVEnabled, boolString(*cfg.ClamAV.Enabled)); err != nil {
			return err
		}
	}
	if err := set(settingClamAVSocketPath, cfg.ClamAV.SocketPath); err != nil {
		return err
	}
	if err := set(settingClamAVTimeout, strconv.Itoa(cfg.ClamAV.TimeoutSeconds)); err != nil {
		return err
	}
	return set(settingClamAVMaxStream, strconv.FormatInt(cfg.ClamAV.MaxStreamBytes, 10))
}

// saveAllDataSourceSettings persists the runtime configuration for each
// shared data source.
func saveAllDataSourceSettings(set, putRuntime settingSetter, cfg *Config) error {
	if err := saveDataSourceSettings(set, putRuntime, openSSFKeys, cfg.DataSources.OpenSSF); err != nil {
		return err
	}
	if err := saveDataSourceSettings(set, putRuntime, trivyKeys, cfg.DataSources.TrivyDB); err != nil {
		return err
	}
	if err := saveDataSourceSettings(set, putRuntime, epssKeys, cfg.DataSources.EPSS); err != nil {
		return err
	}
	return saveDataSourceSettings(set, putRuntime, clamAVDBKeys, cfg.DataSources.ClamAVDB)
}

// saveDataSourceSettings persists a single data source's runtime
// configuration using the key mapping provided.
func saveDataSourceSettings(set, putRuntime settingSetter, keys dataSourceKeys, ds DataSourceRuntimeConfig) error {
	if ds.Enabled != nil {
		if err := putRuntime(keys.enabled, boolString(*ds.Enabled)); err != nil {
			return err
		}
	}
	if err := set(keys.refresh, strconv.Itoa(ds.RefreshIntervalSeconds)); err != nil {
		return err
	}
	if ds.StartupSync != nil {
		if err := putRuntime(keys.startupSync, boolString(*ds.StartupSync)); err != nil {
			return err
		}
	}
	if err := set(keys.timeout, strconv.Itoa(ds.TimeoutSeconds)); err != nil {
		return err
	}
	return set(keys.jitter, strconv.Itoa(ds.JitterPercent))
}

// saveMiscSettings persists release policy, blocking mode, and
// anonymous-access flags.
func saveMiscSettings(set, putRuntime settingSetter, cfg *Config) error {
	days := cfg.ReleasePolicy.MinAgeDays
	if days < 0 {
		days = 0
	}
	if err := set(settingReleaseMinAgeDays, strconv.Itoa(days)); err != nil {
		return err
	}
	if cfg.BlockingMode != nil {
		if err := putRuntime(settingBlockingMode, boolString(*cfg.BlockingMode)); err != nil {
			return err
		}
	}
	if cfg.RepositoryAnonymousAccess != nil {
		if err := putRuntime(settingRepositoryAllowAnonymous, boolString(*cfg.RepositoryAnonymousAccess)); err != nil {
			return err
		}
	}
	return nil
}

// saveRepositoriesTx optionally clears and then upserts repositories for
// the org inside the provided transaction.
func saveRepositoriesTx(tx *sql.Tx, orgID string, repos []RepositoryConfig, replaceRepos bool) error {
	if replaceRepos {
		if _, err := tx.Exec(`DELETE FROM repositories WHERE org_id=?`, orgID); err != nil {
			return err
		}
	}
	for _, repo := range repos {
		if err := upsertRepository(tx, orgID, repo); err != nil {
			return err
		}
	}
	return nil
}

// SaveToStore persists the supplied configuration into the database for the default org.
// When replaceRepos is true, repository rows are replaced with the provided list.
func SaveToStore(store *pgstore.Store, cfg *Config, replaceRepos bool) error {
	return SaveToStoreForOrg(store, cfg, tenancy.DefaultOrgID, replaceRepos)
}

// ReplaceRepositoriesForOrg swaps the stored proxy definitions with the provided list.
func ReplaceRepositoriesForOrg(store *pgstore.Store, orgID string, repos []RepositoryConfig) error {
	if store == nil {
		return errors.New("database store is required")
	}
	return store.WithTx(context.Background(), func(tx *sql.Tx) error {
		return ReplaceRepositoriesForOrgTx(tx, orgID, repos)
	})
}

// ReplaceRepositories swaps the stored proxy definitions with the provided list for the default org.
func ReplaceRepositories(store *pgstore.Store, repos []RepositoryConfig) error {
	return ReplaceRepositoriesForOrg(store, tenancy.DefaultOrgID, repos)
}

// ReplaceRepositoriesForOrgTx swaps the stored proxy definitions with the provided list using an existing transaction.
func ReplaceRepositoriesForOrgTx(tx *sql.Tx, orgID string, repos []RepositoryConfig) error {
	if tx == nil {
		return errors.New("database transaction is required")
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	if _, err := tx.Exec(`DELETE FROM repositories WHERE org_id=?`, orgID); err != nil {
		return err
	}
	for _, repo := range repos {
		if err := upsertRepository(tx, orgID, repo); err != nil {
			return err
		}
	}
	return nil
}

// ErrRepositoryExists reports that the org already has a repository under the
// requested name. Callers surface it as 409 Conflict rather than letting the
// create path silently redefine somebody else's repository.
var ErrRepositoryExists = errors.New("repository already exists")

// CreateRepositoryForOrg inserts ONE repository for the org and returns the
// stored configuration read back from the database.
//
// Deliberately not ReplaceRepositoriesForOrg{,Tx}: those DELETE every row for
// the org before writing, which is the right shape for a whole-config reload
// and catastrophic for a single create — the caller would wipe every other
// repository in the org. This reuses the same upsertRepository helper inside
// a transaction of its own, fronted by an existence check so a name collision
// returns ErrRepositoryExists instead of overwriting the existing definition
// (upsertRepository on its own is ON CONFLICT DO UPDATE).
//
// The existence check is advisory, not a lock: two concurrent creates of the
// same name can both observe "absent", in which case the second serialises on
// the (org_id, name) unique index and lands as an update rather than a 409.
// Both callers asked for the same repository to exist, so the end state is
// still one row with the last writer's definition.
func CreateRepositoryForOrg(store *pgstore.Store, orgID string, repo RepositoryConfig) (RepositoryConfig, error) {
	if store == nil {
		return RepositoryConfig{}, errors.New("database store is required")
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	repo.Name = strings.TrimSpace(repo.Name)
	if repo.Name == "" {
		return RepositoryConfig{}, errors.New("repository name is required")
	}
	if strings.TrimSpace(repo.Format) == "" {
		return RepositoryConfig{}, errors.New("repository format is required")
	}
	err := store.WithTx(context.Background(), func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM repositories WHERE org_id=? AND name=?)`,
			orgID, repo.Name).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("%q: %w", repo.Name, ErrRepositoryExists)
		}
		return upsertRepository(tx, orgID, repo)
	})
	if err != nil {
		return RepositoryConfig{}, err
	}
	return fetchRepository(store.DB(), orgID, repo.Name)
}

// UpdateRepositoryForOrg applies runtime updates to a repository record and returns
// the updated configuration.
func UpdateRepositoryForOrg(store *pgstore.Store, orgID, name string, update RepositoryUpdate) (RepositoryConfig, error) {
	if store == nil {
		return RepositoryConfig{}, errors.New("database store is required")
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	name = strings.TrimSpace(name)
	if name == "" {
		return RepositoryConfig{}, errors.New("repository name is required")
	}
	err := store.WithTx(context.Background(), func(tx *sql.Tx) error {
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS(SELECT 1 FROM repositories WHERE org_id=? AND name=?)`, orgID, name).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("repository %q not found", name)
		}
		setParts := make([]string, 0, 4)
		args := make([]any, 0, 5)
		if update.Enabled != nil {
			setParts = append(setParts, "enabled=?")
			args = append(args, boolInt(*update.Enabled))
		}
		if update.AnonymousAccess != nil {
			setParts = append(setParts, "anonymous_access=?")
			args = append(args, boolInt(*update.AnonymousAccess))
		}
		if strings.TrimSpace(update.RemoteURL) != "" {
			setParts = append(setParts, "remote_url=?")
			args = append(args, strings.TrimSpace(update.RemoteURL))
		}
		if update.CacheNegativeTTLSeconds != nil {
			setParts = append(setParts, "cache_negative_ttl_seconds=?")
			args = append(args, *update.CacheNegativeTTLSeconds)
		}
		if len(setParts) == 0 {
			return errors.New("no mutable fields provided")
		}
		setParts = append(setParts, "updated_at=current_timestamp")
		args = append(args, orgID, name)
		stmt := fmt.Sprintf("UPDATE repositories SET %s WHERE org_id=? AND name=?", strings.Join(setParts, ","))
		_, err := tx.Exec(stmt, args...)
		return err
	})
	if err != nil {
		return RepositoryConfig{}, err
	}
	repo, err := fetchRepository(store.DB(), orgID, name)
	return repo, err
}

// UpdateRepository applies runtime updates to a repository record for the default org.
func UpdateRepository(store *pgstore.Store, name string, update RepositoryUpdate) (RepositoryConfig, error) {
	return UpdateRepositoryForOrg(store, tenancy.DefaultOrgID, name, update)
}

// SetBlockingMode persists the blocking mode flag.
func fetchSettings(db *sql.DB, orgID string) (settingMap, error) {
	orgID = tenancy.NormalizeOrgID(orgID)
	rows, err := db.Query(`SELECT key, value FROM settings WHERE org_id=?`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make(settingMap)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		result[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return result, rows.Err()
}

func fetchRepositories(db *sql.DB, orgID string) ([]RepositoryConfig, bool, error) {
	orgID = tenancy.NormalizeOrgID(orgID)
	rows, err := db.Query(`SELECT name, format, type, enabled, remote_url,
		COALESCE(remote_proxy_url, '') as remote_proxy_url,
		remote_skip_tls, remote_timeout_seconds,
		COALESCE(remote_headers, '') as remote_headers,
		cache_negative_ttl_seconds,
		COALESCE(client_configuration_guide_template, '') as client_configuration_guide,
		COALESCE(anonymous_access, 0) as anonymous_access,
		COALESCE(public_base_url, '') as public_base_url,
		COALESCE(format_options, '') as format_options
		FROM repositories WHERE org_id=? ORDER BY name`, orgID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var repos []RepositoryConfig
	for rows.Next() {
		var (
			name, format, repoType, remoteURL, remoteProxyURL, headersJSON, configGuide, publicBaseURL string
			formatOptions                                                                              string
			enabled, skipTLS, anonymousAccess                                                          int
			timeout, ttl                                                                               int
		)
		if err := rows.Scan(&name, &format, &repoType, &enabled, &remoteURL, &remoteProxyURL, &skipTLS, &timeout, &headersJSON, &ttl, &configGuide, &anonymousAccess, &publicBaseURL, &formatOptions); err != nil {
			return nil, false, err
		}
		repo := RepositoryConfig{
			Name:                     name,
			Format:                   format,
			Type:                     repoType,
			ClientConfigurationGuide: configGuide,
			PublicBaseURL:            publicBaseURL,
			Remote: RemoteConfig{
				URL:            remoteURL,
				ProxyURL:       remoteProxyURL,
				SkipTLSVerify:  skipTLS == 1,
				TimeoutSeconds: timeout,
			},
			Cache: CacheConfig{
				NegativeTTLSeconds: ttl,
			},
		}
		if headersJSON != "" {
			var headers map[string]string
			if err := json.Unmarshal([]byte(headersJSON), &headers); err == nil {
				repo.Remote.Headers = headers
			}
		}
		decodeRepoFormatOptions(formatOptions, &repo)
		if enabled == 0 {
			value := false
			repo.Enabled = &value
		}
		if anonymousAccess == 1 {
			value := true
			repo.AnonymousAccess = &value
		} else {
			value := false
			repo.AnonymousAccess = &value
		}
		repos = append(repos, repo)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return repos, len(repos) > 0, nil
}

func fetchRepository(db *sql.DB, orgID, name string) (RepositoryConfig, error) {
	row := db.QueryRow(`SELECT name, format, type, enabled, remote_url,
		COALESCE(remote_proxy_url, '') as remote_proxy_url,
		remote_skip_tls, remote_timeout_seconds,
		COALESCE(remote_headers, '') as remote_headers,
		cache_negative_ttl_seconds,
		COALESCE(client_configuration_guide_template, '') as client_configuration_guide,
		COALESCE(anonymous_access, 0) as anonymous_access,
		COALESCE(public_base_url, '') as public_base_url,
		COALESCE(format_options, '') as format_options
		FROM repositories WHERE org_id=? AND name=?`, tenancy.NormalizeOrgID(orgID), name)
	var (
		format, repoType, remoteURL, remoteProxyURL, headersJSON, configGuide, publicBaseURL string
		formatOptions                                                                        string
		enabled, skipTLS, anonymousAccess                                                    int
		timeout, ttl                                                                         int
	)
	cfg := RepositoryConfig{}
	if err := row.Scan(&cfg.Name, &format, &repoType, &enabled, &remoteURL, &remoteProxyURL, &skipTLS, &timeout, &headersJSON, &ttl, &configGuide, &anonymousAccess, &publicBaseURL, &formatOptions); err != nil {
		return RepositoryConfig{}, err
	}
	decodeRepoFormatOptions(formatOptions, &cfg)
	cfg.Format = format
	cfg.Type = repoType
	cfg.ClientConfigurationGuide = configGuide
	cfg.PublicBaseURL = publicBaseURL
	cfg.Remote.URL = remoteURL
	cfg.Remote.ProxyURL = remoteProxyURL
	cfg.Remote.SkipTLSVerify = skipTLS == 1
	cfg.Remote.TimeoutSeconds = timeout
	if headersJSON != "" {
		var headers map[string]string
		if err := json.Unmarshal([]byte(headersJSON), &headers); err == nil {
			cfg.Remote.Headers = headers
		}
	}
	cfg.Cache.NegativeTTLSeconds = ttl
	if enabled == 0 {
		value := false
		cfg.Enabled = &value
	}
	if anonymousAccess == 1 {
		value := true
		cfg.AnonymousAccess = &value
	} else {
		value := false
		cfg.AnonymousAccess = &value
	}
	return cfg, nil
}

func SetBlockingModeForOrg(store *pgstore.Store, orgID string, enabled bool) error {
	if store == nil {
		return errors.New("database store is required")
	}
	return setSettingForOrg(store, orgID, settingBlockingMode, boolString(enabled))
}

func SetBlockingMode(store *pgstore.Store, enabled bool) error {
	return SetBlockingModeForOrg(store, tenancy.DefaultOrgID, enabled)
}

// SetRepositoryAnonymousAccessForOrg persists whether /repository routes allow anonymous clients.
func SetRepositoryAnonymousAccessForOrg(store *pgstore.Store, orgID string, allow bool) error {
	if store == nil {
		return errors.New("database store is required")
	}
	return setSettingForOrg(store, orgID, settingRepositoryAllowAnonymous, boolString(allow))
}

// SetRepositoryAnonymousAccess persists whether /repository routes allow anonymous clients.
func SetRepositoryAnonymousAccess(store *pgstore.Store, allow bool) error {
	return SetRepositoryAnonymousAccessForOrg(store, tenancy.DefaultOrgID, allow)
}

// SetReleaseMinAgeDaysForOrg persists the minimum release-age enforcement window.
func SetReleaseMinAgeDaysForOrg(store *pgstore.Store, orgID string, days int) error {
	if store == nil {
		return errors.New("database store is required")
	}
	if days < 0 {
		days = 0
	}
	return setSettingForOrg(store, orgID, settingReleaseMinAgeDays, strconv.Itoa(days))
}

// SetReleaseMinAgeDays persists the minimum release-age enforcement window.
func SetReleaseMinAgeDays(store *pgstore.Store, days int) error {
	return SetReleaseMinAgeDaysForOrg(store, tenancy.DefaultOrgID, days)
}

func SetExceptionAgeForOrg(store *pgstore.Store, orgID string, days int) error {
	if store == nil {
		return errors.New("database store is required")
	}
	if days < 0 {
		days = 0
	}
	return setSettingForOrg(store, orgID, settingExceptionAge, strconv.Itoa(days))
}

func SetExceptionAge(store *pgstore.Store, days int) error {
	return SetExceptionAgeForOrg(store, tenancy.DefaultOrgID, days)
}

// SetBlockContactEmailForOrg persists the explicit block-contact override
// for an org. An empty string clears the override and restores the
// owner-email → generic-string fallback chain.
func SetBlockContactEmailForOrg(store *pgstore.Store, orgID, email string) error {
	if store == nil {
		return errors.New("database store is required")
	}
	email = strings.TrimSpace(email)
	return setSettingForOrg(store, orgID, settingBlockContactEmail, email)
}

// LoadBlockContactEmailForOrg returns the explicit override or empty string
// when unset. An error indicates a store-layer failure, not a missing row.
func LoadBlockContactEmailForOrg(store *pgstore.Store, orgID string) (string, error) {
	if store == nil {
		return "", errors.New("database store is required")
	}
	settings, err := fetchSettings(store.DB(), orgID)
	if err != nil {
		return "", err
	}
	v, _ := settings.lookup(settingBlockContactEmail)
	return strings.TrimSpace(v), nil
}

// RecordYAMLImport persists the absolute path of the YAML config file
// that was just imported and the wall-clock time of the import. Stored
// in the default-org settings table because the YAML import is a
// process-wide event (it seeds the global "default" org); per-org
// imports go through the API and don't touch this record. Errors are
// returned to the caller so the boot path can decide whether they are
// fatal — typically callers log and continue, since the import itself
// already succeeded by the time this is called.
func RecordYAMLImport(store *pgstore.Store, path string) error {
	if store == nil {
		return errors.New("database store is required")
	}
	abs := strings.TrimSpace(path)
	if abs == "" {
		return errors.New("yaml import path must not be empty")
	}
	// Resolve to an absolute path so the recorded value is comparable
	// across boots that change cwd (e.g. running under systemd vs by
	// hand). Best-effort: if filepath.Abs fails fall back to the input
	// — recording something is strictly better than nothing.
	if resolved, err := filepath.Abs(abs); err == nil {
		abs = resolved
	}
	if err := setSetting(store, settingYAMLImportPath, abs); err != nil {
		return err
	}
	return setSetting(store, settingYAMLImportedAt, time.Now().UTC().Format(time.RFC3339Nano))
}

// LastYAMLImport returns the absolute path of the most recently
// imported YAML config and the timestamp at which the import happened.
// Returns ("", zero, nil) when no import has been recorded yet — the
// caller should treat that as "no prior import" rather than an error.
// Both fields are zero-valued on any parse error, so callers don't
// have to special-case malformed legacy rows.
func LastYAMLImport(store *pgstore.Store) (string, time.Time, error) {
	if store == nil {
		return "", time.Time{}, errors.New("database store is required")
	}
	settings, err := fetchSettings(store.DB(), tenancy.DefaultOrgID)
	if err != nil {
		return "", time.Time{}, err
	}
	path := settings.get(settingYAMLImportPath)
	rawTS := settings.get(settingYAMLImportedAt)
	if path == "" && rawTS == "" {
		return "", time.Time{}, nil
	}
	ts, err := time.Parse(time.RFC3339Nano, rawTS)
	if err != nil {
		// Try the older second-precision layout in case an operator
		// hand-edited the row. Anything truly malformed falls back to
		// the zero value, which the caller treats as "unknown".
		if alt, altErr := time.Parse(time.RFC3339, rawTS); altErr == nil {
			ts = alt
		} else {
			ts = time.Time{}
		}
	}
	return path, ts, nil
}

// YAMLFreshnessReport summarises the on-disk vs last-imported state of
// a YAML config file. It is a pure value type so callers can format the
// log line however suits them; the package does not log directly to
// keep test setup cheap.
type YAMLFreshnessReport struct {
	// Path is the YAML file inspected (absolute when resolvable).
	Path string
	// LastImportPath is the absolute path of the previous import as
	// recorded in the settings table. Empty when no prior import.
	LastImportPath string
	// LastImportedAt is the recorded import timestamp. Zero when none.
	LastImportedAt time.Time
	// FileModTime is the on-disk mtime of Path. Zero when the file
	// is missing or unreadable.
	FileModTime time.Time
	// SamePath is true when Path resolves to the same absolute file
	// as LastImportPath. False positives here would over-warn after
	// an operator legitimately swaps in a new YAML file, so we
	// require an exact path match before claiming staleness.
	SamePath bool
	// FileExists is false when Path could not be statted.
	FileExists bool
	// ModifiedAfterImport is true when FileModTime is strictly after
	// LastImportedAt AND SamePath is true. The caller treats this as
	// the trigger for the warning.
	ModifiedAfterImport bool
}

// InspectYAMLFreshness compares the on-disk mtime of `path` against the
// recorded last-import timestamp and returns a structured report. The
// caller decides whether to emit an INFO (file was re-imported just
// now) or a WARN (file is newer than the last import and the operator
// did NOT pass --config). All errors except "file does not exist" are
// returned; the missing-file case sets FileExists=false and returns
// nil so the caller can short-circuit.
func InspectYAMLFreshness(store *pgstore.Store, path string) (YAMLFreshnessReport, error) {
	report := YAMLFreshnessReport{Path: strings.TrimSpace(path)}
	if report.Path == "" {
		return report, errors.New("yaml path must not be empty")
	}
	if abs, err := filepath.Abs(report.Path); err == nil {
		report.Path = abs
	}
	lastPath, lastTS, err := LastYAMLImport(store)
	if err != nil {
		return report, err
	}
	return buildYAMLFreshnessReport(report.Path, lastPath, lastTS, os.Stat)
}

// buildYAMLFreshnessReport is the pure-Go core of InspectYAMLFreshness,
// split out so unit tests can drive the filesystem-vs-timestamp matrix
// without standing up a database. The statFn parameter lets tests
// inject an os.Stat stub; production callers pass os.Stat directly.
//
// path must already be absolute (or at least in the canonical form
// that will be compared against lastPath).
func buildYAMLFreshnessReport(
	path, lastPath string,
	lastImportedAt time.Time,
	statFn func(string) (os.FileInfo, error),
) (YAMLFreshnessReport, error) {
	report := YAMLFreshnessReport{
		Path:           path,
		LastImportPath: lastPath,
		LastImportedAt: lastImportedAt,
		SamePath:       lastPath != "" && lastPath == path,
	}
	if statFn == nil {
		statFn = os.Stat
	}
	info, err := statFn(path)
	if err != nil {
		if os.IsNotExist(err) {
			report.FileExists = false
			return report, nil
		}
		return report, err
	}
	report.FileExists = true
	report.FileModTime = info.ModTime().UTC()

	// Stale only when the operator is talking about the same file AND
	// the on-disk copy is strictly newer. A different path means
	// "operator switched configs", which is a normal first-import event
	// and should not produce a stale warning.
	if report.SamePath && !report.LastImportedAt.IsZero() &&
		report.FileModTime.After(report.LastImportedAt) {
		report.ModifiedAfterImport = true
	}
	return report, nil
}

// SetDataSourceConfigForOrg persists the runtime configuration for a shared datasource.
func SetDataSourceConfigForOrg(store *pgstore.Store, orgID, source string, cfg DataSourceRuntimeConfig) error {
	if store == nil {
		return errors.New("database store is required")
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	source = strings.TrimSpace(strings.ToLower(source))
	switch source {
	case "openssf":
		if cfg.Enabled != nil {
			if err := setSettingForOrg(store, orgID, settingDataSourceOpenSSFEnabled, boolString(*cfg.Enabled)); err != nil {
				return err
			}
		}
		if err := setSettingForOrg(store, orgID, settingDataSourceOpenSSFRefresh, strconv.Itoa(cfg.RefreshIntervalSeconds)); err != nil {
			return err
		}
		if cfg.StartupSync != nil {
			if err := setSettingForOrg(store, orgID, settingDataSourceOpenSSFStartup, boolString(*cfg.StartupSync)); err != nil {
				return err
			}
		}
		if err := setSettingForOrg(store, orgID, settingDataSourceOpenSSFTimeout, strconv.Itoa(cfg.TimeoutSeconds)); err != nil {
			return err
		}
		return setSettingForOrg(store, orgID, settingDataSourceOpenSSFJitter, strconv.Itoa(cfg.JitterPercent))
	case "trivy_db":
		if cfg.Enabled != nil {
			if err := setSettingForOrg(store, orgID, settingDataSourceTrivyEnabled, boolString(*cfg.Enabled)); err != nil {
				return err
			}
		}
		if err := setSettingForOrg(store, orgID, settingDataSourceTrivyRefresh, strconv.Itoa(cfg.RefreshIntervalSeconds)); err != nil {
			return err
		}
		if cfg.StartupSync != nil {
			if err := setSettingForOrg(store, orgID, settingDataSourceTrivyStartup, boolString(*cfg.StartupSync)); err != nil {
				return err
			}
		}
		if err := setSettingForOrg(store, orgID, settingDataSourceTrivyTimeout, strconv.Itoa(cfg.TimeoutSeconds)); err != nil {
			return err
		}
		return setSettingForOrg(store, orgID, settingDataSourceTrivyJitter, strconv.Itoa(cfg.JitterPercent))
	case "epss":
		if cfg.Enabled != nil {
			if err := setSettingForOrg(store, orgID, settingDataSourceEPSSEnabled, boolString(*cfg.Enabled)); err != nil {
				return err
			}
		}
		if err := setSettingForOrg(store, orgID, settingDataSourceEPSSRefresh, strconv.Itoa(cfg.RefreshIntervalSeconds)); err != nil {
			return err
		}
		if cfg.StartupSync != nil {
			if err := setSettingForOrg(store, orgID, settingDataSourceEPSSStartup, boolString(*cfg.StartupSync)); err != nil {
				return err
			}
		}
		if err := setSettingForOrg(store, orgID, settingDataSourceEPSSTimeout, strconv.Itoa(cfg.TimeoutSeconds)); err != nil {
			return err
		}
		return setSettingForOrg(store, orgID, settingDataSourceEPSSJitter, strconv.Itoa(cfg.JitterPercent))
	case "clamav_db":
		if cfg.Enabled != nil {
			if err := setSettingForOrg(store, orgID, settingDataSourceClamAVEnabled, boolString(*cfg.Enabled)); err != nil {
				return err
			}
		}
		if err := setSettingForOrg(store, orgID, settingDataSourceClamAVRefresh, strconv.Itoa(cfg.RefreshIntervalSeconds)); err != nil {
			return err
		}
		if cfg.StartupSync != nil {
			if err := setSettingForOrg(store, orgID, settingDataSourceClamAVStartup, boolString(*cfg.StartupSync)); err != nil {
				return err
			}
		}
		if err := setSettingForOrg(store, orgID, settingDataSourceClamAVTimeout, strconv.Itoa(cfg.TimeoutSeconds)); err != nil {
			return err
		}
		return setSettingForOrg(store, orgID, settingDataSourceClamAVJitter, strconv.Itoa(cfg.JitterPercent))
	default:
		return fmt.Errorf("unknown data source %q", source)
	}
}

func SetClamAVConfigForOrg(store *pgstore.Store, orgID string, cfg ClamAVConfig) error {
	if store == nil {
		return errors.New("database store is required")
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	if cfg.Enabled != nil {
		if err := setSettingForOrg(store, orgID, settingClamAVEnabled, boolString(*cfg.Enabled)); err != nil {
			return err
		}
	}
	if err := setSettingForOrg(store, orgID, settingClamAVSocketPath, cfg.SocketPath); err != nil {
		return err
	}
	if err := setSettingForOrg(store, orgID, settingClamAVTimeout, strconv.Itoa(cfg.TimeoutSeconds)); err != nil {
		return err
	}
	return setSettingForOrg(store, orgID, settingClamAVMaxStream, strconv.FormatInt(cfg.MaxStreamBytes, 10))
}

// EnsureAdminPassword guarantees a hashed administrator password exists. Returns the hash and,
// when a new password was generated, the plaintext that should be surfaced to operators.
func EnsureAdminPassword(store *pgstore.Store) (hash string, generated string, err error) {
	if store == nil {
		return "", "", errors.New("database store is required")
	}
	settings, err := fetchSettings(store.DB(), tenancy.DefaultOrgID)
	if err != nil {
		return "", "", err
	}
	if existing := strings.TrimSpace(settings.get(settingAdminPasswordHash)); existing != "" {
		return existing, "", nil
	}
	if legacy := strings.TrimSpace(settings.get(settingAdminPassword)); legacy != "" {
		hashed, err := SetAdminPassword(store, legacy)
		if err != nil {
			return "", "", err
		}
		_ = deleteSetting(store, settingAdminPassword)
		return hashed, "", nil
	}
	password, err := generateRandomPassword()
	if err != nil {
		return "", "", err
	}
	hashed, err := SetAdminPassword(store, password)
	if err != nil {
		return "", "", err
	}
	return hashed, password, nil
}

// ResetAdminPassword unconditionally generates a new random admin password,
// persists its hash, and returns the plaintext so the caller can surface it
// to the operator (e.g. write it to the generated_password file, print it
// to stdout). Intended for the `--reset-admin-password` CLI recovery flow:
// unlike EnsureAdminPassword, it does not look at any existing hash.
func ResetAdminPassword(store *pgstore.Store) (string, error) {
	if store == nil {
		return "", errors.New("database store is required")
	}
	password, err := generateRandomPassword()
	if err != nil {
		return "", err
	}
	if _, err := SetAdminPassword(store, password); err != nil {
		return "", err
	}
	// Clear any leftover plaintext legacy entry so the next restart
	// doesn't resurrect it via EnsureAdminPassword's legacy path.
	_ = deleteSetting(store, settingAdminPassword)
	return password, nil
}

// SetAdminPassword hashes and persists the provided password, returning the resulting hash.
func SetAdminPassword(store *pgstore.Store, plain string) (string, error) {
	plain = strings.TrimSpace(plain)
	if store == nil {
		return "", errors.New("database store is required")
	}
	if plain == "" {
		return "", errors.New("admin password must not be empty")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hash admin password: %w", err)
	}
	if err := setSetting(store, settingAdminPasswordHash, string(hash)); err != nil {
		return "", err
	}
	return string(hash), nil
}

// AdminPasswordHash returns the hashed password currently stored.
func AdminPasswordHash(store *pgstore.Store) (string, error) {
	if store == nil {
		return "", errors.New("database store is required")
	}
	settings, err := fetchSettings(store.DB(), tenancy.DefaultOrgID)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(settings.get(settingAdminPasswordHash)), nil
}

func upsertRepository(tx *sql.Tx, orgID string, repo RepositoryConfig) error {
	orgID = tenancy.NormalizeOrgID(orgID)
	enabled := 1
	if repo.Enabled != nil && !*repo.Enabled {
		enabled = 0
	}
	anonymousAccess := 0
	if repo.AnonymousAccess != nil && *repo.AnonymousAccess {
		anonymousAccess = 1
	}
	headersJSON := ""
	if len(repo.Remote.Headers) > 0 {
		b, err := json.Marshal(repo.Remote.Headers)
		if err != nil {
			return err
		}
		headersJSON = string(b)
	}
	formatOptions, err := encodeRepoFormatOptions(repo)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO repositories(org_id, name, format, type, enabled, anonymous_access, remote_url, remote_proxy_url,
		remote_skip_tls, remote_timeout_seconds, remote_headers, cache_negative_ttl_seconds, client_configuration_guide_template, public_base_url,
		format_options)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(org_id, name) DO UPDATE SET
			org_id=excluded.org_id,
			format=excluded.format,
			type=excluded.type,
			enabled=excluded.enabled,
			anonymous_access=excluded.anonymous_access,
			remote_url=excluded.remote_url,
			remote_proxy_url=excluded.remote_proxy_url,
			remote_skip_tls=excluded.remote_skip_tls,
			remote_timeout_seconds=excluded.remote_timeout_seconds,
			remote_headers=excluded.remote_headers,
			cache_negative_ttl_seconds=excluded.cache_negative_ttl_seconds,
			client_configuration_guide_template=excluded.client_configuration_guide_template,
			public_base_url=excluded.public_base_url,
			format_options=excluded.format_options,
			updated_at=current_timestamp`, orgID, strings.TrimSpace(repo.Name), strings.TrimSpace(repo.Format), strings.TrimSpace(repo.Type),
		enabled, anonymousAccess, strings.TrimSpace(repo.Remote.URL), strings.TrimSpace(repo.Remote.ProxyURL), boolInt(repo.Remote.SkipTLSVerify),
		repo.Remote.TimeoutSeconds, headersJSON, repo.Cache.NegativeTTLSeconds, strings.TrimSpace(repo.ClientConfigurationGuide),
		strings.TrimSpace(repo.PublicBaseURL), formatOptions)
	return err
}

// repoFormatOptions is the JSON envelope for the per-format metadata
// sub-blocks of a repository. It exists because apt/yum are optional
// pointer structs with no natural scalar columns — and because they were
// the last part of RepositoryConfig with no durable home, so a
// hosted-apt repo's suites/components/architectures silently reverted to
// apt.Default() on the next boot.
type repoFormatOptions struct {
	APT *APTRepoConfig `json:"apt,omitempty"`
	Yum *YumRepoConfig `json:"yum,omitempty"`
}

func encodeRepoFormatOptions(repo RepositoryConfig) (string, error) {
	if repo.APT == nil && repo.Yum == nil {
		return "", nil
	}
	encoded, err := json.Marshal(repoFormatOptions{APT: repo.APT, Yum: repo.Yum})
	if err != nil {
		return "", fmt.Errorf("encode repository %q format options: %w", repo.Name, err)
	}
	return string(encoded), nil
}

// decodeRepoFormatOptions is deliberately lenient: a malformed row leaves
// the sub-blocks nil (which means "use the format's defaults") rather
// than failing the whole config load and wedging boot.
func decodeRepoFormatOptions(raw string, repo *RepositoryConfig) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	var decoded repoFormatOptions
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		return
	}
	repo.APT = decoded.APT
	repo.Yum = decoded.Yum
}

func setSettingForOrg(store *pgstore.Store, orgID, key, value string) error {
	if store == nil {
		return errors.New("database store is required")
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	_, err := store.DB().Exec(`INSERT INTO settings(key,value,org_id) VALUES(?,?,?)
		ON CONFLICT(org_id, key) DO UPDATE SET value=excluded.value`, key, strings.TrimSpace(value), orgID)
	return err
}

func setSetting(store *pgstore.Store, key, value string) error {
	return setSettingForOrg(store, tenancy.DefaultOrgID, key, value)
}

func deleteSettingForOrg(store *pgstore.Store, orgID, key string) error {
	if store == nil {
		return errors.New("database store is required")
	}
	orgID = tenancy.NormalizeOrgID(orgID)
	_, err := store.DB().Exec(`DELETE FROM settings WHERE org_id=? AND key=?`, orgID, key)
	return err
}

func deleteSetting(store *pgstore.Store, key string) error {
	return deleteSettingForOrg(store, tenancy.DefaultOrgID, key)
}

func generateRandomPassword() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

type settingMap map[string]string

func (m settingMap) get(key string) string {
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[key])
}

func (m settingMap) lookup(key string) (string, bool) {
	if m == nil {
		return "", false
	}
	value, ok := m[key]
	return strings.TrimSpace(value), ok
}

func (m settingMap) getInt(key string) int {
	value := m.get(key)
	if value == "" {
		return 0
	}
	num, _ := strconv.Atoi(value)
	return num
}

func (m settingMap) getInt64(key string) int64 {
	value := m.get(key)
	if value == "" {
		return 0
	}
	num, _ := strconv.ParseInt(value, 10, 64)
	return num
}

func (m settingMap) getBool(key string) bool {
	value := strings.ToLower(m.get(key))
	return value == "true" || value == "1"
}

// getBoolDefault returns the parsed bool when the key is present, or
// the supplied default when absent. Wave AF: used for swift settings
// where the desired default is true (git fallback + github convention
// are both on out of the box) but an explicit false in the settings
// table must still win.
func (m settingMap) getBoolDefault(key string, defaultValue bool) bool {
	value, ok := m.lookup(key)
	if !ok {
		return defaultValue
	}
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized == "true" || normalized == "1"
}

// ---------------------------------------------------------------------
// overlay helpers
//
// Each writes through to dst ONLY when the settings table actually holds
// the key. "Absent" and "present but empty" are different: an absent row
// means the store does not own this key yet and the caller's base value
// (YAML, flags, defaults) stands; a present row — even an empty one —
// is the store's stated value and wins. Getting that distinction wrong
// in either direction reintroduces a variant of the bug this file is
// fixing: always-overwrite zeroes YAML-only blocks, never-overwrite
// breaks the admin UI.
//
// Unparseable numeric rows leave dst untouched rather than writing 0.
// A corrupted row must not silently mean "disabled" for something like
// policy.eval_cache_ttl_seconds.
// ---------------------------------------------------------------------

func (m settingMap) overlayString(key string, dst *string) {
	if value, ok := m.lookup(key); ok {
		*dst = value
	}
}

func (m settingMap) overlayInt(key string, dst *int) {
	value, ok := m.lookup(key)
	if !ok {
		return
	}
	if value == "" {
		*dst = 0
		return
	}
	if num, err := strconv.Atoi(value); err == nil {
		*dst = num
	}
}

func (m settingMap) overlayInt64(key string, dst *int64) {
	value, ok := m.lookup(key)
	if !ok {
		return
	}
	if value == "" {
		*dst = 0
		return
	}
	if num, err := strconv.ParseInt(value, 10, 64); err == nil {
		*dst = num
	}
}

func (m settingMap) overlayBool(key string, dst *bool) {
	if value, ok := m.lookup(key); ok {
		*dst = parseSettingBool(value)
	}
}

func (m settingMap) overlayBoolPtr(key string, dst **bool) {
	if value, ok := m.lookup(key); ok {
		*dst = boolPtr(parseSettingBool(value))
	}
}

func (m settingMap) overlayIntPtr(key string, dst **int) {
	value, ok := m.lookup(key)
	if !ok {
		return
	}
	if value == "" {
		// An empty row for a *int knob means "explicitly unset" — fall
		// back to the built-in default via applyDefaults.
		*dst = nil
		return
	}
	if num, err := strconv.Atoi(value); err == nil {
		*dst = &num
	}
}

func (m settingMap) overlayCommaList(key string, dst *[]string) {
	if value, ok := m.lookup(key); ok {
		*dst = splitCommaList(value)
	}
}

// overlayRemoteDefaults decodes the single JSON row that carries the
// whole `remotes:` map. A malformed row is ignored (base stands) rather
// than wiping every per-format upstream URL.
func (m settingMap) overlayRemoteDefaults(key string, dst *map[string]RemoteDefaults) {
	value, ok := m.lookup(key)
	if !ok || value == "" {
		return
	}
	var decoded map[string]RemoteDefaults
	if err := json.Unmarshal([]byte(value), &decoded); err != nil {
		return
	}
	*dst = decoded
}

func parseSettingBool(value string) bool {
	normalized := strings.ToLower(strings.TrimSpace(value))
	return normalized == "true" || normalized == "1"
}

func optionalBool(m settingMap, key string) *bool {
	if m == nil {
		return nil
	}
	value, ok := m.lookup(key)
	if !ok {
		return nil
	}
	normalized := strings.ToLower(strings.TrimSpace(value))
	parsed := normalized == "true" || normalized == "1"
	return boolPtr(parsed)
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

func boolPtr(v bool) *bool {
	value := v
	return &value
}

// splitCommaList parses a comma-separated settings value into a slice.
// Empty input returns nil so a never-saved Swift.GitHubOrgAllowList
// round-trips as nil (matching the YAML zero value) rather than
// []string{""}, which would falsely look like a one-entry allowlist.
func splitCommaList(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// joinCommaList is the inverse of splitCommaList. Nil/empty input
// produces "" so the persisted value is the same shape used by every
// other empty kv row.
func joinCommaList(items []string) string {
	if len(items) == 0 {
		return ""
	}
	cleaned := make([]string, 0, len(items))
	for _, item := range items {
		if t := strings.TrimSpace(item); t != "" {
			cleaned = append(cleaned, t)
		}
	}
	return strings.Join(cleaned, ",")
}
