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
)

// RepositoryUpdate captures mutable fields exposed via the UI.
type RepositoryUpdate struct {
	Enabled                 *bool
	AnonymousAccess         *bool
	RemoteURL               string
	CacheNegativeTTLSeconds *int
}

// LoadFromStoreForOrg hydrates a Config for an org from the database store. The returned
// boolean indicates whether any repositories already existed in the database.
func LoadFromStoreForOrg(store *pgstore.Store, orgID string) (*Config, bool, error) {
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

	cfg := &Config{
		Server: ServerConfig{
			Listen: settings.get(settingServerListen),
			Admin: AdminConfig{
				Username: settings.get(settingAdminUsername),
			},
			TLS: TLSConfig{
				CertFile:   settings.get(settingServerTLSCertFile),
				KeyFile:    settings.get(settingServerTLSKeyFile),
				MinVersion: settings.get(settingServerTLSMinVersion),
			},
		},
		BlobStore: BlobStoreConfig{
			Root: settings.get(settingBlobRoot),
		},
		HTTPClient: HTTPClientConfig{
			TimeoutSeconds: settings.getInt(settingHTTPTimeout),
			TLSInsecure:    settings.getBool(settingHTTPTLSInsecure),
			MaxIdleConns:   settings.getInt(settingHTTPMaxIdle),
		},
		Index: IndexConfig{
			Path: settings.get(settingIndexPath),
		},
		Exceptions: ExceptionsConfig{
			Path: settings.get(settingExceptionsPath),
		},
		GeoIP: GeoIPConfig{
			DBPath: settings.get(settingGeoIPDBPath),
		},
		Hooks: HooksConfig{
			RequestScript:  settings.get(settingHookScript),
			TimeoutSeconds: settings.getInt(settingHookTimeout),
			Trivial: TrivialHookConfig{
				BinaryPath:     settings.get(settingTrivialBinary),
				DBPath:         settings.get(settingTrivialDB),
				TimeoutSeconds: settings.getInt(settingTrivialTimeout),
			},
		},
		ClamAV: ClamAVConfig{
			Enabled:        optionalBool(settings, settingClamAVEnabled),
			SocketPath:     settings.get(settingClamAVSocketPath),
			TimeoutSeconds: settings.getInt(settingClamAVTimeout),
			MaxStreamBytes: settings.getInt64(settingClamAVMaxStream),
		},
		DataSources: DataSourcesConfig{
			OpenSSF: DataSourceRuntimeConfig{
				Enabled:                optionalBool(settings, settingDataSourceOpenSSFEnabled),
				RefreshIntervalSeconds: settings.getInt(settingDataSourceOpenSSFRefresh),
				StartupSync:            optionalBool(settings, settingDataSourceOpenSSFStartup),
				TimeoutSeconds:         settings.getInt(settingDataSourceOpenSSFTimeout),
				JitterPercent:          settings.getInt(settingDataSourceOpenSSFJitter),
			},
			TrivyDB: DataSourceRuntimeConfig{
				Enabled:                optionalBool(settings, settingDataSourceTrivyEnabled),
				RefreshIntervalSeconds: settings.getInt(settingDataSourceTrivyRefresh),
				StartupSync:            optionalBool(settings, settingDataSourceTrivyStartup),
				TimeoutSeconds:         settings.getInt(settingDataSourceTrivyTimeout),
				JitterPercent:          settings.getInt(settingDataSourceTrivyJitter),
			},
			EPSS: DataSourceRuntimeConfig{
				Enabled:                optionalBool(settings, settingDataSourceEPSSEnabled),
				RefreshIntervalSeconds: settings.getInt(settingDataSourceEPSSRefresh),
				StartupSync:            optionalBool(settings, settingDataSourceEPSSStartup),
				TimeoutSeconds:         settings.getInt(settingDataSourceEPSSTimeout),
				JitterPercent:          settings.getInt(settingDataSourceEPSSJitter),
			},
			ClamAVDB: DataSourceRuntimeConfig{
				Enabled:                optionalBool(settings, settingDataSourceClamAVEnabled),
				RefreshIntervalSeconds: settings.getInt(settingDataSourceClamAVRefresh),
				StartupSync:            optionalBool(settings, settingDataSourceClamAVStartup),
				TimeoutSeconds:         settings.getInt(settingDataSourceClamAVTimeout),
				JitterPercent:          settings.getInt(settingDataSourceClamAVJitter),
			},
		},
		Swift: SwiftConfig{
			// Wave AF: GitFallbackEnabled + GitHubConvention now default
			// TRUE when no explicit setting row exists. Real swift
			// package resolve through chain305 requires both: the
			// fallback engages SwiftPM's git-clone path through the
			// proxy, and the convention auto-maps `<scope>.<name>`
			// identifiers to `https://github.com/<scope>/<name>` so
			// SwiftPM's /identifiers?url= probe round-trips correctly
			// (Wave AE #141 fixed the reverse-lookup symmetry).
			// Explicit `false` in the settings table still wins.
			GitFallbackEnabled:  settings.getBoolDefault(settingSwiftGitFallbackEnabled, true),
			IdentifierMapPath:   settings.get(settingSwiftIdentifierMapPath),
			GitCacheDir:         settings.get(settingSwiftGitCacheDir),
			GitHubConvention:    settings.getBoolDefault(settingSwiftGitHubConvention, true),
			GitHubOrgAllowList:  splitCommaList(settings.get(settingSwiftGitHubOrgAllowList)),
			TrustRootBundlePath: settings.get(settingSwiftTrustRootBundlePath),
			TrustSwiftRoot:      settings.getBool(settingSwiftTrustSwiftRoot),
		},
		Repositories: repos,
	}
	cfg.ReleasePolicy.MinAgeDays = settings.getInt(settingReleaseMinAgeDays)
	cfg.Exceptions.AgeDays = settings.getInt(settingExceptionAge)
	if value, ok := settings.lookup(settingBlockingMode); ok {
		enabled := strings.EqualFold(value, "true") || value == "1"
		cfg.BlockingMode = &enabled
	}
	if value, ok := settings.lookup(settingRepositoryAllowAnonymous); ok {
		allow := strings.EqualFold(value, "true") || value == "1"
		cfg.RepositoryAnonymousAccess = boolPtr(allow)
	}
	cfg.applyDefaults("")
	return cfg, hasRepos, nil
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
		COALESCE(public_base_url, '') as public_base_url
		FROM repositories WHERE org_id=? ORDER BY name`, orgID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var repos []RepositoryConfig
	for rows.Next() {
		var (
			name, format, repoType, remoteURL, remoteProxyURL, headersJSON, configGuide, publicBaseURL string
			enabled, skipTLS, anonymousAccess                                                          int
			timeout, ttl                                                                               int
		)
		if err := rows.Scan(&name, &format, &repoType, &enabled, &remoteURL, &remoteProxyURL, &skipTLS, &timeout, &headersJSON, &ttl, &configGuide, &anonymousAccess, &publicBaseURL); err != nil {
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
		COALESCE(public_base_url, '') as public_base_url
		FROM repositories WHERE org_id=? AND name=?`, tenancy.NormalizeOrgID(orgID), name)
	var (
		format, repoType, remoteURL, remoteProxyURL, headersJSON, configGuide, publicBaseURL string
		enabled, skipTLS, anonymousAccess                                                    int
		timeout, ttl                                                                         int
	)
	cfg := RepositoryConfig{}
	if err := row.Scan(&cfg.Name, &format, &repoType, &enabled, &remoteURL, &remoteProxyURL, &skipTLS, &timeout, &headersJSON, &ttl, &configGuide, &anonymousAccess, &publicBaseURL); err != nil {
		return RepositoryConfig{}, err
	}
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
	_, err := tx.Exec(`INSERT INTO repositories(org_id, name, format, type, enabled, anonymous_access, remote_url, remote_proxy_url,
		remote_skip_tls, remote_timeout_seconds, remote_headers, cache_negative_ttl_seconds, client_configuration_guide_template, public_base_url)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
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
			updated_at=current_timestamp`, orgID, strings.TrimSpace(repo.Name), strings.TrimSpace(repo.Format), strings.TrimSpace(repo.Type),
		enabled, anonymousAccess, strings.TrimSpace(repo.Remote.URL), strings.TrimSpace(repo.Remote.ProxyURL), boolInt(repo.Remote.SkipTLSVerify),
		repo.Remote.TimeoutSeconds, headersJSON, repo.Cache.NegativeTTLSeconds, strings.TrimSpace(repo.ClientConfigurationGuide),
		strings.TrimSpace(repo.PublicBaseURL))
	return err
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
