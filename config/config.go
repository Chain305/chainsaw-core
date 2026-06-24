package config

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/chain305/chainsaw-core/policy"
	"gopkg.in/yaml.v3"
)

const (
	defaultAdminUsername = "admin"
)

// Config represents the root configuration document for the proxy service.
type Config struct {
	// Runtime carries cross-cutting runtime knobs — currently just the
	// CHAINSAW_OFFLINE umbrella flag. Placed at the root rather than
	// nested under Server so future runtime knobs (feature flags,
	// sampling, etc.) have an obvious home. See internal/config/offline.go.
	Runtime       RuntimeConfig       `yaml:"runtime"`
	Server        ServerConfig        `yaml:"server"`
	BlobStore     BlobStoreConfig     `yaml:"blob_store"`
	HTTPClient    HTTPClientConfig    `yaml:"http_client"`
	Index         IndexConfig         `yaml:"index"`
	Exceptions    ExceptionsConfig    `yaml:"exceptions"`
	GeoIP         GeoIPConfig         `yaml:"geoip"`
	Hooks         HooksConfig         `yaml:"hooks"`
	ClamAV        ClamAVConfig        `yaml:"clamav"`
	DataSources   DataSourcesConfig   `yaml:"data_sources"`
	ReleasePolicy ReleasePolicyConfig `yaml:"release_policy"`
	Swift         SwiftConfig         `yaml:"swift"`
	Policies      []policy.Policy     `yaml:"policies"`
	Policy        PolicyRuntimeConfig `yaml:"policy"`
	BlockingMode  *bool               `yaml:"blocking_mode"`
	// Provenance configures optional kill-switches for provenance
	// verification. Useful for network-isolated deployments where
	// outbound calls to keys.openpgp.org, sum.golang.org,
	// tuf-repo-cdn.sigstore.dev, Docker Hub, etc. aren't reachable.
	Provenance ProvenanceConfig `yaml:"provenance"`
	// Malware configures the malicious-package syncer (OpenSSF + GHSA).
	Malware MalwareConfig `yaml:"malware"`
	// SBOM controls SBOM export behavior. Default (zero value) keeps
	// exports byte-identical to pre-attribution releases. See SBOMConfig.
	SBOM SBOMConfig `yaml:"sbom"`
	// Correlation gates the optional pull-to-deployment correlation
	// feature. Default OFF — when disabled the admin endpoints, the
	// retention sweeper, and the dashboard "Running in production"
	// badge are all dark. See internal/deploycorr.
	Correlation CorrelationConfig `yaml:"correlation"`
	// Coverage controls the opt-in coverage-reporting feature. Default
	// OFF: no UI surface, no API endpoints registered, no scheduled work.
	// Hard contract: even when enabled the feature is purely
	// informational — never gates an install, never returns non-2xx on
	// the proxy hot path. See internal/coverage/.
	Coverage CoverageConfig `yaml:"coverage"`
	// RepositoryAnonymousAccess controls whether /repository/* endpoints allow requests
	// without client credentials. When nil, anonymous access is enabled.
	RepositoryAnonymousAccess *bool                        `yaml:"repository_anonymous_access"`
	Repositories              []RepositoryConfig           `yaml:"repositories"`
	Remotes                   map[string]RemoteDefaults    `yaml:"remotes"`
	Extra                     map[string]map[string]string `yaml:",inline"` // placeholder for forward compatibility

	// explicitKeys records which runtime-managed settings the YAML
	// explicitly set, captured at parse time BEFORE applyDefaults fills the
	// nil pointers. SaveToStore consults it so a boot-time YAML re-import
	// (the `--config` path in loadAndPersistConfig) overwrites only keys the
	// operator actually declared in YAML, and seeds-if-absent the rest —
	// instead of clobbering UI/API-set values (e.g. clamav.enabled) back to
	// their defaults on every restart. Unexported: never serialized. nil for
	// Default()/programmatic configs → every runtime key treated as
	// non-explicit (seed-if-absent), which is the safe no-clobber posture.
	explicitKeys map[string]bool `yaml:"-"`
}

// Default returns a configuration populated with the built-in repositories and paths.
func Default(baseDir string) (*Config, error) {
	cfg := &Config{}
	cfg.applyDefaults(baseDir)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func defaultBaseDir() string {
	return filepath.Join(".", "configs")
}

// ServerConfig defines HTTP listener parameters.
type ServerConfig struct {
	Listen string      `yaml:"listen"`
	Admin  AdminConfig `yaml:"admin"`
	// TLS turns the listener into an HTTPS listener when both CertFile
	// and KeyFile point at readable files. Default (zero value) keeps
	// the plaintext listener unchanged — many deployments terminate TLS
	// upstream (ingress, ELB, envoy).
	TLS TLSConfig `yaml:"tls"`
}

// AdminConfig holds credentials for accessing the admin UI/API.
type AdminConfig struct {
	Username string `yaml:"username"`
}

// TLSConfig carries the optional in-process TLS listener settings.
//
// The listener boots plaintext by default; it only enables TLS when
// both CertFile and KeyFile are populated and both point at readable
// files on disk. Half-configured states (only cert OR only key) fail
// startup so operators don't silently drop back to plaintext after
// rotating one half of the pair.
type TLSConfig struct {
	// CertFile is the path to a PEM-encoded certificate (or full chain).
	// Empty keeps the listener plaintext.
	CertFile string `yaml:"cert_file"`
	// KeyFile is the path to the matching PEM-encoded private key.
	// Empty keeps the listener plaintext.
	KeyFile string `yaml:"key_file"`
	// MinVersion is "1.2" or "1.3". Empty defaults to "1.2" because
	// TLS 1.0/1.1 are broken and Go's default min is 1.2 as of go1.18.
	MinVersion string `yaml:"min_version"`
}

// Enabled reports whether TLS is fully configured (both cert and key
// paths set). Callers still need to stat the files before trusting the
// listener to boot — see [TLSConfig.Validate].
func (t TLSConfig) Enabled() bool {
	return strings.TrimSpace(t.CertFile) != "" && strings.TrimSpace(t.KeyFile) != ""
}

// Validate rejects half-configured states and unknown min_version
// strings. An entirely-empty TLS block is valid (plaintext mode).
func (t TLSConfig) Validate() error {
	cert := strings.TrimSpace(t.CertFile)
	key := strings.TrimSpace(t.KeyFile)
	switch {
	case cert == "" && key == "":
		// plaintext mode — fine
	case cert == "" && key != "":
		return errors.New("server.tls.key_file is set but server.tls.cert_file is empty")
	case cert != "" && key == "":
		return errors.New("server.tls.cert_file is set but server.tls.key_file is empty")
	}
	switch strings.TrimSpace(t.MinVersion) {
	case "", "1.2", "1.3":
		// fine
	default:
		return fmt.Errorf("server.tls.min_version must be \"1.2\" or \"1.3\" (got %q)", t.MinVersion)
	}
	return nil
}

// BlobStoreConfig defines where cached artifacts live on disk.
type BlobStoreConfig struct {
	Root string `yaml:"root"`
}

// ProvenanceConfig controls the provenance verification subsystem.
// Default (zero-value) behavior: every ecosystem enabled.
type ProvenanceConfig struct {
	// Offline disables all provenance verification. Every Check returns
	// StatusUnavailable. Equivalent to listing every ecosystem in
	// DisabledEcosystems but more explicit.
	Offline bool `yaml:"offline"`
	// DisabledEcosystems lists ecosystem names to skip. Values are
	// matched case-insensitively against the canonical ecosystem keys
	// (npm, pypi, maven, gradle, rubygems, go, docker, nuget,
	// huggingface, apt, dnf, yum, cargo, composer, cocoapods).
	DisabledEcosystems []string `yaml:"disabled_ecosystems"`
	// SwiftFullVerify enables full SE-0391 CMS cryptographic verification
	// in the Swift provenance probe. When false (default), the probe
	// only confirms signature presence and returns StatusUnverified —
	// see internal/provenance/swift.go for the full rationale (archive
	// fetch cost). When true, the probe fetches the archive bytes,
	// invokes swift.Verifier, and returns StatusVerified on success.
	SwiftFullVerify bool `yaml:"swift_full_verify"`
	// SwiftRegistryURL is the SE-0292 registry base URL the probe queries
	// for SE-0391 signature metadata. Empty disables the Swift probe
	// (same as listing "swift" in DisabledEcosystems).
	SwiftRegistryURL string `yaml:"swift_registry_url"`
}

// MalwareConfig controls the malicious-package syncer.
//
// EnableGHSA defaults to true: most deployments benefit from the broader
// coverage GHSA provides for Swift. Air-gapped operators set it to false.
type MalwareConfig struct {
	// EnableGHSA toggles supplementary ingestion from the GitHub
	// Security Advisory database (`ecosystem=swift&type=malware`).
	// Pointer-to-bool so an absent YAML key keeps the default-on
	// behavior; explicit `enable_ghsa: false` opts out.
	EnableGHSA *bool `yaml:"enable_ghsa"`
}

// GHSAEnabled returns the effective EnableGHSA setting, defaulting to
// true when unset.
func (m MalwareConfig) GHSAEnabled() bool {
	if m.EnableGHSA == nil {
		return true
	}
	return *m.EnableGHSA
}

// CorrelationConfig gates the pull-to-deployment correlation feature
// (internal/deploycorr). When Enabled is false (the default) every
// surface is dark: no admin POST endpoint to record observations, no
// admin GET endpoint to look them up, no periodic sweeper goroutine,
// and the dashboard /health endpoint reports installed=false so the UI
// hides the "Running in production" filter. Customers without
// Kubernetes never see the feature at all.
//
// Cluster admins must additionally opt in per cluster by deploying the
// existing K8s admission webhook with --enable-deployment-correlation;
// without that flag the webhook never POSTs, even if the proxy side is
// turned on.
type CorrelationConfig struct {
	// Enabled flips the feature on. Pointer-to-bool was tempting (so
	// "absent key" feels different from "explicit false"), but the
	// contract here is dead simple: default OFF, and the feature is
	// invisible unless the operator opted in. A bool is enough.
	Enabled bool `yaml:"enabled"`
}

// CoverageConfig controls the coverage-reporting feature.
//
// Pain 2 (friction reduction): default ON. The feature is informational
// only — a repo missing from the expected-surface table or a client
// that has gone silent never blocks an install, never returns a non-2xx,
// and never affects policy decisions. Making it default-on closes the
// "/coverage 404 on a fresh org" friction the investigation called out.
//
// The runtime gate has belt-and-braces:
//  1. cfg.Coverage.Enabled controls the static config (default true).
//  2. The PostHog `coverage_default_on` flag (default true) is the
//     per-request kill-switch — operators can flip it per-org without
//     a redeploy if they need an emergency rollback.
//
// When Enabled is false the dashboard hides the page, the
// /api/coverage/* endpoints fall through to 404, the CLI subcommand
// prints "coverage is not enabled", and no scheduled job runs. That
// path remains intact for operators who explicitly opt out.
type CoverageConfig struct {
	// Enabled gates the entire feature. Pointer-to-bool so an absent
	// YAML key falls through to the default (true after the Pain 2
	// flip); explicit `enabled: false` opts out.
	Enabled *bool `yaml:"enabled"`
}

// IsEnabled reports the effective Enabled setting, defaulting to TRUE
// when unset. Pain 2 friction-reduction flip: a fresh install or an
// existing config that doesn't mention coverage now sees the feature
// on. Operators that want it off must say so explicitly with
// `coverage: { enabled: false }`.
func (c CoverageConfig) IsEnabled() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

// HTTPClientConfig controls outbound remote connections.
type HTTPClientConfig struct {
	TimeoutSeconds int  `yaml:"timeout_seconds"`
	TLSInsecure    bool `yaml:"tls_insecure"`
	MaxIdleConns   int  `yaml:"max_idle_conns"`
}

// PolicyRuntimeConfig tunes in-process policy runtime behaviour. The
// only knob today is the per-(org, repo, package, version) evaluation
// cache TTL. A nil EvalCacheTTLSeconds picks up the defaultPolicyEvalCacheTTLSeconds
// default (60s); an explicit 0 disables the cache entirely (every request
// walks the full evaluator path). Negative values are treated the same
// as 0 (disabled).
type PolicyRuntimeConfig struct {
	EvalCacheTTLSeconds *int `yaml:"eval_cache_ttl_seconds"`
}

// defaultPolicyEvalCacheTTLSeconds mirrors policy.DefaultEvalCacheTTL
// (60s). Duplicated as an int here rather than importing the constant
// so PolicyRuntimeConfig stays self-describing and this package doesn't
// take a runtime dep on a sibling's tick.
const defaultPolicyEvalCacheTTLSeconds = 60

// SBOMConfig tunes optional read-side enrichment of CycloneDX SBOM
// exports. All fields are off by default so the existing SBOM bytes are
// unchanged for deployments that don't opt in.
type SBOMConfig struct {
	// AttributionEnabled turns on per-component attribution properties
	// (chainsaw:attribution:*) derived from existing audit/install
	// records. When false (default) the SBOM export is byte-identical to
	// pre-attribution behavior. The CLI `--with-attribution` flag can
	// override this for one-off exports.
	AttributionEnabled bool `yaml:"attribution_enabled"`
	// AttributionWindowDays bounds how far back the audit query looks
	// when deriving attribution. 0 (default) means 90 days; negative is
	// treated the same as 0. The window is intentionally bounded so
	// exports stay quick and historical churn doesn't pollute the
	// "currently exposed" picture.
	AttributionWindowDays int `yaml:"attribution_window_days"`
}

// AttributionWindow returns the effective attribution window, defaulting
// to 90 days when AttributionWindowDays is zero or negative.
func (s SBOMConfig) AttributionWindow() time.Duration {
	d := s.AttributionWindowDays
	if d <= 0 {
		d = 90
	}
	return time.Duration(d) * 24 * time.Hour
}

// IndexConfig controls the package index backing store.
type IndexConfig struct {
	Path string `yaml:"path"`
}

// ExceptionsConfig defines where whitelist entries are stored.
type ExceptionsConfig struct {
	Path    string `yaml:"path"`
	AgeDays int    `yaml:"age_days"`
}

// GeoIPConfig controls the offline country database used for request geolocation.
type GeoIPConfig struct {
	DBPath string `yaml:"db_path"`
}

// HooksConfig defines optional repository hook integration.
type HooksConfig struct {
	RequestScript  string                `yaml:"request_script"`
	TimeoutSeconds int                   `yaml:"timeout_seconds"`
	Trivial        TrivialHookConfig     `yaml:"trivial"`
	DockerLayer    DockerLayerHookConfig `yaml:"docker_layer"`
}

// DockerLayerHookConfig toggles container-image layer-level scanning (PR 7).
// Values may also be overridden at runtime via the CHAINSAW_DOCKER_LAYER_SCAN
// family of environment variables — see internal/hooks/docker_layer_scanner.go.
type DockerLayerHookConfig struct {
	// Mode is "on", "off" or "auto". Empty means "on" (the default).
	Mode string `yaml:"mode"`
	// SizeCapBytes is the image-size ceiling for auto-mode layer scanning.
	// Zero means the built-in default of 1 GiB.
	SizeCapBytes int64 `yaml:"size_cap_bytes"`
	// TimeoutSeconds bounds the per-image layer-scan wallclock. Zero means 60s.
	TimeoutSeconds int `yaml:"timeout_seconds"`
}

// ReleasePolicyConfig controls how Chainsaw treats recently published packages.
type ReleasePolicyConfig struct {
	// MinAgeDays blocks package downloads when the upstream release timestamp is newer
	// than the configured number of days. A value of zero disables the policy.
	MinAgeDays int `yaml:"min_age_days"`
}

// SwiftConfig controls Swift Package Manager (SE-0292) specific knobs.
// All fields are optional; zero values yield a registry-only proxy with
// no git translation.
type SwiftConfig struct {
	// GitFallbackEnabled turns on the git-to-registry translator. When
	// true, requests that miss the configured upstream (or when no
	// upstream is configured) are served by cloning github.com and
	// synthesizing SE-0292 responses from git tags.
	GitFallbackEnabled bool `yaml:"git_fallback_enabled"`
	// IdentifierMapPath is a YAML file mapping `scope.name` identifiers
	// to git clone URLs. See IdentifierMap documentation.
	IdentifierMapPath string `yaml:"identifier_map_path"`
	// GitCacheDir is the working directory for bare git clones. When
	// empty, a subdirectory of the OS temp directory is used.
	GitCacheDir string `yaml:"git_cache_dir"`
	// GitHubConvention auto-translates `scope.name` into
	// github.com/<scope>/<name>.git. Disabled by default because it
	// enables scope-squatting attacks unless combined with an allowlist.
	GitHubConvention bool `yaml:"github_convention"`
	// GitHubOrgAllowList restricts GitHubConvention to the listed scopes.
	GitHubOrgAllowList []string `yaml:"github_org_allowlist"`
	// TrustRootBundlePath is a PEM file of CA certificates used to
	// verify SE-0391 CMS signatures on .zip archives. When empty the
	// system trust store is used.
	TrustRootBundlePath string `yaml:"trust_root_bundle_path"`
	// TrustSwiftRoot, when true, adds Apple's Swift Package Collection
	// signing root to the verification trust pool. Currently a no-op —
	// the embedded root is not yet bundled.
	TrustSwiftRoot bool `yaml:"trust_swift_root"`
}

// TrivialHookConfig describes how to run the trivial scanner.
//
// The scanner now runs in-process against the trivy.db file chainsaw
// already syncs via internal/trivydb/updater.go. BinaryPath is retained
// only so existing YAML configs continue to parse; a warning is logged
// at startup if it is set (main.go: initTrivialScanner).
type TrivialHookConfig struct {
	// DBPath is the path to trivy.db (or a directory containing it).
	DBPath string `yaml:"db_path"`
	// TimeoutSeconds is the per-scan deadline. Default 10.
	TimeoutSeconds int `yaml:"timeout_seconds"`
	// MaxConcurrentScans caps concurrent in-process lookups.
	// 0 picks runtime.NumCPU()*4, capped at 64.
	MaxConcurrentScans int `yaml:"max_concurrent_scans,omitempty"`

	// Deprecated: ignored by the in-process scanner. Left so legacy
	// YAML files continue to parse without raising "unknown field".
	BinaryPath string `yaml:"binary_path,omitempty"`
}

// ClamAVConfig controls system-wide ClamAV artifact scanning.
type ClamAVConfig struct {
	Enabled        *bool  `yaml:"enabled"`
	SocketPath     string `yaml:"socket_path"`
	TimeoutSeconds int    `yaml:"timeout_seconds"`
	MaxStreamBytes int64  `yaml:"max_stream_bytes"`
}

// DataSourcesConfig controls automatic refresh of shared security feeds.
type DataSourcesConfig struct {
	OpenSSF  DataSourceRuntimeConfig `yaml:"openssf"`
	TrivyDB  DataSourceRuntimeConfig `yaml:"trivy_db"`
	EPSS     DataSourceRuntimeConfig `yaml:"epss"`
	ClamAVDB DataSourceRuntimeConfig `yaml:"clamav_db"`
}

// DataSourceRuntimeConfig defines refresh behavior for a shared datasource.
type DataSourceRuntimeConfig struct {
	Enabled                *bool `yaml:"enabled"`
	RefreshIntervalSeconds int   `yaml:"refresh_interval_seconds"`
	StartupSync            *bool `yaml:"startup_sync"`
	TimeoutSeconds         int   `yaml:"timeout_seconds"`
	JitterPercent          int   `yaml:"jitter_percent"`
}

// RepositoryConfig mirrors the Nexus Configuration entity at a high level.
type RepositoryConfig struct {
	Name                     string       `yaml:"name"`
	Format                   string       `yaml:"format"`
	Type                     string       `yaml:"type"`
	Enabled                  *bool        `yaml:"enabled"`
	AnonymousAccess          *bool        `yaml:"anonymous_access"`
	Remote                   RemoteConfig `yaml:"remote"`
	Cache                    CacheConfig  `yaml:"cache"`
	ClientConfigurationGuide string       `yaml:"client_configuration_guide"`
	// PublicBaseURL, when set, overrides the server-wide
	// CHAINSAW_REPO_BASE_URL / CHAINSAW_API_BASE_URL env vars when
	// rendering this repo's client-configuration guide. Use it when the
	// proxy is reachable under a different hostname than the dashboard
	// (e.g. dashboard on `internal.corp`, proxy on `artifacts.corp`).
	// Empty means "fall back to the global renderer".
	PublicBaseURL string `yaml:"public_base_url,omitempty"`
	// APT carries hosted-apt-specific knobs (suites, components,
	// architectures, Origin/Label cosmetic fields) for the metadata
	// generator. Ignored unless format=apt and type=hosted. Optional;
	// nil means "use apt.Default()".
	APT *APTRepoConfig `yaml:"apt,omitempty"`
	// Yum carries hosted-yum/dnf-specific knobs (Origin/Label/Description
	// cosmetic fields) for the rpmrepo metadata generator. Ignored unless
	// format ∈ {yum, dnf} and type=hosted. The (releasever, basearch)
	// portion of the repo layout is derived from the upload prefix at
	// regen time, not from this struct — this only carries display values
	// surfaced by `dnf repolist --verbose`. Optional; nil means
	// "use rpmrepo.Default()".
	Yum *YumRepoConfig `yaml:"yum,omitempty"`
}

// APTRepoConfig is the YAML schema for a hosted-apt repository's
// debian-metadata generator. Mirrors the fields of apt.Config — kept
// as a separate type so the YAML surface is tightly scoped (no risk
// of accidental coupling to internal apt-package types) and so YAML
// parsing errors point at this struct, not at apt.
type APTRepoConfig struct {
	Suites        []string `yaml:"suites"`
	Components    []string `yaml:"components"`
	Architectures []string `yaml:"architectures"`
	Origin        string   `yaml:"origin"`
	Label         string   `yaml:"label"`
	Codename      string   `yaml:"codename"`
	Description   string   `yaml:"description"`
}

// YumRepoConfig is the YAML schema for a hosted-yum/dnf repository's
// rpmrepo metadata generator. Mirrors the cosmetic fields of
// rpmrepo.Config — releasever / basearch live in the upload-path
// prefix (not here), so the surface here is the smaller display block.
type YumRepoConfig struct {
	Origin      string `yaml:"origin"`
	Label       string `yaml:"label"`
	Description string `yaml:"description"`
	Revision    string `yaml:"revision"`
}

// RemoteConfig defines the upstream remote repository.
type RemoteConfig struct {
	URL            string            `yaml:"url"`
	TimeoutSeconds int               `yaml:"timeout_seconds"`
	Headers        map[string]string `yaml:"headers"`
	ProxyURL       string            `yaml:"proxy_url"`
	SkipTLSVerify  bool              `yaml:"skip_tls_verify"`
}

// CacheConfig defines pull-through cache behaviour knobs.
type CacheConfig struct {
	NegativeTTLSeconds int `yaml:"negative_ttl_seconds"`
}

// RemoteDefaults defines fallback remote URLs per format.
type RemoteDefaults struct {
	URL            string            `yaml:"url"`
	TimeoutSeconds int               `yaml:"timeout_seconds"`
	Headers        map[string]string `yaml:"headers"`
}

// Load reads the YAML config file from disk and applies defaults.
func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config: %w", err)
	}
	defer f.Close()
	return parse(f, filepath.Dir(path))
}

func parse(r io.Reader, baseDir string) (*Config, error) {
	var cfg Config
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	// Capture which runtime-managed keys the YAML explicitly declared
	// BEFORE applyDefaults fills the nil pointers — otherwise the
	// seed-if-absent guards in SaveToStore can't tell "operator omitted it"
	// from "operator set false", and a bare YAML clobbers UI/API-set values.
	cfg.captureExplicitRuntimeKeys()
	cfg.applyDefaults(baseDir)
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults(baseDir string) {
	if baseDir == "" {
		baseDir = defaultBaseDir()
	}
	baseDir = filepath.Clean(baseDir)
	if c.BlockingMode == nil {
		defaultBlocking := true
		c.BlockingMode = &defaultBlocking
	}
	c.Server.Listen = strings.TrimSpace(c.Server.Listen)
	if c.Server.Listen == "" {
		c.Server.Listen = ":8787"
	}
	c.Server.Admin.Username = strings.TrimSpace(c.Server.Admin.Username)
	if c.Server.Admin.Username == "" {
		c.Server.Admin.Username = defaultAdminUsername
	}
	c.Server.TLS.CertFile = strings.TrimSpace(c.Server.TLS.CertFile)
	c.Server.TLS.KeyFile = strings.TrimSpace(c.Server.TLS.KeyFile)
	c.Server.TLS.MinVersion = strings.TrimSpace(c.Server.TLS.MinVersion)
	if c.Server.TLS.MinVersion == "" {
		c.Server.TLS.MinVersion = "1.2"
	}
	if c.BlobStore.Root == "" {
		c.BlobStore.Root = filepath.Join(baseDir, "..", "data", "blobs")
	}
	c.BlobStore.Root = filepath.Clean(c.BlobStore.Root)
	if c.Index.Path == "" {
		c.Index.Path = filepath.Join(baseDir, "..", "data", "index.json")
	}
	c.Index.Path = filepath.Clean(c.Index.Path)
	if c.Exceptions.Path == "" {
		c.Exceptions.Path = filepath.Join(baseDir, "..", "data", "exceptions.json")
	}
	c.Exceptions.Path = filepath.Clean(c.Exceptions.Path)
	if c.GeoIP.DBPath != "" {
		c.GeoIP.DBPath = absolutize(baseDir, c.GeoIP.DBPath)
	}
	if c.Hooks.RequestScript != "" {
		if filepath.IsAbs(c.Hooks.RequestScript) {
			c.Hooks.RequestScript = filepath.Clean(c.Hooks.RequestScript)
		} else {
			c.Hooks.RequestScript = filepath.Clean(filepath.Join(baseDir, c.Hooks.RequestScript))
		}
	}
	if c.Hooks.TimeoutSeconds == 0 {
		c.Hooks.TimeoutSeconds = 5
	}
	if c.Hooks.Trivial.BinaryPath != "" {
		c.Hooks.Trivial.BinaryPath = absolutize(baseDir, c.Hooks.Trivial.BinaryPath)
	}
	if c.Hooks.Trivial.DBPath != "" {
		c.Hooks.Trivial.DBPath = absolutize(baseDir, c.Hooks.Trivial.DBPath)
	}
	if c.Hooks.Trivial.TimeoutSeconds == 0 {
		c.Hooks.Trivial.TimeoutSeconds = c.Hooks.TimeoutSeconds
		if c.Hooks.Trivial.TimeoutSeconds == 0 {
			c.Hooks.Trivial.TimeoutSeconds = 10
		}
	}
	// CHAINSAW_OFFLINE=1 flips the default for every data-source
	// startup_sync knob to false. Explicit YAML `startup_sync: true`
	// still wins — an operator who deliberately staged a local mirror
	// and wants to hit it on boot can opt back in — but the ergonomic
	// default stops the server from trying to reach GitHub / Aqua /
	// Cyentia on first boot. See tutorial 44. We run this BEFORE each
	// sub-config's applyDefaults so only explicitly-set StartupSync
	// pointers (non-nil) survive: nil gets populated with `false`.
	if c.IsOffline() {
		off := false
		if c.DataSources.OpenSSF.StartupSync == nil {
			c.DataSources.OpenSSF.StartupSync = &off
		}
		if c.DataSources.TrivyDB.StartupSync == nil {
			c.DataSources.TrivyDB.StartupSync = &off
		}
		if c.DataSources.EPSS.StartupSync == nil {
			c.DataSources.EPSS.StartupSync = &off
		}
		if c.DataSources.ClamAVDB.StartupSync == nil {
			c.DataSources.ClamAVDB.StartupSync = &off
		}
	}
	// Couple signature-DB sync to scanning. If the operator explicitly turns
	// ClamAV scanning on (clamav.enabled=true) but leaves the freshclam refresh
	// data source unset (data_sources.clamav_db.enabled is nil), enable the sync
	// so clamd scans against current definitions instead of a stale/empty DB —
	// the "looks on, never really scans" bug. An explicit clamav_db.enabled=false
	// is respected (operator opted out, e.g. air-gapped bundle refresh). Runs
	// BEFORE ClamAVDB.applyDefaults so the nil sentinel is still observable, and
	// AFTER the offline block so air-gapped StartupSync stays off.
	if c.ClamAV.Enabled != nil && *c.ClamAV.Enabled && c.DataSources.ClamAVDB.Enabled == nil {
		on := true
		c.DataSources.ClamAVDB.Enabled = &on
		// Do NOT block boot on the freshclam startup-sync. clamd already loads
		// signatures at container start (start.sh runs freshclam), so the
		// in-app startup-sync is a periodic refresh, not a boot prerequisite.
		// Defaulting it on would make the readiness gate hang on egress-
		// restricted clusters that can't reach the ClamAV mirror — observed on
		// chain305: a clamav-enabled pod stayed unready for 13m on the shared
		// data-source loader while a clamav-off pod readied in 50s. Only force
		// it off when the operator hasn't explicitly chosen.
		if c.DataSources.ClamAVDB.StartupSync == nil {
			off := false
			c.DataSources.ClamAVDB.StartupSync = &off
		}
	}
	c.ClamAV.applyDefaults(defaultClamAVConfig())
	c.DataSources.OpenSSF.applyDefaults(defaultOpenSSFDataSourceConfig())
	c.DataSources.TrivyDB.applyDefaults(defaultTrivyDBDataSourceConfig())
	c.DataSources.EPSS.applyDefaults(defaultEPSSDataSourceConfig())
	c.DataSources.ClamAVDB.applyDefaults(defaultClamAVDBDataSourceConfig())
	c.Hooks.DockerLayer.Mode = strings.ToLower(strings.TrimSpace(c.Hooks.DockerLayer.Mode))
	if c.Hooks.DockerLayer.Mode == "" {
		c.Hooks.DockerLayer.Mode = "on"
	}
	if c.Hooks.DockerLayer.TimeoutSeconds == 0 {
		c.Hooks.DockerLayer.TimeoutSeconds = 60
	}
	if c.Hooks.DockerLayer.SizeCapBytes == 0 {
		c.Hooks.DockerLayer.SizeCapBytes = 1 << 30 // 1 GiB
	}
	if c.ReleasePolicy.MinAgeDays < 0 {
		c.ReleasePolicy.MinAgeDays = 0
	}
	if c.RepositoryAnonymousAccess == nil {
		defaultAnonymous := false
		c.RepositoryAnonymousAccess = &defaultAnonymous
	}
	if c.HTTPClient.TimeoutSeconds == 0 {
		c.HTTPClient.TimeoutSeconds = 60
	}
	if c.HTTPClient.MaxIdleConns == 0 {
		c.HTTPClient.MaxIdleConns = 64
	}
	if c.Policy.EvalCacheTTLSeconds == nil {
		def := defaultPolicyEvalCacheTTLSeconds
		c.Policy.EvalCacheTTLSeconds = &def
	}
	if c.Remotes == nil {
		c.Remotes = map[string]RemoteDefaults{}
	}
	for format, def := range builtinRemoteDefaults {
		if _, exists := c.Remotes[format]; !exists {
			c.Remotes[format] = def
		}
	}
	for i := range c.Repositories {
		c.Repositories[i].normalize(c.Remotes)
	}
	if len(c.Repositories) == 0 {
		c.Repositories = cloneRepositoryConfigs(builtinRepositories)
		for i := range c.Repositories {
			c.Repositories[i].normalize(c.Remotes)
		}
	}
}

func (c *Config) validate() error {
	if len(c.Repositories) == 0 {
		return errors.New("at least one repository must be configured")
	}
	if err := c.DataSources.OpenSSF.validate("data_sources.openssf"); err != nil {
		return err
	}
	if err := c.DataSources.TrivyDB.validate("data_sources.trivy_db"); err != nil {
		return err
	}
	if err := c.DataSources.EPSS.validate("data_sources.epss"); err != nil {
		return err
	}
	if err := c.DataSources.ClamAVDB.validate("data_sources.clamav_db"); err != nil {
		return err
	}
	if err := c.ClamAV.validate(); err != nil {
		return err
	}
	if strings.TrimSpace(c.Server.Admin.Username) == "" {
		return errors.New("server admin username is required")
	}
	if err := c.Server.TLS.Validate(); err != nil {
		return err
	}
	for _, repo := range c.Repositories {
		remoteURL := strings.TrimSpace(repo.Remote.URL)
		if remoteURL == "" {
			if strings.EqualFold(repo.Type, "raw") {
				continue
			}
			return fmt.Errorf("repository %q missing remote.url", repo.Name)
		}
		if _, err := url.Parse(remoteURL); err != nil {
			return fmt.Errorf("repository %q has invalid remote.url: %w", repo.Name, err)
		}
	}
	return nil
}

func (r *RepositoryConfig) normalize(remotes map[string]RemoteDefaults) {
	r.Name = strings.TrimSpace(r.Name)
	r.Format = strings.ToLower(strings.TrimSpace(r.Format))
	r.Type = strings.ToLower(strings.TrimSpace(r.Type))
	if r.Type == "" {
		r.Type = "proxy"
	}
	// "raw" is a legacy synonym retained for backward compatibility with
	// older configs that pre-date the proxy/hosted/group taxonomy.
	switch r.Type {
	case "proxy", "hosted", "group", "raw":
	default:
		r.Type = "proxy"
	}
	if r.Enabled == nil {
		defaultEnabled := true
		r.Enabled = &defaultEnabled
	}
	if r.Cache.NegativeTTLSeconds == 0 {
		r.Cache.NegativeTTLSeconds = 300
	}
	if r.Remote.URL == "" && !strings.EqualFold(r.Type, "raw") {
		if def, ok := remotes[r.Format]; ok {
			r.Remote.URL = def.URL
			if r.Remote.TimeoutSeconds == 0 {
				r.Remote.TimeoutSeconds = def.TimeoutSeconds
			}
			if len(r.Remote.Headers) == 0 && len(def.Headers) > 0 {
				r.Remote.Headers = cloneMap(def.Headers)
			}
		}
	}
	if r.Remote.TimeoutSeconds == 0 {
		r.Remote.TimeoutSeconds = 60
	}
}

// EnabledValue returns the normalized on/off state for the repository.
func (r RepositoryConfig) EnabledValue() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// AnonymousAccessValue returns the normalized anonymous access state for the repository.
func (r RepositoryConfig) AnonymousAccessValue() bool {
	if r.AnonymousAccess == nil {
		return false
	}
	return *r.AnonymousAccess
}

// NegativeTTL returns the configured negative cache TTL.
func (r RepositoryConfig) NegativeTTL() time.Duration {
	return time.Duration(r.Cache.NegativeTTLSeconds) * time.Second
}

func cloneMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	cp := make(map[string]string, len(m))
	for k, v := range m {
		cp[k] = v
	}
	return cp
}

func defaultOpenSSFDataSourceConfig() DataSourceRuntimeConfig {
	return DataSourceRuntimeConfig{
		Enabled:                boolPtr(true),
		RefreshIntervalSeconds: int((6 * time.Hour).Seconds()),
		StartupSync:            boolPtr(true),
		TimeoutSeconds:         int((5 * time.Minute).Seconds()),
		JitterPercent:          10,
	}
}

func defaultTrivyDBDataSourceConfig() DataSourceRuntimeConfig {
	return DataSourceRuntimeConfig{
		Enabled:                boolPtr(true),
		RefreshIntervalSeconds: int((6 * time.Hour).Seconds()),
		StartupSync:            boolPtr(true),
		TimeoutSeconds:         int((10 * time.Minute).Seconds()),
		JitterPercent:          10,
	}
}

func defaultEPSSDataSourceConfig() DataSourceRuntimeConfig {
	return DataSourceRuntimeConfig{
		Enabled:                boolPtr(true),
		RefreshIntervalSeconds: int((24 * time.Hour).Seconds()),
		StartupSync:            boolPtr(true),
		TimeoutSeconds:         int((2 * time.Minute).Seconds()),
		JitterPercent:          10,
	}
}

func defaultClamAVConfig() ClamAVConfig {
	return ClamAVConfig{
		Enabled:        boolPtr(false),
		SocketPath:     "/tmp/clamd.socket",
		TimeoutSeconds: 60,
		MaxStreamBytes: 512 << 20,
	}
}

func defaultClamAVDBDataSourceConfig() DataSourceRuntimeConfig {
	return DataSourceRuntimeConfig{
		Enabled:                boolPtr(false),
		RefreshIntervalSeconds: int((6 * time.Hour).Seconds()),
		StartupSync:            boolPtr(true),
		TimeoutSeconds:         int((5 * time.Minute).Seconds()),
		JitterPercent:          10,
	}
}

func (c *ClamAVConfig) applyDefaults(defaults ClamAVConfig) {
	if c.Enabled == nil {
		c.Enabled = defaults.Enabled
	}
	c.SocketPath = strings.TrimSpace(c.SocketPath)
	if c.SocketPath == "" {
		c.SocketPath = defaults.SocketPath
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = defaults.TimeoutSeconds
	}
	if c.MaxStreamBytes <= 0 {
		c.MaxStreamBytes = defaults.MaxStreamBytes
	}
}

func (c ClamAVConfig) validate() error {
	return c.ValidateForRuntime()
}

// ValidateForRuntime validates ClamAV settings after runtime edits.
func (c ClamAVConfig) ValidateForRuntime() error {
	if c.EnabledValue() && strings.TrimSpace(c.SocketPath) == "" {
		return errors.New("clamav.socket_path is required when clamav is enabled")
	}
	if c.TimeoutSeconds <= 0 {
		return errors.New("clamav.timeout_seconds must be greater than zero")
	}
	if c.MaxStreamBytes <= 0 {
		return errors.New("clamav.max_stream_bytes must be greater than zero")
	}
	return nil
}

func (c ClamAVConfig) EnabledValue() bool {
	if c.Enabled == nil {
		return false
	}
	return *c.Enabled
}

func (c *DataSourceRuntimeConfig) applyDefaults(defaults DataSourceRuntimeConfig) {
	if c.Enabled == nil {
		c.Enabled = defaults.Enabled
	}
	if c.RefreshIntervalSeconds <= 0 {
		c.RefreshIntervalSeconds = defaults.RefreshIntervalSeconds
	}
	if c.StartupSync == nil {
		c.StartupSync = defaults.StartupSync
	}
	if c.TimeoutSeconds <= 0 {
		c.TimeoutSeconds = defaults.TimeoutSeconds
	}
	if c.JitterPercent <= 0 {
		c.JitterPercent = defaults.JitterPercent
	}
}

func (c DataSourceRuntimeConfig) validate(prefix string) error {
	if c.RefreshIntervalSeconds <= 0 {
		return fmt.Errorf("%s.refresh_interval_seconds must be greater than zero", prefix)
	}
	if c.TimeoutSeconds <= 0 {
		return fmt.Errorf("%s.timeout_seconds must be greater than zero", prefix)
	}
	if c.JitterPercent < 0 || c.JitterPercent > 100 {
		return fmt.Errorf("%s.jitter_percent must be between 0 and 100", prefix)
	}
	return nil
}

// EnabledValue returns the normalized enabled state for a datasource.
func (c DataSourceRuntimeConfig) EnabledValue() bool {
	if c.Enabled == nil {
		return true
	}
	return *c.Enabled
}

// StartupSyncValue returns whether startup sync is enabled for a datasource.
func (c DataSourceRuntimeConfig) StartupSyncValue() bool {
	if c.StartupSync == nil {
		return true
	}
	return *c.StartupSync
}

func absolutize(baseDir, p string) string {
	if p == "" {
		return ""
	}
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Clean(filepath.Join(baseDir, p))
}

var builtinRemoteDefaults = map[string]RemoteDefaults{
	"apt": {
		URL:            "https://archive.ubuntu.com/ubuntu/",
		TimeoutSeconds: 60,
	},
	"pip": {
		URL:            "https://pypi.org/",
		TimeoutSeconds: 60,
	},
	"npm": {
		URL:            "https://registry.npmjs.org",
		TimeoutSeconds: 60,
	},
	"yarn": {
		URL:            "https://registry.yarnpkg.com",
		TimeoutSeconds: 60,
	},
	"bun": {
		URL:            "https://registry.npmjs.org",
		TimeoutSeconds: 60,
	},
	"maven": {
		URL:            "https://repo.maven.apache.org/maven2",
		TimeoutSeconds: 60,
	},
	"nuget": {
		URL:            "https://api.nuget.org/v3-flatcontainer/",
		TimeoutSeconds: 60,
	},
	"composer": {
		URL:            "https://repo.packagist.org/",
		TimeoutSeconds: 60,
	},
	"rubygems": {
		URL:            "https://rubygems.org/",
		TimeoutSeconds: 60,
	},
	"cargo": {
		URL:            "https://index.crates.io/",
		TimeoutSeconds: 60,
	},
	"cocoapods": {
		URL:            "https://cdn.cocoapods.org/",
		TimeoutSeconds: 60,
	},
	"docker": {
		URL:            "https://registry-1.docker.io",
		TimeoutSeconds: 60,
	},
	"dnf": {
		URL:            "https://mirrors.edge.kernel.org/centos",
		TimeoutSeconds: 60,
	},
	"go": {
		URL:            "https://proxy.golang.org",
		TimeoutSeconds: 60,
	},
	"gradle": {
		URL:            "https://repo.maven.apache.org/maven2",
		TimeoutSeconds: 60,
	},
	"huggingface": {
		URL:            "https://huggingface.co",
		TimeoutSeconds: 120,
	},
	"yum": {
		URL:            "https://mirrors.edge.kernel.org/centos",
		TimeoutSeconds: 60,
	},
}

var builtinRepositories = []RepositoryConfig{
	{
		Name:   "apt-main",
		Format: "apt",
		Type:   "proxy",
		Cache:  CacheConfig{NegativeTTLSeconds: 1800},
	},
	{
		Name:   "maven-central",
		Format: "maven",
		Type:   "proxy",
		Cache:  CacheConfig{NegativeTTLSeconds: 900},
	},
	{
		Name:   "npmjs",
		Format: "npm",
		Type:   "proxy",
		Cache:  CacheConfig{NegativeTTLSeconds: 600},
	},
	{
		Name:   "pypi",
		Format: "pip",
		Type:   "proxy",
		Cache:  CacheConfig{NegativeTTLSeconds: 600},
	},
	{
		Name:   "nuget-official",
		Format: "nuget",
		Type:   "proxy",
		Cache:  CacheConfig{NegativeTTLSeconds: 900},
	},
	{
		Name:   "packagist",
		Format: "composer",
		Type:   "proxy",
		Cache:  CacheConfig{NegativeTTLSeconds: 600},
	},
	{
		Name:   "rubygems",
		Format: "rubygems",
		Type:   "proxy",
		Cache:  CacheConfig{NegativeTTLSeconds: 600},
	},
	{
		Name:   "crates-io",
		Format: "cargo",
		Type:   "proxy",
		Cache:  CacheConfig{NegativeTTLSeconds: 600},
	},
	{
		Name:   "docker-hub",
		Format: "docker",
		Type:   "proxy",
		Cache:  CacheConfig{NegativeTTLSeconds: 300},
	},
	{
		Name:   "gomod",
		Format: "go",
		Type:   "proxy",
		Cache:  CacheConfig{NegativeTTLSeconds: 600},
	},
	{
		Name:            "huggingface",
		Format:          "huggingface",
		Type:            "proxy",
		AnonymousAccess: boolPtr(true),
		Cache:           CacheConfig{NegativeTTLSeconds: 600},
	},
	{
		Name:   "dnf-baseos",
		Format: "dnf",
		Type:   "proxy",
		Cache:  CacheConfig{NegativeTTLSeconds: 1200},
	},
	{
		Name:   "yum-base",
		Format: "yum",
		Type:   "proxy",
		Cache:  CacheConfig{NegativeTTLSeconds: 1200},
	},
	{
		Name:   "gradle-central",
		Format: "gradle",
		Type:   "proxy",
		Cache:  CacheConfig{NegativeTTLSeconds: 900},
	},
	{
		Name:   "google-maven",
		Format: "gradle",
		Type:   "proxy",
		Remote: RemoteConfig{URL: "https://dl.google.com/dl/android/maven2/"},
		Cache:  CacheConfig{NegativeTTLSeconds: 900},
	},
	{
		Name:   "gradle-plugins",
		Format: "gradle",
		Type:   "proxy",
		Remote: RemoteConfig{URL: "https://plugins.gradle.org/m2/"},
		Cache:  CacheConfig{NegativeTTLSeconds: 900},
	},
	{
		Name:   "cocoapods-trunk",
		Format: "cocoapods",
		Type:   "proxy",
		Cache:  CacheConfig{NegativeTTLSeconds: 600},
	},
}

// BlockingEnabled reports whether the proxy should reject hook violations.
func (c *Config) BlockingEnabled() bool {
	if c == nil || c.BlockingMode == nil {
		return true
	}
	return *c.BlockingMode
}

// CoverageEnabled reports whether the opt-in coverage-reporting feature
// is on. Nil-safe: a nil *Config returns false so the off path stays
// dark in tests and partial-construction code paths.
func (c *Config) CoverageEnabled() bool {
	if c == nil {
		return false
	}
	return c.Coverage.IsEnabled()
}

// AnonymousRepositoryAccess reports whether repository routes allow unauthenticated access.
func (c *Config) AnonymousRepositoryAccess() bool {
	if c == nil || c.RepositoryAnonymousAccess == nil {
		return true
	}
	return *c.RepositoryAnonymousAccess
}

// ReleaseMinAgeDays returns the minimum release age (in days) required before packages
// are allowed to download. Zero disables the policy.
func (c *Config) ReleaseMinAgeDays() int {
	if c == nil {
		return 0
	}
	if c.ReleasePolicy.MinAgeDays < 0 {
		return 0
	}
	return c.ReleasePolicy.MinAgeDays
}

// PolicyEvalCacheTTL returns the configured evaluation cache TTL as a
// duration. A zero return means "cache disabled" and callers must NOT
// call evaluator.WithEvalCache (which would otherwise resurrect the
// default). applyDefaults populates a 60s default when the YAML leaves
// the field unset, so callers only see 0 when an operator explicitly
// opted out.
func (c *Config) PolicyEvalCacheTTL() time.Duration {
	if c == nil || c.Policy.EvalCacheTTLSeconds == nil {
		return time.Duration(defaultPolicyEvalCacheTTLSeconds) * time.Second
	}
	secs := *c.Policy.EvalCacheTTLSeconds
	if secs <= 0 {
		return 0
	}
	return time.Duration(secs) * time.Second
}

// ExceptionAgeDays returns the exception expiry age (in days). Zero disables expiry.
func (c *Config) ExceptionAgeDays() int {
	if c == nil {
		return 0
	}
	if c.Exceptions.AgeDays < 0 {
		return 0
	}
	return c.Exceptions.AgeDays
}

func cloneRepositoryConfigs(src []RepositoryConfig) []RepositoryConfig {
	if len(src) == 0 {
		return nil
	}
	out := make([]RepositoryConfig, len(src))
	for i, cfg := range src {
		out[i] = cloneRepositoryConfig(cfg)
	}
	return out
}

func cloneRepositoryConfig(cfg RepositoryConfig) RepositoryConfig {
	cp := cfg
	if cfg.Enabled != nil {
		value := *cfg.Enabled
		cp.Enabled = &value
	}
	cp.Remote = cloneRemoteConfig(cfg.Remote)
	return cp
}

func cloneRemoteConfig(cfg RemoteConfig) RemoteConfig {
	cp := cfg
	if len(cfg.Headers) > 0 {
		cp.Headers = cloneMap(cfg.Headers)
	}
	return cp
}
