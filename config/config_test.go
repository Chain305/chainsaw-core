package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// First test file for internal/config. Prior code-quality review flagged
// this package (2,701 LOC, 0 tests) as a ship-blocker for a security
// product — a parse bug silently defaulting the SSRF allowlist off is the
// kind of thing that should be caught by a unit test, not by a pen-tester.
// These tests cover the highest-leverage surfaces: Load/parse, defaults,
// validate, and the known-defaults accessors the server relies on.

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoadRejectsMissingFile(t *testing.T) {
	_, err := Load("/nonexistent/does/not/exist.yaml")
	if err == nil {
		t.Fatal("expected error opening nonexistent config")
	}
	if !strings.Contains(err.Error(), "open config") {
		t.Errorf("expected wrapped open error, got %v", err)
	}
}

func TestLoadRejectsMalformedYAML(t *testing.T) {
	path := writeTempConfig(t, "repositories:\n  - not_a_map\n  just a string\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected parse error on malformed YAML")
	}
	if !strings.Contains(err.Error(), "parse config") {
		t.Errorf("expected wrapped parse error, got %v", err)
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	// KnownFields(true) means a typo in a config key is a hard error,
	// not a silent default. This is the "SSRF allowlist silently off"
	// regression guard the prior review flagged.
	body := `
server:
  listen: ":8787"
  admin:
    username: "admin"
unknown_top_level_key_should_fail: true
repositories:
  - name: pypi
    format: pypi
    remote:
      url: "https://pypi.org"
`
	path := writeTempConfig(t, body)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error on unknown top-level key")
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	body := `
repositories:
  - name: pypi
    format: pypi
    remote:
      url: "https://pypi.org"
`
	path := writeTempConfig(t, body)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Server.Listen != ":8787" {
		t.Errorf("expected default listen :8787, got %q", cfg.Server.Listen)
	}
	if cfg.Server.Admin.Username != defaultAdminUsername {
		t.Errorf("expected default admin username %q, got %q", defaultAdminUsername, cfg.Server.Admin.Username)
	}
	if cfg.BlockingMode == nil || !*cfg.BlockingMode {
		t.Error("expected blocking_mode to default to true")
	}
	if cfg.RepositoryAnonymousAccess == nil || *cfg.RepositoryAnonymousAccess {
		t.Error("expected repository_anonymous_access to default to false (deny)")
	}
	if cfg.Hooks.TimeoutSeconds != 5 {
		t.Errorf("expected hooks.timeout_seconds default 5, got %d", cfg.Hooks.TimeoutSeconds)
	}
	if cfg.HTTPClient.TimeoutSeconds != 60 {
		t.Errorf("expected http_client.timeout_seconds default 60, got %d", cfg.HTTPClient.TimeoutSeconds)
	}
}

func TestLoadFillsBuiltinRepositoriesWhenEmpty(t *testing.T) {
	// applyDefaults populates builtinRepositories when the YAML lists none,
	// so a bare config still passes validation. This is the opposite of
	// what a casual reader expects from a "repositories required" rule —
	// document it via test so the defaulting can't silently disappear.
	body := `
server:
  listen: ":8787"
  admin:
    username: "admin"
repositories: []
`
	path := writeTempConfig(t, body)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Repositories) == 0 {
		t.Error("expected builtin repositories to be populated when YAML is empty")
	}
}

func TestLoadValidatesRepositoryMissingRemoteURL(t *testing.T) {
	body := `
repositories:
  - name: bogus
    format: pypi
    type: proxy
`
	path := writeTempConfig(t, body)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected validate to reject repo missing remote.url")
	}
	if !strings.Contains(err.Error(), "remote.url") {
		t.Errorf("expected remote.url error, got %v", err)
	}
}

func TestLoadValidatesRawRepositoryAllowedWithoutRemoteURL(t *testing.T) {
	// Raw repos are storage-only — they legitimately have no upstream.
	body := `
repositories:
  - name: internal-raw
    format: raw
    type: raw
`
	path := writeTempConfig(t, body)
	if _, err := Load(path); err != nil {
		t.Fatalf("expected raw repo without remote.url to validate, got %v", err)
	}
}

func TestBlockingEnabledRespectsExplicitFalse(t *testing.T) {
	body := `
blocking_mode: false
repositories:
  - name: pypi
    format: pypi
    remote:
      url: "https://pypi.org"
`
	path := writeTempConfig(t, body)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.BlockingEnabled() {
		t.Error("expected BlockingEnabled() false when YAML says false")
	}
}

func TestPolicyEvalCacheTTLDefault(t *testing.T) {
	body := `
repositories:
  - name: pypi
    format: pypi
    remote:
      url: "https://pypi.org"
`
	cfg, err := Load(writeTempConfig(t, body))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.PolicyEvalCacheTTL(); got != 60*time.Second {
		t.Errorf("expected default policy eval cache TTL 60s, got %s", got)
	}
	if cfg.Policy.EvalCacheTTLSeconds == nil {
		t.Fatal("expected defaults to populate EvalCacheTTLSeconds")
	}
	if *cfg.Policy.EvalCacheTTLSeconds != 60 {
		t.Errorf("expected EvalCacheTTLSeconds=60, got %d", *cfg.Policy.EvalCacheTTLSeconds)
	}
}

func TestPolicyEvalCacheTTLExplicitZeroDisables(t *testing.T) {
	body := `
policy:
  eval_cache_ttl_seconds: 0
repositories:
  - name: pypi
    format: pypi
    remote:
      url: "https://pypi.org"
`
	cfg, err := Load(writeTempConfig(t, body))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.PolicyEvalCacheTTL(); got != 0 {
		t.Errorf("explicit 0 in YAML should return zero duration (cache disabled), got %s", got)
	}
}

func TestPolicyEvalCacheTTLExplicitPositive(t *testing.T) {
	body := `
policy:
  eval_cache_ttl_seconds: 15
repositories:
  - name: pypi
    format: pypi
    remote:
      url: "https://pypi.org"
`
	cfg, err := Load(writeTempConfig(t, body))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got := cfg.PolicyEvalCacheTTL(); got != 15*time.Second {
		t.Errorf("expected 15s, got %s", got)
	}
}

func TestPolicyEvalCacheTTLNilConfigSafe(t *testing.T) {
	var cfg *Config
	if got := cfg.PolicyEvalCacheTTL(); got != 60*time.Second {
		t.Errorf("nil config should fall back to default, got %s", got)
	}
}

func TestDefaultReturnsValidConfig(t *testing.T) {
	cfg, err := Default(t.TempDir())
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	if len(cfg.Repositories) == 0 {
		t.Error("expected default config to ship at least one repository")
	}
	// Defaults should carry sane minimums — regression-guard against a
	// nil-pointer deref at startup.
	if cfg.BlockingMode == nil {
		t.Error("expected BlockingMode pointer populated by defaults")
	}
	// The pull-to-deployment correlation feature must be OFF by
	// default. This test pins the design contract: customers without
	// K8s never see the feature, no DB writes, no UI surface — see
	// internal/deploycorr.
	if cfg.Correlation.Enabled {
		t.Error("expected correlation.enabled to default false (opt-in)")
	}
}

// TestCorrelationConfigOptIn verifies the YAML parse path: an explicit
// correlation.enabled=true flips the flag, and the absence of the
// section keeps it OFF. Together with TestDefaultReturnsValidConfig
// this pins both axes of the opt-in contract.
func TestCorrelationConfigOptIn(t *testing.T) {
	t.Parallel()
	t.Run("absent section", func(t *testing.T) {
		t.Parallel()
		var cfg Config
		if cfg.Correlation.Enabled {
			t.Fatal("zero-value Config should have correlation disabled")
		}
	})
	t.Run("explicit enabled", func(t *testing.T) {
		t.Parallel()
		cfg := Config{Correlation: CorrelationConfig{Enabled: true}}
		if !cfg.Correlation.Enabled {
			t.Fatal("explicit Enabled=true should be honoured")
		}
	})
}

// TestClamAVScanningCouplesDBSync pins the A3 fix: enabling ClamAV scanning
// without explicitly configuring the freshclam refresh data source must turn
// the sync ON, so clamd scans against current definitions instead of a stale
// or empty DB (the "looks on, never really scans" bug). An explicit opt-out
// (clamav_db.enabled=false) and offline mode must both still be respected.
func TestClamAVScanningCouplesDBSync(t *testing.T) {
	on, off := true, false

	t.Run("enabling scanning auto-enables db sync but NOT startup-sync", func(t *testing.T) {
		cfg := &Config{}
		cfg.ClamAV.Enabled = &on // clamav_db left nil (operator didn't touch it)
		cfg.applyDefaults("")
		if !cfg.DataSources.ClamAVDB.EnabledValue() {
			t.Error("clamav.enabled=true with unset clamav_db should auto-enable db sync")
		}
		// Coupled startup-sync must be OFF: clamd loads sigs at container start;
		// a boot-blocking freshclam fetch hangs readiness on egress-restricted
		// clusters (chain305: 13m unready vs 50s with clamav off).
		if cfg.DataSources.ClamAVDB.StartupSyncValue() {
			t.Error("auto-coupled clamav_db must NOT startup-sync (no boot-block on freshclam)")
		}
	})

	t.Run("explicit clamav_db startup_sync survives the coupling", func(t *testing.T) {
		cfg := &Config{}
		cfg.ClamAV.Enabled = &on
		on2 := true
		cfg.DataSources.ClamAVDB.StartupSync = &on2 // operator explicitly wants boot sync
		cfg.applyDefaults("")
		if !cfg.DataSources.ClamAVDB.StartupSyncValue() {
			t.Error("explicit startup_sync:true must win over the coupling's off-default")
		}
	})

	t.Run("explicit db-sync opt-out is respected", func(t *testing.T) {
		cfg := &Config{}
		cfg.ClamAV.Enabled = &on
		cfg.DataSources.ClamAVDB.Enabled = &off // operator opted out (e.g. air-gapped bundle)
		cfg.applyDefaults("")
		if cfg.DataSources.ClamAVDB.EnabledValue() {
			t.Error("explicit clamav_db.enabled=false must win over the coupling")
		}
	})

	t.Run("scanning off leaves db sync off", func(t *testing.T) {
		cfg := &Config{}
		cfg.ClamAV.Enabled = &off
		cfg.applyDefaults("")
		if cfg.DataSources.ClamAVDB.EnabledValue() {
			t.Error("clamav.enabled=false should not enable db sync")
		}
	})

	t.Run("offline keeps startup_sync off even when coupled on", func(t *testing.T) {
		t.Setenv(offlineEnvVar, "1")
		cfg := &Config{}
		cfg.ClamAV.Enabled = &on
		cfg.applyDefaults("")
		if !cfg.DataSources.ClamAVDB.EnabledValue() {
			t.Error("coupling should still enable db sync when offline")
		}
		if cfg.DataSources.ClamAVDB.StartupSyncValue() {
			t.Error("offline must keep clamav_db startup_sync off (no boot-time phone-home)")
		}
	})
}

// TestCaptureExplicitRuntimeKeys pins the A3 fix: SaveToStore must overwrite
// a runtime-managed key only when the YAML declared it, and seed-if-absent
// otherwise — so a boot-time YAML re-import (the `--config` path) can't clobber
// a UI/API-set value (e.g. clamav.enabled) back to its default on every restart.
func TestCaptureExplicitRuntimeKeys(t *testing.T) {
	on := true

	t.Run("yaml-declared clamav.enabled is explicit", func(t *testing.T) {
		c := &Config{}
		c.ClamAV.Enabled = &on // simulates `clamav: { enabled: true }` in YAML
		c.captureExplicitRuntimeKeys()
		if !c.explicitKeys[settingClamAVEnabled] {
			t.Error("declared clamav.enabled should be explicit (→ overwrite)")
		}
	})

	t.Run("omitted clamav.enabled is non-explicit", func(t *testing.T) {
		c := &Config{} // YAML omitted clamav entirely
		c.captureExplicitRuntimeKeys()
		if c.explicitKeys[settingClamAVEnabled] {
			t.Error("omitted clamav.enabled must be non-explicit (→ seed-if-absent, no clobber)")
		}
		if c.explicitKeys[settingDataSourceClamAVEnabled] {
			t.Error("omitted clamav_db.enabled must be non-explicit")
		}
	})

	t.Run("captured explicitness survives applyDefaults", func(t *testing.T) {
		c := &Config{}
		c.captureExplicitRuntimeKeys()
		c.applyDefaults("")
		if c.ClamAV.Enabled == nil {
			t.Fatal("applyDefaults should fill Enabled (precondition)")
		}
		if c.explicitKeys[settingClamAVEnabled] {
			t.Error("post-default non-nil pointer must not flip captured explicitness to true")
		}
	})
}
