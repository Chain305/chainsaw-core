package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/pgstore"
	"github.com/chain305/chainsaw-core/tenancy"
)

// roundTripStore opens the DB-backed store these tests need, plus a
// per-test org so the settings rows written here can never leak into
// another test's view of the default org.
//
// Gated on CHAINSAW_DATABASE_URL like every other DB test in the tree.
// core/config is wired into scripts/ci-db-tests.sh, so the gate means
// "skip" under `make test-short` and "run" in the DB job.
func roundTripStore(t *testing.T) (*pgstore.Store, string) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CHAINSAW_DATABASE_URL"))
	if dsn == "" {
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping DB-backed config round-trip test")
	}
	store, err := pgstore.Open(dsn)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	org := tenancy.NormalizeOrgID("cfgrt-" + strings.ToLower(strings.ReplaceAll(t.Name(), "/", "-")))
	clean := func() {
		_, _ = store.DB().Exec(`DELETE FROM settings WHERE org_id=$1`, org)
		_, _ = store.DB().Exec(`DELETE FROM repositories WHERE org_id=$1`, org)
	}
	clean()
	t.Cleanup(func() {
		clean()
		_ = store.Close()
	})
	return store, org
}

// loadYAML materialises a config file in a temp dir and parses it the
// way cmd/chainsaw-proxy does, so the test exercises the real
// parse → captureExplicitRuntimeKeys → applyDefaults → validate path
// rather than a hand-built struct literal.
func loadYAML(t *testing.T, body string) *Config {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "chainsaw.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write yaml: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load yaml: %v", err)
	}
	return cfg
}

// TestYAMLOnlyBlocksSurviveBootRoundTrip is the regression test for the
// bug this whole change exists for. It walks the real boot sequence —
// parse YAML, SaveToStore, load back — and asserts the values the
// operator wrote are still there afterwards.
//
// It deliberately uses SaveToStoreForOrg + LoadFromStoreForOrg — both of
// which predate this change — so the test body compiles unmodified
// against the pre-fix tree, where it fails on eleven separate
// assertions starting with runtime.offline. A regression test that only
// compiles against the fixed code proves nothing.
func TestYAMLOnlyBlocksSurviveBootRoundTrip(t *testing.T) {
	store, org := roundTripStore(t)

	yaml := `
runtime:
  offline: true
  offline_fail_mode: closed
  intel_bundle_path: /srv/chainsaw/intel-bundle.tar.gz
provenance:
  offline: true
  swift_full_verify: true
  disabled_ecosystems:
    - docker
    - go
  swift_registry_url: https://swift.internal.example/registry
coverage:
  enabled: false
correlation:
  enabled: true
policy:
  eval_cache_ttl_seconds: 0
malware:
  enable_ghsa: false
sbom:
  attribution_enabled: true
  attribution_window_days: 30
hooks:
  docker_layer:
    mode: "off"
    timeout_seconds: 45
    size_cap_bytes: 2147483648
  trivial:
    max_concurrent_scans: 7
remotes:
  npm:
    url: https://npm.internal.example/
    timeout_seconds: 11
repositories:
  - name: internal-apt
    format: apt
    type: hosted
    apt:
      suites: [stable]
      components: [main, contrib]
      architectures: [amd64, arm64]
      origin: Example Corp
      label: internal
  - name: internal-yum
    format: yum
    type: hosted
    yum:
      origin: Example Corp
      label: rpm-internal
      description: internal rpms
      revision: "7"
`
	cfg := loadYAML(t, yaml)

	// Sanity: the YAML parse itself must have seen these. If this block
	// fails the test is lying about what it proves.
	if !cfg.Runtime.Offline || !cfg.Provenance.SwiftFullVerify {
		t.Fatalf("precondition: YAML parse dropped the values under test (offline=%v swift_full_verify=%v)",
			cfg.Runtime.Offline, cfg.Provenance.SwiftFullVerify)
	}

	// The boot path: import the YAML, then read the authoritative copy
	// back out of the database.
	if err := SaveToStoreForOrg(store, cfg, org, true); err != nil {
		t.Fatalf("save to store: %v", err)
	}
	got, hasRepos, err := LoadFromStoreForOrg(store, org)
	if err != nil {
		t.Fatalf("load from store: %v", err)
	}
	if !hasRepos {
		t.Fatalf("expected repositories to have been persisted")
	}

	// --- runtime.* --------------------------------------------------
	// The single highest-consequence assertion: with this false, the
	// startup log says "Offline mode active" and nothing is gated.
	if !got.Runtime.Offline {
		t.Errorf("runtime.offline did not survive the round trip: got false, want true")
	}
	if !got.IsOffline() {
		t.Errorf("IsOffline() = false after round trip; the offline umbrella flag is not in effect")
	}
	if got.Runtime.OfflineFailMode != "closed" {
		t.Errorf("runtime.offline_fail_mode = %q, want %q", got.Runtime.OfflineFailMode, "closed")
	}
	if got.Runtime.IntelBundlePath != "/srv/chainsaw/intel-bundle.tar.gz" {
		t.Errorf("runtime.intel_bundle_path = %q", got.Runtime.IntelBundlePath)
	}

	// --- provenance.* -----------------------------------------------
	if !got.Provenance.SwiftFullVerify {
		t.Errorf("provenance.swift_full_verify did not survive: full SE-0391 CMS verification would never engage")
	}
	if !got.Provenance.Offline {
		t.Errorf("provenance.offline did not survive: an air-gapped deployment keeps dialling keys.openpgp.org / sum.golang.org / the Sigstore TUF CDN")
	}
	if strings.Join(got.Provenance.DisabledEcosystems, ",") != "docker,go" {
		t.Errorf("provenance.disabled_ecosystems = %v, want [docker go]", got.Provenance.DisabledEcosystems)
	}
	if got.Provenance.SwiftRegistryURL != "https://swift.internal.example/registry" {
		t.Errorf("provenance.swift_registry_url = %q", got.Provenance.SwiftRegistryURL)
	}

	// --- feature blocks ---------------------------------------------
	if got.CoverageEnabled() {
		t.Errorf("coverage.enabled=false did not survive")
	}
	if !got.Correlation.Enabled {
		t.Errorf("correlation.enabled did not survive; YAML is its ONLY surface, so internal/deploycorr could never be turned on")
	}
	if ttl := got.PolicyEvalCacheTTL(); ttl != 0 {
		t.Errorf("policy.eval_cache_ttl_seconds=0 did not survive: got %s of cached policy decisions, want cache disabled", ttl)
	}
	if got.Malware.GHSAEnabled() {
		t.Errorf("malware.enable_ghsa=false did not survive")
	}
	if !got.SBOM.AttributionEnabled || got.SBOM.AttributionWindowDays != 30 {
		t.Errorf("sbom block did not survive: enabled=%v window=%d", got.SBOM.AttributionEnabled, got.SBOM.AttributionWindowDays)
	}

	// --- hooks.docker_layer / trivial -------------------------------
	if got.Hooks.DockerLayer.Mode != "off" || got.Hooks.DockerLayer.TimeoutSeconds != 45 || got.Hooks.DockerLayer.SizeCapBytes != 2147483648 {
		t.Errorf("hooks.docker_layer did not survive: %+v", got.Hooks.DockerLayer)
	}
	if got.Hooks.Trivial.MaxConcurrentScans != 7 {
		t.Errorf("hooks.trivial.max_concurrent_scans = %d, want 7", got.Hooks.Trivial.MaxConcurrentScans)
	}

	// --- remotes -----------------------------------------------------
	if npm := got.Remotes["npm"]; npm.URL != "https://npm.internal.example/" || npm.TimeoutSeconds != 11 {
		t.Errorf("remotes.npm did not survive: %+v", npm)
	}
	if _, ok := got.Remotes["pypi"]; ok {
		// builtinRemoteDefaults uses "pip", not "pypi" — guard against a
		// silent rename making the assertion above vacuous.
		t.Errorf("unexpected remotes key layout")
	}

	// --- repositories[].apt / .yum ------------------------------------
	byName := map[string]RepositoryConfig{}
	for _, repo := range got.Repositories {
		byName[repo.Name] = repo
	}
	apt, ok := byName["internal-apt"]
	if !ok {
		t.Fatalf("internal-apt repository missing after round trip")
	}
	if apt.APT == nil {
		t.Fatalf("repositories[].apt did not survive: a hosted-apt repo silently reverts to apt.Default()")
	}
	if strings.Join(apt.APT.Components, ",") != "main,contrib" || apt.APT.Origin != "Example Corp" {
		t.Errorf("repositories[].apt lost content: %+v", *apt.APT)
	}
	yum, ok := byName["internal-yum"]
	if !ok {
		t.Fatalf("internal-yum repository missing after round trip")
	}
	if yum.Yum == nil || yum.Yum.Revision != "7" || yum.Yum.Label != "rpm-internal" {
		t.Errorf("repositories[].yum did not survive: %+v", yum.Yum)
	}
}
