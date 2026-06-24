package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// validation_test.go — table-driven coverage for every Validate()
// function and helper in the package, plus the env-driven and
// pointer-bool feature toggles. These surfaces are the highest-risk
// parts of the config layer: a silent default in any of them flips
// the proxy from "secure by default" to "open by default".

// ---------------------------------------------------------------------
// TLSConfig.Validate
// ---------------------------------------------------------------------

func TestTLSConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		tls     TLSConfig
		wantErr string // substring match; empty means no error
	}{
		{"empty plaintext", TLSConfig{}, ""},
		{"key without cert", TLSConfig{KeyFile: "/a/key.pem"}, "cert_file is empty"},
		{"cert without key", TLSConfig{CertFile: "/a/cert.pem"}, "key_file is empty"},
		{"both blank spaces", TLSConfig{CertFile: "  ", KeyFile: "  "}, ""},
		{"valid pair 1.2", TLSConfig{CertFile: "c", KeyFile: "k", MinVersion: "1.2"}, ""},
		{"valid pair 1.3", TLSConfig{CertFile: "c", KeyFile: "k", MinVersion: "1.3"}, ""},
		{"unknown min version", TLSConfig{CertFile: "c", KeyFile: "k", MinVersion: "1.1"}, "min_version"},
		{"empty min version ok", TLSConfig{CertFile: "c", KeyFile: "k", MinVersion: ""}, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.tls.Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestTLSConfigEnabled(t *testing.T) {
	if (TLSConfig{}).Enabled() {
		t.Error("empty TLS should not be enabled")
	}
	if (TLSConfig{CertFile: "a"}).Enabled() {
		t.Error("cert alone should not mark TLS enabled")
	}
	if !(TLSConfig{CertFile: "a", KeyFile: "b"}).Enabled() {
		t.Error("cert+key should mark TLS enabled")
	}
	if (TLSConfig{CertFile: "  ", KeyFile: "  "}).Enabled() {
		t.Error("whitespace-only paths should not mark TLS enabled")
	}
}

// ---------------------------------------------------------------------
// DataSourceRuntimeConfig.validate
// ---------------------------------------------------------------------

func TestDataSourceRuntimeConfigValidate(t *testing.T) {
	cases := []struct {
		name    string
		cfg     DataSourceRuntimeConfig
		wantErr string
	}{
		{"happy path", DataSourceRuntimeConfig{RefreshIntervalSeconds: 10, TimeoutSeconds: 5, JitterPercent: 0}, ""},
		{"jitter 100 allowed", DataSourceRuntimeConfig{RefreshIntervalSeconds: 10, TimeoutSeconds: 5, JitterPercent: 100}, ""},
		{"zero refresh", DataSourceRuntimeConfig{TimeoutSeconds: 5, JitterPercent: 10}, "refresh_interval_seconds"},
		{"negative refresh", DataSourceRuntimeConfig{RefreshIntervalSeconds: -1, TimeoutSeconds: 5, JitterPercent: 10}, "refresh_interval_seconds"},
		{"zero timeout", DataSourceRuntimeConfig{RefreshIntervalSeconds: 10, JitterPercent: 10}, "timeout_seconds"},
		{"jitter 101", DataSourceRuntimeConfig{RefreshIntervalSeconds: 10, TimeoutSeconds: 5, JitterPercent: 101}, "jitter_percent"},
		{"jitter -1", DataSourceRuntimeConfig{RefreshIntervalSeconds: 10, TimeoutSeconds: 5, JitterPercent: -1}, "jitter_percent"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validate("data_sources.foo")
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
			if err != nil && !strings.Contains(err.Error(), "data_sources.foo") {
				t.Errorf("expected prefix in error, got %v", err)
			}
		})
	}
}

func TestDataSourceRuntimeConfigAccessorDefaults(t *testing.T) {
	// Nil Enabled -> true by default; nil StartupSync -> true.
	var c DataSourceRuntimeConfig
	if !c.EnabledValue() {
		t.Error("nil Enabled pointer should default to true")
	}
	if !c.StartupSyncValue() {
		t.Error("nil StartupSync pointer should default to true")
	}
	off := false
	c.Enabled = &off
	c.StartupSync = &off
	if c.EnabledValue() {
		t.Error("explicit false should be respected")
	}
	if c.StartupSyncValue() {
		t.Error("explicit false should be respected")
	}
}

func TestDataSourceRuntimeConfigApplyDefaults(t *testing.T) {
	defaults := DataSourceRuntimeConfig{
		Enabled:                boolPtr(true),
		RefreshIntervalSeconds: 300,
		StartupSync:            boolPtr(false),
		TimeoutSeconds:         30,
		JitterPercent:          10,
	}
	// Zero-value cfg picks up every default.
	var cfg DataSourceRuntimeConfig
	cfg.applyDefaults(defaults)
	if cfg.RefreshIntervalSeconds != 300 || cfg.TimeoutSeconds != 30 || cfg.JitterPercent != 10 {
		t.Errorf("applyDefaults missed a field: %+v", cfg)
	}
	if cfg.Enabled == nil || !*cfg.Enabled {
		t.Error("applyDefaults should copy Enabled pointer")
	}
	if cfg.StartupSync == nil || *cfg.StartupSync {
		t.Error("applyDefaults should copy StartupSync pointer")
	}

	// Explicitly-set values must be preserved.
	onTrue := true
	cfg2 := DataSourceRuntimeConfig{
		Enabled:                &onTrue,
		RefreshIntervalSeconds: 1,
		StartupSync:            &onTrue,
		TimeoutSeconds:         2,
		JitterPercent:          3,
	}
	cfg2.applyDefaults(defaults)
	if cfg2.RefreshIntervalSeconds != 1 || cfg2.TimeoutSeconds != 2 || cfg2.JitterPercent != 3 {
		t.Errorf("applyDefaults clobbered explicit values: %+v", cfg2)
	}
}

// ---------------------------------------------------------------------
// ClamAV validation & defaults
// ---------------------------------------------------------------------

func TestClamAVValidate(t *testing.T) {
	enabled := true
	disabled := false
	cases := []struct {
		name    string
		cfg     ClamAVConfig
		wantErr string
	}{
		{"disabled happy", ClamAVConfig{Enabled: &disabled, TimeoutSeconds: 1, MaxStreamBytes: 1}, ""},
		{"enabled missing socket", ClamAVConfig{Enabled: &enabled, SocketPath: "", TimeoutSeconds: 1, MaxStreamBytes: 1}, "socket_path"},
		{"enabled whitespace socket", ClamAVConfig{Enabled: &enabled, SocketPath: "   ", TimeoutSeconds: 1, MaxStreamBytes: 1}, "socket_path"},
		{"zero timeout", ClamAVConfig{SocketPath: "/s", TimeoutSeconds: 0, MaxStreamBytes: 1}, "timeout_seconds"},
		{"negative timeout", ClamAVConfig{SocketPath: "/s", TimeoutSeconds: -5, MaxStreamBytes: 1}, "timeout_seconds"},
		{"zero max stream", ClamAVConfig{SocketPath: "/s", TimeoutSeconds: 5, MaxStreamBytes: 0}, "max_stream_bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("expected nil error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("want error containing %q, got %v", tc.wantErr, err)
			}
		})
	}
}

func TestClamAVEnabledValue(t *testing.T) {
	if (ClamAVConfig{}).EnabledValue() {
		t.Error("nil Enabled should default to false")
	}
	tr := true
	if !(ClamAVConfig{Enabled: &tr}).EnabledValue() {
		t.Error("explicit true should be honored")
	}
}

func TestClamAVApplyDefaultsPreservesExplicit(t *testing.T) {
	defaults := ClamAVConfig{
		Enabled:        boolPtr(false),
		SocketPath:     "/tmp/d.sock",
		TimeoutSeconds: 60,
		MaxStreamBytes: 1024,
	}
	// All empty/zero -> defaults.
	var c ClamAVConfig
	c.applyDefaults(defaults)
	if c.SocketPath != "/tmp/d.sock" || c.TimeoutSeconds != 60 || c.MaxStreamBytes != 1024 {
		t.Errorf("defaults not applied: %+v", c)
	}
	if c.Enabled == nil || *c.Enabled {
		t.Error("Enabled pointer not copied from defaults")
	}
	// Whitespace socket is treated as empty.
	c2 := ClamAVConfig{SocketPath: "   "}
	c2.applyDefaults(defaults)
	if c2.SocketPath != "/tmp/d.sock" {
		t.Errorf("whitespace socket should be replaced, got %q", c2.SocketPath)
	}
	// Explicit values survive.
	tr := true
	c3 := ClamAVConfig{
		Enabled:        &tr,
		SocketPath:     "/mine.sock",
		TimeoutSeconds: 5,
		MaxStreamBytes: 42,
	}
	c3.applyDefaults(defaults)
	if c3.SocketPath != "/mine.sock" || c3.TimeoutSeconds != 5 || c3.MaxStreamBytes != 42 {
		t.Errorf("explicit values should survive, got %+v", c3)
	}
}

// ---------------------------------------------------------------------
// MalwareConfig.GHSAEnabled (feature-flag with default-on semantics)
// ---------------------------------------------------------------------

func TestGHSAEnabledDefault(t *testing.T) {
	// Default-on: nil pointer -> true.
	if !(MalwareConfig{}).GHSAEnabled() {
		t.Error("default GHSAEnabled should be true")
	}
	off := false
	if (MalwareConfig{EnableGHSA: &off}).GHSAEnabled() {
		t.Error("explicit false must be respected")
	}
	on := true
	if !(MalwareConfig{EnableGHSA: &on}).GHSAEnabled() {
		t.Error("explicit true must be respected")
	}
}

// ---------------------------------------------------------------------
// RepositoryConfig normalize + accessors
// ---------------------------------------------------------------------

func TestRepositoryConfigNormalize(t *testing.T) {
	remotes := map[string]RemoteDefaults{
		"npm": {
			URL:            "https://registry.npmjs.org",
			TimeoutSeconds: 42,
			Headers:        map[string]string{"X-Foo": "bar"},
		},
	}
	repo := RepositoryConfig{
		Name:   "  my-proxy  ",
		Format: "  NPM  ",
	}
	repo.normalize(remotes)
	if repo.Name != "my-proxy" {
		t.Errorf("name should be trimmed, got %q", repo.Name)
	}
	if repo.Format != "npm" {
		t.Errorf("format should be lowercased, got %q", repo.Format)
	}
	if repo.Type != "proxy" {
		t.Errorf("type should default to proxy, got %q", repo.Type)
	}
	if repo.Enabled == nil || !*repo.Enabled {
		t.Error("Enabled should default to true when nil")
	}
	if repo.Cache.NegativeTTLSeconds != 300 {
		t.Errorf("negative TTL default 300, got %d", repo.Cache.NegativeTTLSeconds)
	}
	if repo.Remote.URL != "https://registry.npmjs.org" {
		t.Errorf("remote URL should be filled from remotes, got %q", repo.Remote.URL)
	}
	if repo.Remote.TimeoutSeconds != 42 {
		t.Errorf("timeout from defaults, got %d", repo.Remote.TimeoutSeconds)
	}
	if repo.Remote.Headers["X-Foo"] != "bar" {
		t.Errorf("headers should be cloned from defaults, got %v", repo.Remote.Headers)
	}
	// Mutating the copy must not touch the source.
	repo.Remote.Headers["X-Foo"] = "mutated"
	if remotes["npm"].Headers["X-Foo"] != "bar" {
		t.Error("headers were not cloned — mutating copy leaked into source map")
	}
}

func TestRepositoryConfigNormalizeRawSkipsRemoteFallback(t *testing.T) {
	repo := RepositoryConfig{Name: "internal", Format: "raw", Type: "raw"}
	repo.normalize(builtinRemoteDefaults)
	if repo.Remote.URL != "" {
		t.Errorf("raw repo should stay remote-less, got %q", repo.Remote.URL)
	}
	if repo.Remote.TimeoutSeconds != 60 {
		t.Errorf("timeout should still default to 60, got %d", repo.Remote.TimeoutSeconds)
	}
}

func TestRepositoryAccessors(t *testing.T) {
	// Nil Enabled -> true (default-enabled).
	if !(RepositoryConfig{}).EnabledValue() {
		t.Error("nil Enabled should default to true")
	}
	off := false
	if (RepositoryConfig{Enabled: &off}).EnabledValue() {
		t.Error("explicit false should win")
	}
	// AnonymousAccess: default false.
	if (RepositoryConfig{}).AnonymousAccessValue() {
		t.Error("nil anonymous_access should default to false")
	}
	on := true
	if !(RepositoryConfig{AnonymousAccess: &on}).AnonymousAccessValue() {
		t.Error("explicit true should be respected")
	}
	// NegativeTTL conversion.
	r := RepositoryConfig{Cache: CacheConfig{NegativeTTLSeconds: 90}}
	if r.NegativeTTL() != 90*time.Second {
		t.Errorf("NegativeTTL conversion wrong: %s", r.NegativeTTL())
	}
}

// ---------------------------------------------------------------------
// Config top-level accessors
// ---------------------------------------------------------------------

func TestConfigAccessorsNilSafe(t *testing.T) {
	var c *Config
	if !c.BlockingEnabled() {
		t.Error("nil Config should default BlockingEnabled to true")
	}
	if !c.AnonymousRepositoryAccess() {
		t.Error("nil Config should default AnonymousRepositoryAccess to true")
	}
	if c.ReleaseMinAgeDays() != 0 {
		t.Error("nil Config should report 0 min age")
	}
	if c.ExceptionAgeDays() != 0 {
		t.Error("nil Config should report 0 exception age")
	}
	if c.PolicyEvalCacheTTL() != 60*time.Second {
		t.Error("nil Config should fall back to default TTL")
	}
}

func TestReleaseMinAgeDaysClampsNegative(t *testing.T) {
	c := &Config{}
	c.ReleasePolicy.MinAgeDays = -5
	if got := c.ReleaseMinAgeDays(); got != 0 {
		t.Errorf("expected negative min age to clamp to 0, got %d", got)
	}
	c.ReleasePolicy.MinAgeDays = 7
	if got := c.ReleaseMinAgeDays(); got != 7 {
		t.Errorf("expected 7, got %d", got)
	}
}

func TestExceptionAgeDaysClampsNegative(t *testing.T) {
	c := &Config{}
	c.Exceptions.AgeDays = -10
	if got := c.ExceptionAgeDays(); got != 0 {
		t.Errorf("expected negative to clamp to 0, got %d", got)
	}
	c.Exceptions.AgeDays = 14
	if c.ExceptionAgeDays() != 14 {
		t.Error("expected 14")
	}
}

// ---------------------------------------------------------------------
// Validate() — top-level error paths
// ---------------------------------------------------------------------

func TestValidateRejectsEmptyAdminUsername(t *testing.T) {
	// Build a config with at least one valid repo but blank admin.
	c := &Config{}
	c.applyDefaults("")
	c.Server.Admin.Username = "   "
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "admin username") {
		t.Fatalf("expected admin username error, got %v", err)
	}
}

func TestValidateRejectsInvalidRemoteURLPropagates(t *testing.T) {
	// url.Parse is very permissive; use an explicitly malformed control
	// character to force an error.
	c := &Config{
		Repositories: []RepositoryConfig{{
			Name:   "bad",
			Format: "npm",
			Type:   "proxy",
			Remote: RemoteConfig{URL: "http://\x7f/bad"},
		}},
	}
	c.applyDefaults("")
	err := c.validate()
	if err == nil {
		t.Fatal("expected url parse error")
	}
	if !strings.Contains(err.Error(), "invalid remote.url") {
		t.Errorf("expected invalid remote.url wrapper, got %v", err)
	}
}

func TestValidateRejectsBadTLS(t *testing.T) {
	c := &Config{
		Repositories: []RepositoryConfig{{
			Name:   "r",
			Format: "npm",
			Type:   "proxy",
			Remote: RemoteConfig{URL: "https://registry.npmjs.org"},
		}},
		Server: ServerConfig{
			TLS: TLSConfig{CertFile: "only-cert.pem"},
		},
	}
	c.applyDefaults("")
	err := c.validate()
	if err == nil || !strings.Contains(err.Error(), "key_file is empty") {
		t.Fatalf("expected TLS error, got %v", err)
	}
}

func TestValidateBubblesDataSourceError(t *testing.T) {
	c := &Config{}
	c.applyDefaults("")
	c.DataSources.OpenSSF.JitterPercent = 500
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "openssf") {
		t.Fatalf("expected openssf jitter error, got %v", err)
	}
}

// ---------------------------------------------------------------------
// applyDefaults clamps and defaults knobs
// ---------------------------------------------------------------------

func TestApplyDefaultsClampsAndPopulates(t *testing.T) {
	c := &Config{}
	c.ReleasePolicy.MinAgeDays = -1
	c.HTTPClient.TimeoutSeconds = 0
	c.HTTPClient.MaxIdleConns = 0
	c.applyDefaults("")
	if c.ReleasePolicy.MinAgeDays != 0 {
		t.Errorf("negative min_age_days should clamp to 0, got %d", c.ReleasePolicy.MinAgeDays)
	}
	if c.HTTPClient.TimeoutSeconds != 60 {
		t.Errorf("timeout default 60, got %d", c.HTTPClient.TimeoutSeconds)
	}
	if c.HTTPClient.MaxIdleConns != 64 {
		t.Errorf("max idle default 64, got %d", c.HTTPClient.MaxIdleConns)
	}
	if c.Server.Listen != ":8787" {
		t.Errorf("default listen, got %q", c.Server.Listen)
	}
	if c.Server.TLS.MinVersion != "1.2" {
		t.Errorf("TLS min default 1.2, got %q", c.Server.TLS.MinVersion)
	}
	if c.Hooks.DockerLayer.Mode != "on" {
		t.Errorf("docker_layer mode default on, got %q", c.Hooks.DockerLayer.Mode)
	}
	if c.Hooks.DockerLayer.TimeoutSeconds != 60 {
		t.Errorf("docker_layer timeout default 60, got %d", c.Hooks.DockerLayer.TimeoutSeconds)
	}
	if c.Hooks.DockerLayer.SizeCapBytes != 1<<30 {
		t.Errorf("docker_layer size cap default 1GiB, got %d", c.Hooks.DockerLayer.SizeCapBytes)
	}
}

func TestApplyDefaultsNormalizesDockerLayerMode(t *testing.T) {
	c := &Config{}
	c.Hooks.DockerLayer.Mode = "  OFF  "
	c.applyDefaults("")
	if c.Hooks.DockerLayer.Mode != "off" {
		t.Errorf("expected 'off', got %q", c.Hooks.DockerLayer.Mode)
	}
}

// ---------------------------------------------------------------------
// Default() — constructor invariants
// ---------------------------------------------------------------------

func TestDefaultPopulatesRemotes(t *testing.T) {
	cfg, err := Default(t.TempDir())
	if err != nil {
		t.Fatalf("Default: %v", err)
	}
	// Built-in defaults must include canonical ecosystems.
	for _, key := range []string{"npm", "pip", "maven", "docker"} {
		if _, ok := cfg.Remotes[key]; !ok {
			t.Errorf("expected builtin remote defaults to include %q", key)
		}
	}
}

// ---------------------------------------------------------------------
// bool helpers
// ---------------------------------------------------------------------

func TestBoolHelpers(t *testing.T) {
	if boolInt(true) != 1 || boolInt(false) != 0 {
		t.Error("boolInt wrong")
	}
	if boolString(true) != "true" || boolString(false) != "false" {
		t.Error("boolString wrong")
	}
	p := boolPtr(true)
	if p == nil || !*p {
		t.Error("boolPtr(true) should yield non-nil true")
	}
}

// ---------------------------------------------------------------------
// settingMap tolerant parsers
// ---------------------------------------------------------------------

func TestSettingMapGetters(t *testing.T) {
	var nilMap settingMap
	if nilMap.get("x") != "" {
		t.Error("nil get should be empty")
	}
	if _, ok := nilMap.lookup("x"); ok {
		t.Error("nil lookup should report !ok")
	}
	if nilMap.getInt("x") != 0 || nilMap.getInt64("x") != 0 || nilMap.getBool("x") {
		t.Error("nil-map getters should return zero values")
	}

	m := settingMap{
		"str":     "  hello  ",
		"num":     "42",
		"bignum":  "9223372036854775807",
		"badnum":  "not-a-number", // preserved as 0
		"bt":      "True",
		"bf":      "no",
		"b1":      "1",
		"present": "",
	}
	if m.get("str") != "hello" {
		t.Errorf("get should trim, got %q", m.get("str"))
	}
	if m.getInt("num") != 42 {
		t.Error("getInt failed")
	}
	if m.getInt("missing") != 0 {
		t.Error("missing int should be 0")
	}
	if m.getInt("badnum") != 0 {
		t.Error("malformed int should become 0, not panic")
	}
	if m.getInt64("bignum") != 9223372036854775807 {
		t.Error("getInt64 truncated")
	}
	if !m.getBool("bt") {
		t.Error("True should parse to true")
	}
	if !m.getBool("b1") {
		t.Error("1 should parse to true")
	}
	if m.getBool("bf") {
		t.Error("'no' is not recognised as true — but our impl treats 'no' as false; regression-guard")
	}
	v, ok := m.lookup("present")
	if !ok || v != "" {
		t.Errorf("lookup of empty string should return (\"\", true); got (%q, %v)", v, ok)
	}
}

func TestOptionalBool(t *testing.T) {
	// Missing key => nil.
	if optionalBool(nil, "x") != nil {
		t.Error("nil map should return nil pointer")
	}
	m := settingMap{"a": "true", "b": "0", "c": "YeS"}
	if p := optionalBool(m, "missing"); p != nil {
		t.Error("missing key should yield nil")
	}
	p := optionalBool(m, "a")
	if p == nil || !*p {
		t.Error("a=true should yield &true")
	}
	p = optionalBool(m, "b")
	if p == nil || *p {
		t.Error("b=0 should yield &false")
	}
	// Case-insensitive truthy values — only "true" / "1" are truthy
	// per the impl; "YeS" should decode to false.
	p = optionalBool(m, "c")
	if p == nil || *p {
		t.Error("c=YeS should decode to &false (only 'true'/'1' are truthy)")
	}
}

// ---------------------------------------------------------------------
// Authorized-repositories helpers
// ---------------------------------------------------------------------

func TestNormalizeAuthorizedRepositories(t *testing.T) {
	// Empty slice / all whitespace => nil.
	if out, err := normalizeAuthorizedRepositories(nil); err != nil || out != nil {
		t.Errorf("nil input should return (nil,nil); got (%v,%v)", out, err)
	}
	if out, _ := normalizeAuthorizedRepositories([]string{"", "   "}); out != nil {
		t.Errorf("whitespace-only input should normalize to nil; got %v", out)
	}
	// "all" wildcard (case-insensitive) => nil to signal wildcard.
	if out, _ := normalizeAuthorizedRepositories([]string{"ALL", "foo"}); out != nil {
		t.Errorf("wildcard 'ALL' should collapse to nil, got %v", out)
	}
	if out, _ := normalizeAuthorizedRepositories([]string{"*"}); out != nil {
		t.Errorf("wildcard '*' should collapse to nil, got %v", out)
	}
	// Dedup (case-insensitive) preserves order.
	out, _ := normalizeAuthorizedRepositories([]string{"Repo", "repo", "other"})
	if len(out) != 2 || out[0] != "Repo" || out[1] != "other" {
		t.Errorf("dedup failed: %v", out)
	}
}

func TestParseAuthorizedRepositoriesRoundTrip(t *testing.T) {
	// marshal → parse should roundtrip.
	raw, err := marshalAuthorizedRepositories([]string{"alpha", "beta"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got, err := parseAuthorizedRepositories(raw.(string))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(got) != 2 || got[0] != "alpha" || got[1] != "beta" {
		t.Errorf("roundtrip lost data: %v", got)
	}

	// Empty input -> nil, no error.
	if out, err := parseAuthorizedRepositories("   "); err != nil || out != nil {
		t.Errorf("empty input should be (nil,nil); got (%v,%v)", out, err)
	}

	// Malformed JSON -> error wrapping ErrInvalidClientCredential.
	_, err = parseAuthorizedRepositories("{ this is not json }")
	if err == nil || !errors.Is(err, ErrInvalidClientCredential) {
		t.Errorf("expected ErrInvalidClientCredential, got %v", err)
	}
}

func TestMarshalAuthorizedRepositoriesEmpty(t *testing.T) {
	v, err := marshalAuthorizedRepositories(nil)
	if err != nil {
		t.Fatalf("marshal nil: %v", err)
	}
	if v != nil {
		t.Errorf("empty input should marshal to nil, got %v", v)
	}
}

// ---------------------------------------------------------------------
// Client ID validation
// ---------------------------------------------------------------------

func TestValidateClientID(t *testing.T) {
	cases := []struct {
		in   string
		want bool // want valid
	}{
		{"", false},
		{"ab", false}, // too short
		{"abc", true}, // min length 3
		{"a12", true}, // letters+digits
		{"user-name_1", true},
		{"ABCDEF", false}, // uppercase not allowed after normalization; raw input should fail
		{"1abc", false},   // must start with letter
		{"-abc", false},   // must start with letter
		{strings.Repeat("a", 32), true},
		{strings.Repeat("a", 33), false},
		{"bad id", false}, // spaces
		{"bad/id", false},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			err := validateClientID(tc.in)
			if tc.want && err != nil {
				t.Errorf("%q should be valid, got %v", tc.in, err)
			}
			if !tc.want && err == nil {
				t.Errorf("%q should be invalid", tc.in)
			}
			if err != nil && !errors.Is(err, ErrInvalidClientCredential) {
				t.Errorf("error should wrap ErrInvalidClientCredential, got %v", err)
			}
		})
	}
}

func TestNormalizeClientID(t *testing.T) {
	if got := normalizeClientID("  ABC  "); got != "abc" {
		t.Errorf("expected 'abc', got %q", got)
	}
}

// ---------------------------------------------------------------------
// Client-guide base URL resolution (env precedence)
// ---------------------------------------------------------------------

func TestResolveClientGuideBaseURLPrecedence(t *testing.T) {
	// Clear every env var the resolver consults so each subtest starts
	// from a known-empty baseline.
	envs := []string{
		"CHAINSAW_REPO_BASE_URL",
		"NEXT_PUBLIC_CHAINSAW_REPO_BASE_URL",
		"CHAINSAW_API_BASE_URL",
		"NEXT_PUBLIC_CHAINSAW_API_BASE_URL",
		"CHAINSAW_API_BASEPATH",
		"NEXT_PUBLIC_CHAINSAW_API_BASEPATH",
		"CHAINSAW_API_ORIGIN",
		"NEXT_PUBLIC_CHAINSAW_API_ORIGIN",
	}
	for _, e := range envs {
		t.Setenv(e, "")
	}

	// Nothing set → empty result.
	base, host := resolveClientGuideBaseURL()
	if base != "" || host != "" {
		t.Errorf("expected empty base/host when no env set, got (%q,%q)", base, host)
	}

	// REPO_BASE wins over every other.
	t.Setenv("CHAINSAW_REPO_BASE_URL", "https://artifacts.corp/")
	t.Setenv("CHAINSAW_API_BASE_URL", "https://dash.corp/api/v1")
	base, host = resolveClientGuideBaseURL()
	if base != "https://artifacts.corp" {
		t.Errorf("REPO_BASE should win; got %q", base)
	}
	if host != "artifacts.corp" {
		t.Errorf("host parsed from REPO_BASE, got %q", host)
	}

	// Falls back to NEXT_PUBLIC_REPO_BASE when CHAINSAW_REPO_BASE unset.
	t.Setenv("CHAINSAW_REPO_BASE_URL", "")
	t.Setenv("NEXT_PUBLIC_CHAINSAW_REPO_BASE_URL", "https://pub.corp")
	base, _ = resolveClientGuideBaseURL()
	if base != "https://pub.corp" {
		t.Errorf("NEXT_PUBLIC_REPO_BASE fallback failed; got %q", base)
	}

	// Falls back to API_BASE when no repo base.
	t.Setenv("NEXT_PUBLIC_CHAINSAW_REPO_BASE_URL", "")
	t.Setenv("CHAINSAW_API_BASE_URL", "https://dash.corp/api/v1")
	base, host = resolveClientGuideBaseURL()
	if base != "https://dash.corp" {
		t.Errorf("API_BASE should strip /api/v1 suffix; got %q", base)
	}
	if host != "dash.corp" {
		t.Errorf("API_BASE host, got %q", host)
	}

	// API_BASE + explicit BASEPATH keeps the basepath.
	t.Setenv("CHAINSAW_API_BASE_URL", "https://dash.corp/api/v1")
	t.Setenv("CHAINSAW_API_BASEPATH", "/custom")
	base, _ = resolveClientGuideBaseURL()
	if base != "https://dash.corp/custom" {
		t.Errorf("explicit basepath should override stripped suffix; got %q", base)
	}

	// ORIGIN fallback when API_BASE is unparseable.
	t.Setenv("CHAINSAW_API_BASE_URL", "")
	t.Setenv("CHAINSAW_API_BASEPATH", "")
	t.Setenv("CHAINSAW_API_ORIGIN", "https://origin.corp")
	base, _ = resolveClientGuideBaseURL()
	if base != "https://origin.corp" {
		t.Errorf("ORIGIN fallback, got %q", base)
	}
}

func TestFirstEnvPrecedence(t *testing.T) {
	t.Setenv("A1", "")
	t.Setenv("A2", "second")
	t.Setenv("A3", "third")
	if got := firstEnv("A1", "A2", "A3"); got != "second" {
		t.Errorf("firstEnv should skip empties; got %q", got)
	}
	if got := firstEnv("Z1", "Z2"); got != "" {
		t.Errorf("all-missing should be empty; got %q", got)
	}
	// Trims whitespace.
	t.Setenv("A1", "   padded   ")
	if got := firstEnv("A1"); got != "padded" {
		t.Errorf("firstEnv should trim; got %q", got)
	}
}

func TestHostFromURL(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{"", ""},
		{"https://example.com/path", "example.com"},
		{"example.com:8787", "example.com:8787"},
		{"http://a.b:9000/x", "a.b:9000"},
	}
	for _, tc := range cases {
		if got := hostFromURL(tc.in); got != tc.out {
			t.Errorf("hostFromURL(%q) = %q, want %q", tc.in, got, tc.out)
		}
	}
}

func TestNormalizeBasePath(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{"", ""},
		{"/", ""},
		{"api", "/api"},
		{"/api/", "/api"},
		{"  /custom/  ", "/custom"},
	}
	for _, tc := range cases {
		if got := normalizeBasePath(tc.in); got != tc.out {
			t.Errorf("normalizeBasePath(%q) = %q, want %q", tc.in, got, tc.out)
		}
	}
}

func TestStripApiSuffix(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{"", ""},
		{"/api", ""},
		{"/api/v1", ""},
		{"/base/api/v1", "/base"},
		{"/base/api", "/base"},
		{"/nothing/here", "/nothing/here"},
	}
	for _, tc := range cases {
		if got := stripApiSuffix(tc.in); got != tc.out {
			t.Errorf("stripApiSuffix(%q) = %q, want %q", tc.in, got, tc.out)
		}
	}
}

// ---------------------------------------------------------------------
// cloneMap / cloneRepositoryConfig behaviour
// ---------------------------------------------------------------------

func TestCloneMapAndRepositoryConfig(t *testing.T) {
	if cloneMap(nil) != nil {
		t.Error("cloneMap(nil) should be nil")
	}
	src := map[string]string{"a": "1", "b": "2"}
	cp := cloneMap(src)
	cp["a"] = "changed"
	if src["a"] != "1" {
		t.Error("cloneMap should deep-copy")
	}

	on := true
	r := RepositoryConfig{
		Name:    "foo",
		Enabled: &on,
		Remote:  RemoteConfig{URL: "u", Headers: map[string]string{"k": "v"}},
	}
	clone := cloneRepositoryConfig(r)
	*clone.Enabled = false
	clone.Remote.Headers["k"] = "mutated"
	if !*r.Enabled {
		t.Error("cloning must deep-copy Enabled pointer")
	}
	if r.Remote.Headers["k"] != "v" {
		t.Error("cloning must deep-copy Headers map")
	}

	if cloneRepositoryConfigs(nil) != nil {
		t.Error("cloneRepositoryConfigs(nil) should be nil")
	}
	list := cloneRepositoryConfigs([]RepositoryConfig{r, r})
	if len(list) != 2 {
		t.Errorf("expected 2 clones, got %d", len(list))
	}
}

// ---------------------------------------------------------------------
// AllowInsecureTLS — high-risk default-off security flag
// ---------------------------------------------------------------------

func TestAllowInsecureTLSDefaultsFailClosed(t *testing.T) {
	t.Setenv(allowInsecureTLSEnvVar, "")
	// Nil receiver must not panic and must fail closed.
	var nilC *Config
	if nilC.AllowInsecureTLS() {
		t.Error("nil config must fail closed (false)")
	}
	c := &Config{}
	if c.AllowInsecureTLS() {
		t.Error("zero-value config must fail closed (false)")
	}
}

func TestAllowInsecureTLSEnvWins(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"1", true},
		{"true", true},
		{"YES", true},
		{"on", true},
		{"0", false},
		{"false", false},
		{"off", false},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(allowInsecureTLSEnvVar, tc.env)
			// YAML says the opposite — env must win.
			c := &Config{Runtime: RuntimeConfig{AllowInsecureTLS: !tc.want}}
			if got := c.AllowInsecureTLS(); got != tc.want {
				t.Errorf("env=%q: got %v, want %v", tc.env, got, tc.want)
			}
		})
	}
}

func TestAllowInsecureTLSYAMLFallback(t *testing.T) {
	t.Setenv(allowInsecureTLSEnvVar, "")
	c := &Config{Runtime: RuntimeConfig{AllowInsecureTLS: true}}
	if !c.AllowInsecureTLS() {
		t.Error("YAML true should be honored when env unset")
	}
	// Unrecognised env value must not accidentally flip the flag to
	// true — the "yaml decides" path must kick in.
	t.Setenv(allowInsecureTLSEnvVar, "maybe-later")
	c2 := &Config{Runtime: RuntimeConfig{AllowInsecureTLS: false}}
	if c2.AllowInsecureTLS() {
		t.Error("unparseable env must not flip flag; YAML false should stand")
	}
}

func TestParseAllowInsecureTLSEnv(t *testing.T) {
	cases := []struct {
		env     string
		wantVal bool
		wantOK  bool
	}{
		{"", false, false},
		{"1", true, true},
		{"0", false, true},
		{"wat", false, false},
		{"T", true, true}, // ParseBool fallback
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(allowInsecureTLSEnvVar, tc.env)
			got, ok := parseAllowInsecureTLSEnv()
			if got != tc.wantVal || ok != tc.wantOK {
				t.Errorf("parseAllowInsecureTLSEnv(%q)=(%v,%v), want (%v,%v)", tc.env, got, ok, tc.wantVal, tc.wantOK)
			}
		})
	}
}

// ---------------------------------------------------------------------
// absolutize — path resolution
// ---------------------------------------------------------------------

func TestAbsolutize(t *testing.T) {
	if got := absolutize("/base", ""); got != "" {
		t.Errorf("empty in should be empty out, got %q", got)
	}
	if got := absolutize("/base", "/already/abs"); got != "/already/abs" {
		t.Errorf("abs path should pass through, got %q", got)
	}
	if got := absolutize("/base", "child"); got != "/base/child" {
		t.Errorf("rel path should be joined, got %q", got)
	}
}

// ---------------------------------------------------------------------
// Client guide renderer — host/URL substitution
// ---------------------------------------------------------------------

func TestClientGuideRenderWithOverride(t *testing.T) {
	// Clear env so the renderer has no baseURL.
	for _, e := range []string{
		"CHAINSAW_REPO_BASE_URL", "NEXT_PUBLIC_CHAINSAW_REPO_BASE_URL",
		"CHAINSAW_API_BASE_URL", "NEXT_PUBLIC_CHAINSAW_API_BASE_URL",
		"CHAINSAW_API_BASEPATH", "NEXT_PUBLIC_CHAINSAW_API_BASEPATH",
		"CHAINSAW_API_ORIGIN", "NEXT_PUBLIC_CHAINSAW_API_ORIGIN",
	} {
		t.Setenv(e, "")
	}

	r := NewClientGuideRenderer()
	// No guide → empty result unchanged.
	if r.Render("") != "" {
		t.Error("empty guide should return empty")
	}

	guide := "# npm setup\n\nUse ${CHAINSAW_REPO_BASE_URL}/npm and http://localhost:8787/npm.\n"
	// No env, no override → ${...} placeholder stays unsubstituted.
	out := r.Render(guide)
	if !strings.Contains(out, "${CHAINSAW_REPO_BASE_URL}") {
		t.Errorf("placeholder should remain when no base URL; got %q", out)
	}

	// Explicit override substitutes both the template variable and the
	// localhost bare-host reference.
	out = r.RenderWithOverride(guide, "https://proxy.corp")
	if strings.Contains(out, "${CHAINSAW_REPO_BASE_URL}") {
		t.Errorf("placeholder should be substituted, got %q", out)
	}
	if !strings.Contains(out, "https://proxy.corp/npm") {
		t.Errorf("expected substituted URL, got %q", out)
	}
	if strings.Contains(out, "localhost:8787") {
		t.Errorf("localhost:8787 should have been replaced, got %q", out)
	}
}

func TestClientGuideRenderEnvDrivesBaseURL(t *testing.T) {
	// With env set, Render() picks it up.
	for _, e := range []string{
		"NEXT_PUBLIC_CHAINSAW_REPO_BASE_URL",
		"CHAINSAW_API_BASE_URL", "NEXT_PUBLIC_CHAINSAW_API_BASE_URL",
		"CHAINSAW_API_BASEPATH", "NEXT_PUBLIC_CHAINSAW_API_BASEPATH",
		"CHAINSAW_API_ORIGIN", "NEXT_PUBLIC_CHAINSAW_API_ORIGIN",
	} {
		t.Setenv(e, "")
	}
	t.Setenv("CHAINSAW_REPO_BASE_URL", "https://artifacts.corp")
	r := NewClientGuideRenderer()
	guide := "# pip setup\n\nPoint pip at ${CHAINSAW_REPO_BASE_URL}/simple/\n"
	out := r.Render(guide)
	if !strings.Contains(out, "https://artifacts.corp/simple/") {
		t.Errorf("env base URL should drive substitution; got %q", out)
	}
}

func TestInferGuideFormat(t *testing.T) {
	cases := map[string]string{
		"# npm setup":               "npm",
		"# Yarn Configuration":      "yarn",
		"# Configure pip for PyPI":  "pip",
		"# Maven setup":             "maven",
		"# Docker Hub proxy":        "docker",
		"# cargo instructions":      "cargo",
		"# Go Modules setup":        "go",
		"# Swift package manager":   "swift",
		"# Unknown ecosystem":       "",
		"":                          "",
		"no leading heading at all": "",
	}
	for guide, want := range cases {
		if got := inferGuideFormat(guide); got != want {
			t.Errorf("inferGuideFormat(%q) = %q, want %q", guide, got, want)
		}
	}
}

func TestCacheAdviceForFormat(t *testing.T) {
	// Every known format produces advice containing the canonical heading.
	for _, f := range []string{"npm", "yarn", "pip", "maven", "nuget", "composer", "go", "apt", "yum", "dnf", "docker", "gradle", "cocoapods", "swift"} {
		got := cacheAdviceForFormat(f)
		if got == "" {
			t.Errorf("format %q should emit advice", f)
		}
		if !strings.Contains(got, cacheAdviceHeading) {
			t.Errorf("format %q advice missing heading", f)
		}
	}
	if cacheAdviceForFormat("unknown-fmt") != "" {
		t.Error("unknown format should emit no advice")
	}
	// Case-insensitive + trimmed.
	if cacheAdviceForFormat("  NPM  ") == "" {
		t.Error("format matching should be case-insensitive")
	}
}

func TestInsertCacheAdviceNoOptions(t *testing.T) {
	// Guide without an "Option N" heading stays unchanged.
	in := "# npm setup\n\nnothing to do\n"
	if got := insertCacheAdvice(in); got != in {
		t.Error("guide without Option heading should be returned as-is")
	}
	// Empty input stays empty.
	if got := insertCacheAdvice(""); got != "" {
		t.Error("empty input should stay empty")
	}
	// Guide WITH an Option N heading gets the cache advice inserted.
	guide := "# npm setup\n\nIntro text\n\nOption 1: blah blah\n"
	out := insertCacheAdvice(guide)
	if !strings.Contains(out, cacheAdviceHeading) {
		t.Errorf("expected advice heading inserted, got %q", out)
	}
	// Idempotent: running again shouldn't double-insert.
	again := insertCacheAdvice(out)
	if strings.Count(again, cacheAdviceHeading) != 1 {
		t.Errorf("insertCacheAdvice should be idempotent; got %d headings", strings.Count(again, cacheAdviceHeading))
	}
}

// ---------------------------------------------------------------------
// nullableTime
// ---------------------------------------------------------------------

func TestNullableTime(t *testing.T) {
	if nullableTime(nil) != nil {
		t.Error("nil input should marshal to nil")
	}
	ts := time.Date(2024, 1, 2, 3, 4, 5, 0, time.FixedZone("x", 3600))
	got := nullableTime(&ts)
	tv, ok := got.(time.Time)
	if !ok {
		t.Fatalf("expected time.Time, got %T", got)
	}
	if tv.Location() != time.UTC {
		t.Errorf("should convert to UTC, got %v", tv.Location())
	}
}

// ---------------------------------------------------------------------
// RenderWithOverride — full-URL with embedded credentials
// ---------------------------------------------------------------------

func TestRenderWithOverrideStripsLocalhostURLsWithCreds(t *testing.T) {
	for _, e := range []string{
		"CHAINSAW_REPO_BASE_URL", "NEXT_PUBLIC_CHAINSAW_REPO_BASE_URL",
		"CHAINSAW_API_BASE_URL", "NEXT_PUBLIC_CHAINSAW_API_BASE_URL",
		"CHAINSAW_API_BASEPATH", "NEXT_PUBLIC_CHAINSAW_API_BASEPATH",
		"CHAINSAW_API_ORIGIN", "NEXT_PUBLIC_CHAINSAW_API_ORIGIN",
	} {
		t.Setenv(e, "")
	}
	r := NewClientGuideRenderer()
	// Embedded-credential URL gets rewritten to the override host.
	guide := "pip install -i http://user:pass@localhost:8787/simple/ foo\n"
	out := r.RenderWithOverride(guide, "https://proxy.corp/base")
	if strings.Contains(out, "localhost:8787") {
		t.Errorf("localhost:8787 should be replaced, got %q", out)
	}
	if !strings.Contains(out, "user:pass@proxy.corp") {
		t.Errorf("credentials should be preserved with new host, got %q", out)
	}
	if !strings.Contains(out, "/base/simple/") {
		t.Errorf("basepath should be prefixed, got %q", out)
	}
}

func TestRenderWithOverrideFallsBackToServerWideBase(t *testing.T) {
	for _, e := range []string{
		"NEXT_PUBLIC_CHAINSAW_REPO_BASE_URL",
		"CHAINSAW_API_BASE_URL", "NEXT_PUBLIC_CHAINSAW_API_BASE_URL",
		"CHAINSAW_API_BASEPATH", "NEXT_PUBLIC_CHAINSAW_API_BASEPATH",
		"CHAINSAW_API_ORIGIN", "NEXT_PUBLIC_CHAINSAW_API_ORIGIN",
	} {
		t.Setenv(e, "")
	}
	t.Setenv("CHAINSAW_REPO_BASE_URL", "https://server-wide.corp")
	r := NewClientGuideRenderer()
	guide := "Use ${CHAINSAW_REPO_BASE_URL}/npm\n"
	// Empty override should fall through to the server-wide env-derived base.
	out := r.RenderWithOverride(guide, "   ")
	if !strings.Contains(out, "https://server-wide.corp/npm") {
		t.Errorf("empty override should fall through to env base, got %q", out)
	}
}

// ---------------------------------------------------------------------
// Default with empty baseDir uses the defaultBaseDir path
// ---------------------------------------------------------------------

func TestDefaultWithEmptyBaseDir(t *testing.T) {
	cfg, err := Default("")
	if err != nil {
		t.Fatalf("Default(\"\"): %v", err)
	}
	// defaultBaseDir returns "./configs"; the blob root is resolved
	// relative to it. Require that a path was set, not crashing.
	if cfg.BlobStore.Root == "" {
		t.Error("BlobStore.Root should be populated")
	}
	if cfg.Index.Path == "" {
		t.Error("Index.Path should be populated")
	}
}

// ---------------------------------------------------------------------
// parseOfflineEnv edge cases
// ---------------------------------------------------------------------

func TestParseOfflineEnv(t *testing.T) {
	cases := []struct {
		env     string
		wantVal bool
		wantOK  bool
	}{
		{"", false, false},
		{"  ", false, false},
		{"1", true, true},
		{"0", false, true},
		{"True", true, true},
		{"FALSE", false, true},
		{"yes", true, true},
		{"off", false, true},
		{"wat", false, false}, // unrecognised -> (false,false) so YAML decides
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(offlineEnvVar, tc.env)
			got, ok := parseOfflineEnv()
			if got != tc.wantVal || ok != tc.wantOK {
				t.Errorf("parseOfflineEnv(%q) = (%v,%v), want (%v,%v)", tc.env, got, ok, tc.wantVal, tc.wantOK)
			}
		})
	}
}
