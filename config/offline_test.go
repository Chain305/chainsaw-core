package config

import (
	"testing"
)

func TestIsOfflineEnvWins(t *testing.T) {
	cases := []struct {
		env  string
		want bool
	}{
		{"1", true},
		{"true", true},
		{"True", true},
		{"TRUE", true},
		{"yes", true},
		{"YES", true},
		{"on", true},
		{"0", false},
		{"false", false},
		{"no", false},
		{"off", false},
	}
	for _, tc := range cases {
		t.Run(tc.env, func(t *testing.T) {
			t.Setenv(offlineEnvVar, tc.env)
			cfg := &Config{Runtime: RuntimeConfig{Offline: !tc.want}}
			if got := cfg.IsOffline(); got != tc.want {
				t.Errorf("IsOffline() with env=%q = %v, want %v", tc.env, got, tc.want)
			}
		})
	}
}

func TestIsOfflineYAMLFallback(t *testing.T) {
	t.Setenv(offlineEnvVar, "")
	cfg := &Config{Runtime: RuntimeConfig{Offline: true}}
	if !cfg.IsOffline() {
		t.Fatal("IsOffline() = false when YAML runtime.offline = true")
	}
	cfg.Runtime.Offline = false
	if cfg.IsOffline() {
		t.Fatal("IsOffline() = true when nothing set it")
	}
}

func TestIsOfflineNilReceiver(t *testing.T) {
	t.Setenv(offlineEnvVar, "")
	var cfg *Config
	if cfg.IsOffline() {
		t.Fatal("nil receiver should not report offline")
	}
	t.Setenv(offlineEnvVar, "1")
	if !cfg.IsOffline() {
		t.Fatal("nil receiver should still honour env=1")
	}
}

func TestOfflineSource(t *testing.T) {
	t.Setenv(offlineEnvVar, "1")
	cfg := &Config{}
	if got := cfg.OfflineSource(); got != "env" {
		t.Errorf("OfflineSource env = %q, want env", got)
	}
	t.Setenv(offlineEnvVar, "")
	cfg.Runtime.Offline = true
	if got := cfg.OfflineSource(); got != "yaml" {
		t.Errorf("OfflineSource yaml = %q, want yaml", got)
	}
	cfg.Runtime.Offline = false
	if got := cfg.OfflineSource(); got != "default" {
		t.Errorf("OfflineSource default = %q, want default", got)
	}
}

func TestOfflineSuppressesStartupSyncDefaults(t *testing.T) {
	t.Setenv(offlineEnvVar, "1")
	cfg := &Config{}
	cfg.applyDefaults("")
	if cfg.DataSources.OpenSSF.StartupSyncValue() {
		t.Error("offline should flip openssf startup_sync to false")
	}
	if cfg.DataSources.TrivyDB.StartupSyncValue() {
		t.Error("offline should flip trivy_db startup_sync to false")
	}
	if cfg.DataSources.EPSS.StartupSyncValue() {
		t.Error("offline should flip epss startup_sync to false")
	}
	if cfg.DataSources.ClamAVDB.StartupSyncValue() {
		t.Error("offline should flip clamav_db startup_sync to false")
	}
}

func TestOfflineExplicitStartupSyncRespected(t *testing.T) {
	// Operator with a local mirror wants to still sync on boot.
	t.Setenv(offlineEnvVar, "1")
	on := true
	cfg := &Config{}
	cfg.DataSources.TrivyDB.StartupSync = &on
	cfg.applyDefaults("")
	if !cfg.DataSources.TrivyDB.StartupSyncValue() {
		t.Error("explicit startup_sync:true should win over offline default")
	}
}
