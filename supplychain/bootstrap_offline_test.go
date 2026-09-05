package supplychain

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chain305/chainsaw-core/malware"
)

// noEgressTarballServer points malware.TarballURL at a server that fails the
// test if anything reaches it, and restores the URL afterwards.
func noEgressTarballServer(t *testing.T) *atomic.Int64 {
	t.Helper()
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		t.Errorf("offline mode still fetched the malware dataset: %s %s", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	old := malware.TarballURL
	malware.TarballURL = srv.URL
	t.Cleanup(func() { malware.TarballURL = old })
	return &hits
}

// TestBootstrapMalwareSyncerRespectsOfflineMode is the wiring proof, not an
// option unit test. malware.WithOfflineCheck could be perfectly tested inside
// its own package while nothing passed it — which is precisely the state this
// fixes: `malware.enable_ghsa` was the only switch on any malware egress, and
// the OpenSSF tarball download honoured nothing at all, so an air-gapped
// deployment made outbound requests it had been told it would not.
//
// Asserts the property that matters end to end: a value set on BootstrapConfig
// — the struct cmd/chainsaw-proxy fills — stops the syncer dialling out, and
// the index still carries the embedded floor.
func TestBootstrapMalwareSyncerRespectsOfflineMode(t *testing.T) {
	hits := noEgressTarballServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	comp := Bootstrap(ctx, BootstrapConfig{
		DataDir:             t.TempDir(),
		PopularPackageLimit: 1,
		MalwareSyncInterval: time.Hour,
		Logger:              discardLogger(),
		EnableGHSAMalware:   true, // default-on in production; must NOT re-open egress
		Offline:             func() bool { return true },
	})
	if comp == nil || comp.MalwareSyncer == nil || comp.MalwareIndex == nil {
		t.Fatal("Bootstrap did not return a malware syncer/index")
	}

	if err := comp.MalwareSyncer.Sync(context.Background()); err != nil {
		t.Fatalf("offline Sync through the bootstrap wiring = %v, want nil", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("offline mode made %d dataset requests, want 0", n)
	}
	assertBootstrapFloorPresent(t, comp)
}

// TestBootstrapMalwareSyncerHonoursOfflineEnvVar covers the default path. No
// caller sets BootstrapConfig.Offline today (core/supplychain cannot import
// chainsaw-core/config), so the CHAINSAW_OFFLINE umbrella has to reach the
// syncer on its own or an air-gapped deployment stays exposed until
// cmd/chainsaw-proxy is changed.
func TestBootstrapMalwareSyncerHonoursOfflineEnvVar(t *testing.T) {
	t.Setenv("CHAINSAW_OFFLINE", "1")
	hits := noEgressTarballServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	comp := Bootstrap(ctx, BootstrapConfig{
		DataDir:             t.TempDir(),
		PopularPackageLimit: 1,
		MalwareSyncInterval: time.Hour,
		Logger:              discardLogger(),
		EnableGHSAMalware:   true,
		// Offline deliberately left nil: the env var must be enough.
	})
	if comp == nil || comp.MalwareSyncer == nil {
		t.Fatal("Bootstrap did not return a malware syncer")
	}
	if err := comp.MalwareSyncer.Bootstrap(context.Background()); err != nil {
		t.Fatalf("offline Bootstrap through the env umbrella = %v, want nil", err)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("CHAINSAW_OFFLINE=1 still made %d dataset requests, want 0", n)
	}
	assertBootstrapFloorPresent(t, comp)
}

// assertBootstrapFloorPresent pins that offline is not the same as empty: the
// embedded floor must reach the index, or an air-gapped box would return a
// clean verdict for every known-malicious coordinate.
func assertBootstrapFloorPresent(t *testing.T, comp *Components) {
	t.Helper()
	if !comp.MalwareIndex.FloorLoaded() {
		t.Error("FloorLoaded() = false after an offline sync: the embedded floor was dropped")
	}
	if res := comp.MalwareIndex.Lookup(context.Background(), "npm", "event-stream", "3.3.6"); !res.IsKnownMalicious {
		t.Errorf("event-stream 3.3.6 not known-malicious after an offline sync (lookup = %+v)", res)
	}
	if !comp.MalwareIndex.HasData() {
		t.Error("HasData() = false: offline produced an empty malware index")
	}
}

// TestResolveOfflineCheck covers the resolution order in isolation: an explicit
// predicate always wins, and the env var is re-read on every call so a running
// process can be flipped without a restart.
func TestResolveOfflineCheck(t *testing.T) {
	t.Run("explicit_wins_over_env", func(t *testing.T) {
		t.Setenv("CHAINSAW_OFFLINE", "1")
		if resolveOfflineCheck(func() bool { return false })() {
			t.Fatal("explicit predicate did not win over the env var")
		}
	})

	t.Run("env_values", func(t *testing.T) {
		for _, tc := range []struct {
			raw  string
			want bool
		}{
			{"1", true}, {"true", true}, {"TRUE", true}, {" yes ", true}, {"on", true},
			{"", false}, {"0", false}, {"false", false}, {"no", false}, {"maybe", false},
		} {
			t.Setenv("CHAINSAW_OFFLINE", tc.raw)
			if got := resolveOfflineCheck(nil)(); got != tc.want {
				t.Errorf("CHAINSAW_OFFLINE=%q → %v, want %v", tc.raw, got, tc.want)
			}
		}
	})

	t.Run("env_read_per_call", func(t *testing.T) {
		t.Setenv("CHAINSAW_OFFLINE", "")
		check := resolveOfflineCheck(nil)
		if check() {
			t.Fatal("unset env read as offline")
		}
		t.Setenv("CHAINSAW_OFFLINE", "1")
		if !check() {
			t.Fatal("predicate cached the env var at construction; a runtime flip must take effect")
		}
	})
}
