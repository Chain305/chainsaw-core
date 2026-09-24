package pgstore

import (
	"os"
	"strings"
	"testing"
)

// The read pool must not inherit the writable pool's 50 connections: with a
// read DSN set and no size given, 50 read + 50-60 write exceeds Postgres's
// usual max_connections of 100, so the pool meant to survive saturation would
// cause it.
func TestReadPoolDefaultsAreItsOwn(t *testing.T) {
	got := PoolConfig{}.applyReadDefaults()
	if got.MaxOpenConns != defaultReadMaxOpenConns || got.MaxIdleConns != defaultReadMaxIdleConns {
		t.Fatalf("read defaults = %d open / %d idle, want %d / %d",
			got.MaxOpenConns, got.MaxIdleConns, defaultReadMaxOpenConns, defaultReadMaxIdleConns)
	}
	if write := defaultPoolConfig().MaxOpenConns; got.MaxOpenConns+write > 100 {
		t.Errorf("default read (%d) + write (%d) connections exceed max_connections=100", got.MaxOpenConns, write)
	}
	if got.ConnMaxLifetime == 0 || got.ConnMaxIdleTime == 0 {
		t.Error("the remaining fields must still take the shared defaults")
	}
	explicit := PoolConfig{MaxOpenConns: 3, MaxIdleConns: 1}.applyReadDefaults()
	if explicit.MaxOpenConns != 3 || explicit.MaxIdleConns != 1 {
		t.Errorf("explicit sizing overridden: %+v", explicit)
	}
}

// The helper alone is not the guarantee: OpenWithConfig has to call it. This
// reads the size off the pool it actually opened.
func TestOpenWithConfigSizesTheReadPoolItself(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("CHAINSAW_DATABASE_URL"))
	if dsn == "" {
		if os.Getenv("CHAINSAW_TEST_REQUIRE_DB") != "" {
			t.Fatal("CHAINSAW_TEST_REQUIRE_DB is set but CHAINSAW_DATABASE_URL is empty")
		}
		t.Skip("CHAINSAW_DATABASE_URL not set; skipping database test")
	}
	s, err := OpenWithConfig(dsn, dsn, PoolConfig{}, PoolConfig{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if got := s.ReadDB().Stats().MaxOpenConnections; got != defaultReadMaxOpenConns {
		t.Errorf("read pool opened with MaxOpenConns=%d, want %d", got, defaultReadMaxOpenConns)
	}
	if s.ReadDB() == s.DB() {
		t.Error("a read DSN was given but ReadDB aliases the writable pool")
	}
}
