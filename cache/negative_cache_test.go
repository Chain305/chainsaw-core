package cache

import (
	"testing"
	"time"
)

// TestNegativeCacheStoresUTC confirms that the negative cache records
// expiry instants in UTC, so cross-package comparisons against
// CURRENT_TIMESTAMP DB rows (also UTC) don't drift on non-UTC hosts.
// Regression guard for finding X-X5.
func TestNegativeCacheStoresUTC(t *testing.T) {
	c := NewNegativeCache(5 * time.Minute)
	c.Remember("some/path")
	c.mu.RLock()
	expiry, ok := c.entries["some/path"]
	c.mu.RUnlock()
	if !ok {
		t.Fatal("expected entry to be present")
	}
	if loc := expiry.Location(); loc != time.UTC {
		t.Fatalf("expected expiry to be in UTC, got %v", loc)
	}
}
