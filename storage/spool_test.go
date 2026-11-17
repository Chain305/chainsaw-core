package storage

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func withSpoolBudget(t *testing.T, n int64) {
	t.Helper()
	prev := spoolBudget
	spoolBudget = func() int64 { return n }
	t.Cleanup(func() { spoolBudget = prev })
	if used := spoolUsed.Load(); used != 0 {
		t.Fatalf("spool bytes leaked by an earlier test: %d", used)
	}
}

// TestScanSpoolSharesOneProcessBudget reproduces R2-G2: the scan spool was
// capped per artifact only, so N concurrent fills could each take up to the
// stream limit of /tmp and together evict the pod. A second spool that
// would push the process past the budget must be refused (fail closed: the
// artifact is not scanned and not stored), and bytes return to the budget
// when the spool file is removed.
func TestScanSpoolSharesOneProcessBudget(t *testing.T) {
	withSpoolBudget(t, 100)
	inner := &testStorageFacet{}
	facet := NewScanningStorage(inner, nil, &testContentScanner{enabled: true})
	meta := ContentMetadata{PackageName: "pkg", PackageVersion: "1.0.0"}

	// Another spool (an upload, a concurrent fill) holds 60 bytes.
	other := NewSpoolWriter(&bytes.Buffer{})
	if _, err := other.Write(make([]byte, 60)); err != nil {
		t.Fatal(err)
	}
	before := SpoolBudgetRejections()
	_, err := facet.Put(context.Background(), "pkg/-/pkg-1.0.0.tgz", strings.NewReader(strings.Repeat("x", 50)), meta)
	if !errors.Is(err, ErrSpoolBudgetExhausted) {
		t.Fatalf("Put over the shared budget: err = %v, want ErrSpoolBudgetExhausted", err)
	}
	if inner.puts != 0 {
		t.Fatal("an artifact that could not be spooled for scanning was stored")
	}
	if SpoolBudgetRejections() != before+1 {
		t.Fatalf("rejections = %d, want %d", SpoolBudgetRejections(), before+1)
	}
	if got := SpoolBytesInUse(); got != 60 {
		t.Fatalf("after the refused Put, bytes in use = %d, want the other spool's 60", got)
	}

	other.Release()
	other.Release() // idempotent
	if _, err := facet.Put(context.Background(), "pkg/-/pkg-1.0.0.tgz", strings.NewReader(strings.Repeat("x", 50)), meta); err != nil {
		t.Fatalf("Put with the budget free: %v", err)
	}
	if inner.puts != 1 || inner.data != strings.Repeat("x", 50) {
		t.Fatalf("stored %d puts, %q", inner.puts, inner.data)
	}
	if got := SpoolBytesInUse(); got != 0 {
		t.Fatalf("a finished spool kept %d bytes of the budget", got)
	}
}

func TestSpoolBudgetFromEnv(t *testing.T) {
	for _, c := range []struct {
		explicit, ephemeral string
		want                int64
	}{
		{"", "", DefaultSpoolBudget},
		{"1048576", "8589934592", 1048576},
		{"", "4294967296", 1 << 30},
		{"junk", "", DefaultSpoolBudget},
		{"-5", "0", DefaultSpoolBudget},
	} {
		t.Setenv(SpoolBudgetEnv, c.explicit)
		t.Setenv(EphemeralStorageLimitEnv, c.ephemeral)
		if got := spoolBudgetFromEnv(); got != c.want {
			t.Errorf("explicit=%q ephemeral=%q: budget %d, want %d", c.explicit, c.ephemeral, got, c.want)
		}
	}
}
