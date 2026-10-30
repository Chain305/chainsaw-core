package intelligence

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// The dependency walk is bounded process-wide: at most depEnqueueConcurrency
// at once, one walk per eco|name, and a full budget skips (and counts)
// instead of parking a goroutine.
func TestDepEnqueueBudgetAndDedup(t *testing.T) {
	before := DepEnqueueSkippedCount()
	var keys []string
	for i := 0; i < depEnqueueConcurrency; i++ {
		k := fmt.Sprintf("npm|budget-%d", i)
		if !tryStartDep(k) {
			t.Fatalf("slot %d refused below the budget", i)
		}
		keys = append(keys, k)
	}
	if tryStartDep("npm|budget-over") {
		t.Fatal("a dependency started past the process-wide budget")
	}
	if got := DepEnqueueSkippedCount() - before; got != 1 {
		t.Fatalf("skipped counter moved by %d, want 1", got)
	}
	finishDep(keys[0])
	if tryStartDep(keys[1]) {
		t.Fatal("the same dependency started twice while its first walk is in flight")
	}
	if !tryStartDep("npm|budget-over") {
		t.Fatal("a freed slot was not reusable")
	}
	finishDep("npm|budget-over")
	for _, k := range keys[1:] {
		finishDep(k)
	}
}

// The cache-warm and the dependency walk used to restart each other's depth:
// the warm scanned on a context with no dependency depth (so the walk began
// again at 0), and the walk's children left WarmDepth at 0 (so each one
// warmed). Source guard: catches either line being deleted.
func TestDepWalkAndCacheWarmDoNotRestartEachOther(t *testing.T) {
	for file, want := range map[string]string{
		"cache_warm.go":   "bg = withDepDepth(bg, maxAutoDepDepth)",
		"dep_enqueuer.go": "WarmDepth: maxWarmDepth,",
	} {
		src, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), want) {
			t.Errorf("%s no longer contains %q", file, want)
		}
	}
}
