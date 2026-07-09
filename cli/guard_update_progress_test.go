package cli

// Regression for the 2026-07 guard-update UX fix: the post-download phase
// (walk + parse ~200k OSV files, then write a ~200 MB cache) used to run
// silently and looked like a hang. collectOSVEntries now reports a running
// count, and the install path no longer prompts-and-downloads the full feed
// inline. These cover the count formatting and the progress-callback wiring.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHumanCount(t *testing.T) {
	cases := map[int]string{
		0:       "0",
		7:       "7",
		999:     "999",
		1000:    "1,000",
		12345:   "12,345",
		228044:  "228,044",
		1000000: "1,000,000",
	}
	for in, want := range cases {
		if got := humanCount(in); got != want {
			t.Errorf("humanCount(%d) = %q, want %q", in, got, want)
		}
	}
}

func TestCollectOSVEntriesProgress(t *testing.T) {
	dir := t.TempDir()
	// A handful of valid OSV JSON files plus noise that must be skipped.
	const valid = 5
	for i := 0; i < valid; i++ {
		p := filepath.Join(dir, "MAL-000"+string(rune('0'+i))+".json")
		if err := os.WriteFile(p, []byte(`{"id":"MAL-000`+string(rune('0'+i))+`"}`), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Non-JSON and a subdir — both must be ignored by the walker.
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "nested"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Shrink the heartbeat so a small fixture exercises the callback.
	prev := osvIndexProgressStep
	osvIndexProgressStep = 2
	t.Cleanup(func() { osvIndexProgressStep = prev })

	var ticks []int
	entries := collectOSVEntries(dir, func(n int) { ticks = append(ticks, n) })

	if len(entries) != valid {
		t.Fatalf("parsed %d entries, want %d", len(entries), valid)
	}
	// With step=2 over 5 entries, the callback fires at 2 and 4.
	if len(ticks) != 2 || ticks[0] != 2 || ticks[1] != 4 {
		t.Fatalf("progress ticks = %v, want [2 4]", ticks)
	}
}

func TestCollectOSVEntriesNilCallback(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.json"), []byte(`{"id":"MAL-1"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	// A nil callback must not panic (the guard's non-verbose paths pass nil).
	if got := collectOSVEntries(dir, nil); len(got) != 1 {
		t.Fatalf("parsed %d entries with nil callback, want 1", len(got))
	}
}
