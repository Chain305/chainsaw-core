// Command osv-bundle-gen builds the OSV advisory bundle that
// core/intelligence's offline CVE provider reads.
//
//	osv-bundle-gen --out ./osv-bundle.json.gz
//	CHAINSAW_OSV_BUNDLE_PATH=$PWD/osv-bundle.json.gz <your binary or test>
//
// ─── WHY THIS EXISTS ────────────────────────────────────────────────────────
//
// provider_osv.go resolves its bundle from CHAINSAW_OSV_BUNDLE_PATH, else
// /system/osv-bundle.json.gz — a path the Dockerfile bakes. Outside that
// image the file does not exist, the provider stays DORMANT, and its
// Supports() still returns true so the matrix looks covered while Run()
// returns an empty PartialReport.
//
// That is a silent zero, and it was measured rather than theorised: a
// 20-coordinate pilot of the comparison harness, with every other provider
// correctly wired, detected 10 of 10 known-malicious packages and found
// CVEs on 0 of 10 coordinates that OSV itself lists as vulnerable. Without
// a bundle, any CVE comparison reports a total coverage failure that is
// entirely an artifact of the instrument -- the same shape as the withdrawn
// F-1 finding in docs/REPORTS.md#socket-comparison-2026-09-14-rev2, where a dormant
// provider was read as engine silence.
//
// The same gap applies to airgapped and self-hosted deployments, which is
// why this is a tool rather than a line in a test fixture.
//
// ─── IT REFUSES TO WRITE A BUNDLE THAT WOULD READ AS DORMANT ────────────────
//
// An empty or near-empty bundle loads cleanly and is indistinguishable
// downstream from no bundle at all, so --min-advisories (default 10,000) is
// a floor, not a formality. Below it the tool exits 2 -- DID NOT RUN --
// rather than leaving a file that makes the provider look healthy.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/chain305/chainsaw-core/intelligence/osv"
)

func main() {
	out := flag.String("out", "./osv-bundle.json.gz", "destination path for the bundle")
	base := flag.String("base", "", "upstream base URL (default: OSV's public bucket); point at a local mirror serving <base>/<ecosystem>/all.zip to build offline")
	minAdv := flag.Int("min-advisories", 10000, "refuse to write a bundle with fewer advisories than this; a thin bundle is indistinguishable from a dormant one")
	timeout := flag.Duration("timeout", 20*time.Minute, "overall budget; the archives total ~280 MB")
	flag.Parse()

	abs, err := filepath.Abs(*out)
	if err != nil {
		fail("resolve --out: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		fail("create %s: %v", filepath.Dir(abs), err)
	}

	// CHAINSAW_OFFLINE makes NewRefresher return nil, and Start on a nil
	// receiver is a documented no-op -- so without this check the tool
	// would exit 0 having written nothing at all.
	if v := os.Getenv("CHAINSAW_OFFLINE"); v != "" && v != "0" && v != "false" {
		fail("CHAINSAW_OFFLINE=%s disables the refresher; unset it to build a bundle", v)
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	done := make(chan *osv.Index, 1)
	r := osv.NewRefresher(osv.RefresherConfig{
		Path:     abs,
		BaseURL:  *base,
		Interval: 24 * time.Hour, // irrelevant: we stop after the first tick
		Logger:   logger,
		Swap: func(idx *osv.Index) {
			select {
			case done <- idx:
			default:
			}
		},
	})
	if r == nil {
		fail("refresher construction returned nil (offline, kill-switch, or %s is not writable)", filepath.Dir(abs))
	}

	fmt.Fprintf(os.Stderr, "building OSV bundle -> %s\n", abs)
	r.Start(ctx)

	select {
	case idx := <-done:
		n := idx.Total()
		if n < *minAdv {
			os.Remove(abs)
			fail("bundle held %d advisories, below the %d floor — refusing to leave a file that "+
				"makes the provider look healthy while it answers nothing", n, *minAdv)
		}
		st, _ := os.Stat(abs)
		size := int64(0)
		if st != nil {
			size = st.Size()
		}
		fmt.Printf("advisories: %d\nbytes:      %d\npath:       %s\n\nUse it:\n  CHAINSAW_OSV_BUNDLE_PATH=%s\n",
			n, size, abs, abs)
	case <-ctx.Done():
		fail("timed out after %s before the first refresh completed", *timeout)
	}
}

// fail exits 2 — DID NOT RUN — never 1 and never 0. Every failure here means
// no usable bundle was produced, and a caller must be able to tell that from
// "built a bundle that happens to be small".
func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "DID NOT RUN: "+format+"\n", args...)
	os.Exit(2)
}
