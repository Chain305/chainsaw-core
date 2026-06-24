package intelligence

import (
	"context"
	"sync/atomic"
	"testing"
)

// TestScan_Ephemeral_DoesNotPersistSharedReport is the cache-poisoning
// regression for the direct artifact-upload API.
//
// THREAT: an uploaded artifact declares a client-asserted coordinate
// (e.g. npm:left-pad@1.3.0). The artifact scan reuses intelligence.Scan
// with the uploaded bytes. Before the fix, Scan unconditionally wrote the
// resulting Report into the shared, coordinate-keyed intelligence_reports
// store (store.Upsert) AND ran the reportSink denormaliser. An attacker
// could therefore overwrite/poison the authoritative report that PROXY and
// REGISTRY coordinate-keyed reads consume — a cross-tenant integrity break.
//
// The fix adds Options.Ephemeral, which the artifact-upload path sets. In
// Ephemeral mode the full fan-out still runs and the Report is returned,
// but the shared persistence side effects (store.Upsert + reportSink) are
// never invoked.
//
// We observe persistence via the reportSink hook because it fires inside
// the exact same branch as store.Upsert (the DB-backed Upsert needs a live
// Postgres; the sink is a faithful, zero-dependency proxy for "the shared
// persistence path ran"). The test FAILS before the fix (sink fires in
// both modes) and PASSES after (sink fires only in the non-ephemeral mode).
func TestScan_Ephemeral_DoesNotPersistSharedReport(t *testing.T) {
	makeSvc := func(sink *int64) *DefaultService {
		// A normal byte-signal provider standing in for the Tier-2 scanners.
		p := &fakeProvider{
			name:   "fake-malware",
			signal: SignalMalware,
			partial: PartialReport{
				SupplyChain: &SupplyChainSection{MalwareStatus: "clean"},
			},
		}
		svc := New(Config{Providers: []Provider{p}})
		svc.SetReportSink(func(_ context.Context, _ string, _ *Report) {
			atomic.AddInt64(sink, 1)
		})
		return svc
	}

	// The client-asserted coordinate an attacker would target: a real,
	// popular package. A proxy scan of this same coordinate must NOT see a
	// row authored by the upload.
	poisonKey := Key{Ecosystem: "npm", Package: "left-pad", Version: "1.3.0"}

	t.Run("non-ephemeral scan persists (baseline)", func(t *testing.T) {
		var sinkCalls int64
		svc := makeSvc(&sinkCalls)
		report, err := svc.Scan(context.Background(), Request{
			Key:   poisonKey,
			OrgID: "org-victim",
		})
		if err != nil {
			t.Fatalf("Scan err: %v", err)
		}
		if report == nil {
			t.Fatalf("nil report")
		}
		if got := atomic.LoadInt64(&sinkCalls); got != 1 {
			t.Fatalf("non-ephemeral scan must persist to the shared store exactly once; sink calls = %d", got)
		}
	})

	t.Run("ephemeral artifact-upload scan persists nothing", func(t *testing.T) {
		var sinkCalls int64
		svc := makeSvc(&sinkCalls)
		report, err := svc.Scan(context.Background(), Request{
			Key:   poisonKey, // attacker-declared coordinate for a real package
			OrgID: "org-attacker",
			Artifact: &ArtifactHandle{
				Bytes:  []byte("crafted artifact bytes"),
				SHA256: "deadbeef",
			},
			Options: Options{Ephemeral: true},
		})
		if err != nil {
			t.Fatalf("ephemeral Scan err: %v", err)
		}
		// Functionality preserved: the scan still runs and returns a report
		// with the byte-derived signals.
		if report == nil {
			t.Fatalf("ephemeral scan returned nil report — functionality regressed")
		}
		if got := report.SupplyChain.MalwareStatus; got != "clean" {
			t.Fatalf("ephemeral scan dropped byte signals: MalwareStatus = %q, want clean", got)
		}
		// THE INVARIANT: the shared, coordinate-keyed report store was never
		// written — the proxy's view of left-pad@1.3.0 is untouched.
		if got := atomic.LoadInt64(&sinkCalls); got != 0 {
			t.Fatalf("ephemeral artifact scan wrote to the shared intelligence_reports cache "+
				"(sink calls = %d) — cache-poisoning vulnerability is present", got)
		}
	})
}
