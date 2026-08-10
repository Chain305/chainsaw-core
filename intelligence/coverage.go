package intelligence

import (
	"time"

	"github.com/chain305/chainsaw-core/coverage"
)

// providerToSource maps the Provider.Name() values that appear in
// Report.Observation to the operator-facing coverage sources.
//
// This map lives here, not in core/coverage, so that coverage stays a
// stdlib-only leaf package. coverage_sourcemap_test.go pins the keys against
// the real providers' Name() values and pins the values against the v1
// allowlist.
var providerToSource = map[string]coverage.Source{
	"malware":          coverage.SourceMalware,
	"cve":              coverage.SourceCVE,
	"typosquat":        coverage.SourceTyposquat,
	"provenance":       coverage.SourceProvenance,
	"registrymetadata": coverage.SourceRegistryMetadata,
	"checksum":         coverage.SourceChecksum,
	"installscripts":   coverage.SourceInstallScripts,
	"hiddenunicode":    coverage.SourceHiddenUnicode,
}

// LedgerFromReport derives the coverage picture from a completed Scan.
//
// A provider that appears in ProviderTimings ran, so its source starts at OK;
// a warning against that provider downgrades it via the shared classifier. A
// provider absent from ProviderTimings gets NO entry, because "did not run" is
// not the same claim as "ran and succeeded" — Gate treats an absent entry as
// unavailable, which is the conservative reading.
//
// Timestamps come from Observation.CollectedAt, not from time.Now(): a Report
// served from cache must carry the age of the scan that produced it, or a
// stale-healthy report would vouch for a source that is currently down. That
// age is what Posture.MaxLedgerAge bounds.
func LedgerFromReport(r *Report) coverage.Ledger {
	led := coverage.Ledger{}
	if r == nil {
		return led
	}
	at := r.Observation.CollectedAt

	for _, t := range r.Observation.ProviderTimings {
		src, ok := providerToSource[t.Provider]
		if !ok {
			continue
		}
		led[src] = coverage.Entry{
			Status:     coverage.StatusOK,
			Producer:   t.Provider,
			ObservedAt: at,
			LastOKAt:   at,
		}
	}

	for _, w := range r.Observation.Warnings {
		src, ok := providerToSource[w.Provider]
		if !ok {
			continue
		}
		status := coverage.StatusForWarnCode(w.Code)
		if status == coverage.StatusOK {
			// e.g. not_found — a real answer from the source, not an outage.
			// Leave the OK entry written above alone.
			continue
		}
		prev := led[src]
		// Preserve a GENUINELY EARLIER healthy observation so Gate's grace
		// window can still recognise a blip — but never the OK stamp this
		// same scan wrote in the loop above. A provider that ran and failed at
		// `at` was not OK at `at`, and treating it as such would rescue every
		// fresh failure through the grace window, silently making the gate
		// inert for the whole grace period after every scan.
		//
		// A single Report carries one CollectedAt, so in practice this zeroes
		// LastOKAt: the intelligence producer has no cross-scan history. Grace
		// is therefore a rail for producers that do keep history (the
		// workstation guard); on this path the fresh status stands on its own.
		lastOK := prev.LastOKAt
		if !lastOK.Before(at) {
			lastOK = time.Time{}
		}
		led[src] = coverage.Entry{
			Status:     status,
			Producer:   w.Provider,
			Code:       w.Code,
			ObservedAt: at,
			LastOKAt:   lastOK,
		}
	}
	return led
}
