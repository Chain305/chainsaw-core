package provenance

import (
	"context"
	"log/slog"
	"net/http"
)

// absentChecker is used by ecosystems that don't have a verifier-
// consumable attestation standard at all. The previous behavior was a
// silent "unavailable"; we now return StatusUnavailable with a specific
// explanation so the UI can distinguish "we haven't written a checker"
// from "this ecosystem has no standard to check against."
type absentChecker struct {
	ecosystem string
	reason    string
}

func newCargoChecker(_ *http.Client, _ *slog.Logger) *absentChecker {
	return &absentChecker{
		ecosystem: "cargo",
		reason:    "crates.io has Trusted Publishing OIDC identity server-side but no attestation is exposed to downstream verifiers as of 2026",
	}
}

func newComposerChecker(_ *http.Client, _ *slog.Logger) *absentChecker {
	return &absentChecker{
		ecosystem: "composer",
		reason:    "Packagist has no per-package attestation standard; only integrity hashes are available",
	}
}

func newCocoaPodsChecker(_ *http.Client, _ *slog.Logger) *absentChecker {
	return &absentChecker{
		ecosystem: "cocoapods",
		reason:    "CocoaPods specs carry optional integrity hashes only; no publisher-signed attestations exist",
	}
}

func (c *absentChecker) Ecosystem() string { return c.ecosystem }

func (c *absentChecker) Check(_ context.Context, _ string, _ string) Result {
	return Result{
		Status:    StatusUnavailable,
		Ecosystem: c.ecosystem,
		Error:     c.reason,
	}
}
