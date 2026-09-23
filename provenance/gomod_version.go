package provenance

// Canonical Go module versions, in ONE place.
//
// Go lockfile parsers strip the leading "v" so their coordinates dedup against
// each other and match how vulnerability databases index semver. Everything
// upstream of Go — the module proxy AND the checksum database — requires
// canonical semver WITH the prefix, and answers a bare version with an error:
//
//	sum.golang.org/lookup/github.com/spf13/pflag@1.0.3   -> HTTP 400
//	sum.golang.org/lookup/github.com/spf13/pflag@v1.0.3  -> HTTP 200
//
// Measured in prod 2026-09-23: 5,905 of 6,056 failed Go attestations were
// HTTP 400 from sum.golang.org, which is 39% of every failed attestation in
// the corpus and the single largest cause of signal_repair S-2's "attestation
// fails on 67% of everything". It is not a verification failure at all — the
// request was malformed and the sumdb never got as far as looking.
//
// This is the THIRD site to hit the same bug. GoModuleZipPath's own comment
// records the second ("the artifact path had the prefix problem the METADATA
// path had already solved ... because each rebuilt the URL for itself"), so a
// third private copy would be repeating the diagnosis rather than fixing it.
// It lives here, in the lowest package of the three, because core/intelligence
// already imports core/provenance and the reverse would cycle.

import (
	"strings"

	"golang.org/x/mod/semver"
)

// CanonicalGoVersion restores the leading "v" a lockfile parser stripped and
// reports whether the result is canonical semver.
//
// ok is false rather than a best-effort string for anything upstream cannot
// answer — a pseudo-version fragment, "latest", or a branch name reaching here
// is a bug in the caller, and issuing the request anyway spends a rate-limited
// upstream call on a guaranteed error AND records the rejection as if the
// package's provenance had failed verification.
func CanonicalGoVersion(version string) (string, bool) {
	version = strings.TrimSpace(version)
	if version == "" {
		return "", false
	}
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}
	// semver.IsValid accepts "+incompatible" and pseudo-versions, both of
	// which the sumdb answers, so this rejects only what is genuinely
	// unusable.
	if !semver.IsValid(version) {
		return "", false
	}
	return version, true
}
