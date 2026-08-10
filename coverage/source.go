package coverage

import "fmt"

// Source is a data source whose availability an operator can require.
//
// Sources are NOT risk signal IDs. A risk signal (sc.known_malicious,
// vuln.kev) is a scoring rule that fires or does not; several of them share
// one producer, and a positive signal like sc.provenance_verified legitimately
// does not fire on most packages. Availability is a property of the producer,
// so that is what the operator declares. See decision D2 in
// docs/plan_optional_fail_closed.md.
type Source string

const (
	SourceMalware          Source = "malware"
	SourceCVE              Source = "cve"
	SourceTyposquat        Source = "typosquat"
	SourceProvenance       Source = "provenance"
	SourceRegistryMetadata Source = "registry_metadata"
	SourceChecksum         Source = "checksum"
	SourceInstallScripts   Source = "install_scripts"
	SourceHiddenUnicode    Source = "hidden_unicode"
)

// v1Allowlist is the set an operator may require in config version 1.
//
// Deliberately excludes derived / post-merge signals (KEV, maintenance, the
// transitive overlay): their availability is a dependency graph rather than a
// single producer, so a truthful status cannot be computed for them yet.
// Widening this set later requires modelling that graph, not just adding a row.
var v1Allowlist = map[Source]bool{
	SourceMalware:          true,
	SourceCVE:              true,
	SourceTyposquat:        true,
	SourceProvenance:       true,
	SourceRegistryMetadata: true,
	SourceChecksum:         true,
	SourceInstallScripts:   true,
	SourceHiddenUnicode:    true,
}

// AllSources returns the v1 allowlist in a stable order, for help text and
// error messages.
func AllSources() []Source {
	return []Source{
		SourceMalware, SourceCVE, SourceTyposquat, SourceProvenance,
		SourceRegistryMetadata, SourceChecksum, SourceInstallScripts,
		SourceHiddenUnicode,
	}
}

// ParseSource validates a configured source name. Unknown names are a config
// error, never a silent no-op: an operator who typos a required source must
// find out at startup, not discover months later that the control was inert.
func ParseSource(name string) (Source, error) {
	s := Source(name)
	if !v1Allowlist[s] {
		return "", fmt.Errorf("coverage: unknown source %q (valid: %v)", name, AllSources())
	}
	return s, nil
}
