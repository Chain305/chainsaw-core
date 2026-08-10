package coverage

import (
	"fmt"
	"sort"
	"strings"
)

// Surface attestation.
//
// Gate can only refuse on a source that the surface actually consults. If a
// surface never reads artifact bytes, its artifact-bound providers emit
// "needs_artifact", which StatusForWarnCode classifies as StatusNotApplicable,
// which never blocks. An operator who requires `checksum` on such a surface
// therefore gets a control that is silently, permanently inert — the exact
// failure this whole feature exists to prevent, dressed up as the fix for it.
//
// The rule: a surface declares what it can attest, and requiring anything
// outside that set is a CONFIG error surfaced at startup. Not a silent pass
// (the operator would never learn), and not a standing block (a knob that
// refuses every install forever is indistinguishable from an outage, and it
// punishes the operator for a typo instead of telling them about it).
//
// See "Surface attestation rule" in docs/plan_optional_fail_closed.md.

// metadataOnlySources are attestable by any surface that evaluates a package
// coordinate without reading the artifact bytes: the registry-proxy hot path
// (which scans with Artifact=nil to keep installs fast) and the publish
// pre-run (Tier-1 only). All five are Tier-1 providers.
var metadataOnlySources = []Source{
	SourceMalware,
	SourceCVE,
	SourceTyposquat,
	SourceProvenance,
	SourceRegistryMetadata,
}

// artifactBoundSources need the bytes. Their providers are Tier 2 and emit
// "needs_artifact" when the request carries no artifact, so a metadata-only
// surface can never truthfully say whether they were evaluable.
var artifactBoundSources = []Source{
	SourceChecksum,
	SourceInstallScripts,
	SourceHiddenUnicode,
}

// MetadataOnlySources returns the sources a metadata-only surface can attest.
// The result is a fresh slice; callers may sort or append to it freely.
func MetadataOnlySources() []Source {
	out := make([]Source, len(metadataOnlySources))
	copy(out, metadataOnlySources)
	return out
}

// ArtifactBoundSources returns the sources that require the artifact bytes and
// are therefore NOT attestable on a metadata-only surface. The result is a
// fresh slice.
func ArtifactBoundSources() []Source {
	out := make([]Source, len(artifactBoundSources))
	copy(out, artifactBoundSources)
	return out
}

// UnattestableSourcesError reports required sources a surface cannot observe.
//
// Callers MUST treat this as fatal at startup. Returning it from a request
// path and continuing would leave the operator with an inert control; blocking
// every request on it would turn a typo into an outage.
type UnattestableSourcesError struct {
	// Surface is the caller-supplied label, used only in the message.
	Surface string
	// Sources are the required-but-unattestable names, sorted.
	Sources []Source
	// Attestable is what this surface can observe, in declaration order.
	Attestable []Source
}

func (e *UnattestableSourcesError) Error() string {
	return fmt.Sprintf(
		"coverage: surface %q cannot attest required source(s) %s — requiring them here yields a control that can never fire, so this is refused rather than silently ignored; "+
			"remove them from %s (this surface can attest %s), or enforce them on a surface that reads artifact bytes",
		e.Surface,
		joinSources(e.Sources),
		EnvRequired,
		joinSources(e.Attestable),
	)
}

// ValidateForSurface is Validate plus the surface-attestation rule.
//
// Every surface that wires the gate MUST call this at startup with the set it
// can actually observe, and MUST refuse to start on error (decision D3). A
// ModeOff posture always validates: with the gate off there is nothing to be
// inert about.
func (p Posture) ValidateForSurface(surface string, attestable []Source) error {
	if err := p.Validate(); err != nil {
		return err
	}
	if p.Mode == ModeOff {
		return nil
	}

	ok := make(map[Source]bool, len(attestable))
	for _, s := range attestable {
		ok[s] = true
	}
	var bad []Source
	seen := make(map[Source]bool, len(p.Required))
	for _, s := range p.Required {
		if ok[s] || seen[s] {
			continue
		}
		seen[s] = true
		bad = append(bad, s)
	}
	if len(bad) == 0 {
		return nil
	}
	sort.Slice(bad, func(i, j int) bool { return bad[i] < bad[j] })
	return &UnattestableSourcesError{
		Surface:    surface,
		Sources:    bad,
		Attestable: attestable,
	}
}

func joinSources(ss []Source) string {
	if len(ss) == 0 {
		return "nothing"
	}
	names := make([]string, len(ss))
	for i, s := range ss {
		names[i] = string(s)
	}
	return strings.Join(names, ", ")
}
