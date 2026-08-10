package coverage

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The failure this file exists to prevent: an operator sets
//
//	CHAINSAW_COVERAGE_MODE=closed
//	CHAINSAW_COVERAGE_REQUIRED=malware,checksum
//
// on the registry proxy. The proxy's hot-path scan runs with Artifact=nil, so
// the checksum provider emits "needs_artifact", which classifies as
// StatusNotApplicable, which never blocks. The operator believes they have a
// mandatory checksum control; they have an inert one. That must be impossible
// to configure, and it must fail loudly at startup rather than at 3am.
func TestValidateForSurface(t *testing.T) {
	metadataOnly := MetadataOnlySources()

	cases := []struct {
		name       string
		posture    Posture
		surface    string
		attestable []Source
		wantErr    bool
		// wantUnattestable is the exact set the error must name.
		wantUnattestable []Source
	}{
		{
			name:       "off never errors even when the required set is nonsense",
			posture:    Posture{Version: 1, Mode: ModeOff, Required: []Source{SourceChecksum}},
			surface:    "proxy",
			attestable: metadataOnly,
			wantErr:    false,
		},
		{
			name: "closed with only attestable sources is fine",
			posture: Posture{
				Version: 1, Mode: ModeClosed,
				Required:     []Source{SourceMalware, SourceCVE},
				Grace:        DefaultGrace,
				MaxLedgerAge: DefaultMaxLedgerAge,
			},
			surface:    "proxy",
			attestable: metadataOnly,
			wantErr:    false,
		},
		{
			name: "closed requiring an artifact-bound source on a metadata-only surface",
			posture: Posture{
				Version: 1, Mode: ModeClosed,
				Required:     []Source{SourceMalware, SourceChecksum},
				Grace:        DefaultGrace,
				MaxLedgerAge: DefaultMaxLedgerAge,
			},
			surface:          "proxy",
			attestable:       metadataOnly,
			wantErr:          true,
			wantUnattestable: []Source{SourceChecksum},
		},
		{
			// warn is a dry run OF closed. A dry run of a control that could
			// never fire teaches the operator that their block rate is zero
			// and hands them false confidence — the same failure, delayed.
			name: "warn is validated exactly like closed",
			posture: Posture{
				Version: 1, Mode: ModeWarn,
				Required:     []Source{SourceInstallScripts},
				Grace:        DefaultGrace,
				MaxLedgerAge: DefaultMaxLedgerAge,
			},
			surface:          "publish",
			attestable:       metadataOnly,
			wantErr:          true,
			wantUnattestable: []Source{SourceInstallScripts},
		},
		{
			name: "every unattestable source is reported, not just the first",
			posture: Posture{
				Version: 1, Mode: ModeClosed,
				Required:     []Source{SourceHiddenUnicode, SourceMalware, SourceChecksum, SourceInstallScripts},
				Grace:        DefaultGrace,
				MaxLedgerAge: DefaultMaxLedgerAge,
			},
			surface:    "proxy",
			attestable: metadataOnly,
			wantErr:    true,
			// sorted, so the message is stable
			wantUnattestable: []Source{SourceChecksum, SourceHiddenUnicode, SourceInstallScripts},
		},
		{
			name: "a surface that attests nothing rejects every required source",
			posture: Posture{
				Version: 1, Mode: ModeClosed,
				Required:     []Source{SourceMalware},
				Grace:        DefaultGrace,
				MaxLedgerAge: DefaultMaxLedgerAge,
			},
			surface:          "mystery",
			attestable:       nil,
			wantErr:          true,
			wantUnattestable: []Source{SourceMalware},
		},
		{
			// ValidateForSurface must not be a way to skip Validate.
			name: "base validation still applies",
			posture: Posture{
				Version: 1, Mode: ModeClosed,
				Required:     []Source{SourceMalware},
				Grace:        time.Hour,
				MaxLedgerAge: time.Minute,
			},
			surface:    "proxy",
			attestable: metadataOnly,
			wantErr:    true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.posture.ValidateForSurface(tc.surface, tc.attestable)
			if tc.wantErr != (err != nil) {
				t.Fatalf("ValidateForSurface() error = %v, wantErr %v", err, tc.wantErr)
			}
			if !tc.wantErr || tc.wantUnattestable == nil {
				return
			}
			var ue *UnattestableSourcesError
			if !errors.As(err, &ue) {
				t.Fatalf("error %v is not an *UnattestableSourcesError", err)
			}
			if len(ue.Sources) != len(tc.wantUnattestable) {
				t.Fatalf("Sources = %v, want %v", ue.Sources, tc.wantUnattestable)
			}
			for i, s := range tc.wantUnattestable {
				if ue.Sources[i] != s {
					t.Fatalf("Sources = %v, want %v", ue.Sources, tc.wantUnattestable)
				}
			}
			if ue.Surface != tc.surface {
				t.Errorf("Surface = %q, want %q", ue.Surface, tc.surface)
			}
			// The message has to be actionable without reading the source:
			// which surface, which sources, and what is available instead.
			msg := err.Error()
			for _, want := range []string{tc.surface, string(tc.wantUnattestable[0]), EnvRequired} {
				if !strings.Contains(msg, want) {
					t.Errorf("error message %q does not mention %q", msg, want)
				}
			}
		})
	}
}

// Every v1 source must be classified as either metadata-only or artifact-bound.
// Adding a source to the allowlist without classifying it would silently make
// it unattestable everywhere (a surface that can attest it would still reject
// it), so this is a drift guard, not a tautology.
func TestAttestationPartitionsTheAllowlist(t *testing.T) {
	seen := map[Source]int{}
	for _, s := range MetadataOnlySources() {
		seen[s]++
	}
	for _, s := range ArtifactBoundSources() {
		seen[s]++
	}
	for _, s := range AllSources() {
		switch seen[s] {
		case 0:
			t.Errorf("source %q is in the v1 allowlist but classified neither metadata-only nor artifact-bound", s)
		case 1:
		default:
			t.Errorf("source %q is classified in both partitions", s)
		}
		delete(seen, s)
	}
	for s := range seen {
		t.Errorf("source %q is classified but not in the v1 allowlist", s)
	}
}

// The returned slices must be copies: a caller that sorts or appends to them
// must not corrupt the classification for every other surface in the process.
func TestAttestationSlicesAreCopies(t *testing.T) {
	a := MetadataOnlySources()
	orig := a[0]
	a[0] = Source("clobbered")
	if MetadataOnlySources()[0] != orig {
		t.Fatal("MetadataOnlySources returns shared backing state")
	}
	b := ArtifactBoundSources()
	origB := b[0]
	b[0] = Source("clobbered")
	if ArtifactBoundSources()[0] != origB {
		t.Fatal("ArtifactBoundSources returns shared backing state")
	}
}
