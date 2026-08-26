package risk

// P8-44, evaluator half: an Input marked SignalsUnavailable that ALSO
// carries a known-malicious verdict must quarantine, not report Unknown.
//
// The malware provider is Tier 1 and needs no artifact, so it runs in
// parallel with registry metadata and its answer is on the merged Report
// even when the registry says the version was never published. Before this
// fix the SignalsUnavailable branch returned first and the verdict was
// discarded — an unpublished or yanked MALICIOUS version, the case you
// most want flagged, came back NOT EVALUATED.

import "testing"

func TestInstantBlockPrecedesUnavailable(t *testing.T) {
	cases := []struct {
		name string
		in   Input
		want Verdict
	}{
		{
			name: "malicious + signals unavailable quarantines",
			in: Input{
				Ecosystem: "npm", Package: "lodahs", Version: "9.9.9",
				SignalsUnavailable: true,
				UnavailableReason:  "version not found in the registry's published versions",
				IsKnownMalicious:   true,
				MalwareID:          "MAL-2024-0001",
			},
			want: VerdictQuarantine,
		},
		{
			name: "checksum mismatch + signals unavailable quarantines",
			in: Input{
				Ecosystem: "npm", Package: "x", Version: "1.0.0",
				SignalsUnavailable: true,
				ChecksumMismatch:   true,
			},
			want: VerdictQuarantine,
		},
		{
			name: "signals unavailable with no instant-block fact stays unknown",
			in: Input{
				Ecosystem: "npm", Package: "x", Version: "9.9.9",
				SignalsUnavailable: true,
			},
			want: VerdictUnknown,
		},
		{
			name: "malicious on a fully-evaluated input still quarantines",
			in: Input{
				Ecosystem: "npm", Package: "x", Version: "1.0.0",
				IsKnownMalicious: true,
			},
			want: VerdictQuarantine,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := EvaluatePackage(tc.in, Options{})
			if ev == nil {
				t.Fatal("EvaluatePackage returned nil")
			}
			if ev.Verdict != tc.want {
				t.Fatalf("Verdict = %q, want %q (summary: %q)",
					ev.Verdict, tc.want, ev.Resolution.Summary)
			}
		})
	}
}

// The rejected fix, stated as a property: an unavailable Input must never
// be scored by the additive signal set. lic.missing + license.unidentified
// fire on an empty Input and were the whole of the fake 86/92 scores.
func TestUnavailableInputIsNeverAdditivelyScored(t *testing.T) {
	ev := EvaluatePackage(Input{
		Ecosystem: "pypi", Package: "requests-python", Version: "1.0.0",
		SignalsUnavailable: true,
	}, Options{})
	if ev.Verdict != VerdictUnknown {
		t.Fatalf("Verdict = %q, want unknown", ev.Verdict)
	}
	if ev.RolledUp.Overall != 0 {
		t.Fatalf("Overall = %d, want 0 — an unavailable Input was scored", ev.RolledUp.Overall)
	}
	for cat, cs := range ev.RolledUp.Categories {
		if cs.DataAvailable {
			t.Errorf("category %s reports DataAvailable on an unavailable Input", cat)
		}
		if len(cs.FiredSignals) != 0 {
			t.Errorf("category %s fired %d signals on an unavailable Input",
				cat, len(cs.FiredSignals))
		}
	}
}

// The instant-block path on an unavailable Input must carry ONLY the
// instant-block signal as evidence. Anything else would be a signal that
// fired on facts nobody fetched.
func TestUnavailableInstantBlockCarriesOnlyTheInstantBlockSignal(t *testing.T) {
	ev := EvaluatePackage(Input{
		Ecosystem: "npm", Package: "lodahs", Version: "9.9.9",
		SignalsUnavailable: true,
		IsKnownMalicious:   true,
	}, Options{})
	total := 0
	for _, cs := range ev.RolledUp.Categories {
		for _, f := range cs.FiredSignals {
			total++
			if f.ID != SignalSCKnownMalicious {
				t.Errorf("unexpected fired signal %q on an unavailable Input", f.ID)
			}
		}
	}
	if total != 1 {
		t.Fatalf("fired %d signals, want exactly 1 (sc.known_malicious)", total)
	}
}
