package cli

import "testing"

// TestHasSupplyChainSection covers the gate that decides whether to
// print the "Supply chain signals" section of `pkg info`. A BOM entry
// with only legacy fields should not trigger the section (the legacy
// fields are already rendered by the existing code).
func TestHasSupplyChainSection(t *testing.T) {
	truePtr := func() *bool { v := true; return &v }

	legacyOnly := bomEntry{
		PackageName:      "foo",
		PackageVersion:   "1.0.0",
		TrustScore:       nil,
		ProvenanceStatus: "verified",
		MalwareStatus:    "clean",
	}
	if hasSupplyChainSection(legacyOnly) {
		t.Fatalf("legacy-only entry should not trigger supply-chain section")
	}

	cases := []struct {
		name string
		in   bomEntry
	}{
		{"install script", bomEntry{InstallScriptKind: "present"}},
		{"publisher set", bomEntry{PublisherSet: []string{"alice"}}},
		{"publisher changed", bomEntry{PublisherChanged: truePtr()}},
		{"version anomaly", bomEntry{VersionAnomalyFlags: []string{"semver_regression"}}},
		{"hidden unicode", bomEntry{HiddenUnicodeHits: 2}},
		{"publish velocity", bomEntry{PublishVelocity24h: 30}},
		{"repo link timestamp", bomEntry{RepoLinkLastCheckedAt: "2026-04-17T00:00:00Z"}},
		{"checksum declared", bomEntry{ChecksumDeclared: "sha256:abc"}},
		{"checksum actual", bomEntry{ChecksumActual: "sha256:def"}},
		{"trust breakdown", bomEntry{TrustScoreBreakdown: `{"score":50}`}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !hasSupplyChainSection(tc.in) {
				t.Fatalf("expected section for %+v", tc.in)
			}
		})
	}
}

func TestTruncateHashPkg(t *testing.T) {
	if got := truncateHashPkg(""); got != "—" {
		t.Fatalf("empty → em-dash, got %q", got)
	}
	if got := truncateHashPkg("short"); got != "short" {
		t.Fatalf("short pass-through, got %q", got)
	}
	long := "0123456789abcdef0123456789abcdef"
	if got := truncateHashPkg(long); got != "0123456789abcdef0123..." {
		t.Fatalf("truncate long: got %q", got)
	}
}
