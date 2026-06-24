package cli

import (
	"reflect"
	"testing"
)

// TestDeriveTriggeredConditions_EachSignal covers the per-signal
// derivation rules in deriveTriggeredConditions. Each sub-test sets
// exactly one supply-chain input and asserts the resulting condition
// name list — drift in the naming convention (e.g. renaming
// "hasInstallScript" → "installScript") breaks this test loudly so
// CI integrations pinning on a specific condition name catch it.
func TestDeriveTriggeredConditions_EachSignal(t *testing.T) {
	truePtr := func() *bool { v := true; return &v }

	tests := []struct {
		name string
		in   scanResultItem
		want []string
	}{
		{
			name: "no signals",
			in:   scanResultItem{Name: "foo", Version: "1.0.0"},
			want: nil,
		},
		{
			name: "install-script present",
			in:   scanResultItem{InstallScriptKind: "present"},
			want: []string{"hasInstallScript"},
		},
		{
			name: "install-script fetches remote implies both",
			in:   scanResultItem{InstallScriptKind: "fetches_remote"},
			want: []string{"hasInstallScript", "installScriptFetchesRemote"},
		},
		{
			name: "install-script eval encoded implies both",
			in:   scanResultItem{InstallScriptKind: "eval_encoded"},
			want: []string{"hasInstallScript", "installScriptFetchesRemote"},
		},
		{
			name: "install-script none does not trigger",
			in:   scanResultItem{InstallScriptKind: "none"},
			want: nil,
		},
		{
			name: "publisher changed",
			in:   scanResultItem{PublisherChanged: truePtr()},
			want: []string{"publisherChanged"},
		},
		{
			name: "version anomaly via flags",
			in:   scanResultItem{VersionAnomalyFlags: []string{"semver_regression"}},
			want: []string{"versionAnomaly"},
		},
		{
			name: "hidden unicode hits",
			in:   scanResultItem{HiddenUnicodeHits: 3},
			want: []string{"hasHiddenUnicode"},
		},
		{
			name: "publish velocity > 0",
			in:   scanResultItem{PublishVelocity24h: 25},
			want: []string{"publishVelocityAnomaly"},
		},
		{
			name: "malware malicious",
			in:   scanResultItem{MalwareStatus: "malicious"},
			want: []string{"malware"},
		},
		{
			name: "typosquat suspected",
			in:   scanResultItem{TyposquatStatus: "suspected"},
			want: []string{"typosquat"},
		},
		{
			name: "repo link missing",
			in:   scanResultItem{RepoLinkStatus: "missing"},
			want: []string{"repoLinkMissing"},
		},
		{
			name: "repo link ownership mismatch",
			in:   scanResultItem{RepoLinkStatus: "ownership_mismatch"},
			want: []string{"repoLinkMissing"},
		},
		{
			name: "repo link archived",
			in:   scanResultItem{RepoLinkStatus: "archived"},
			want: []string{"repoLinkArchived"},
		},
		{
			name: "provenance unverified",
			in:   scanResultItem{ProvenanceStatus: "unverified"},
			want: []string{"provenanceUnverified"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := deriveTriggeredConditions(tc.in)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("deriveTriggeredConditions() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestResolveHighestSeverity_ConditionMap asserts that each supply-chain
// condition contributes the severity level committed to in the product
// decision (documented on supplyChainConditionSeverity). This is the
// load-bearing mapping for `--severity` filter and `--fail-on` gate —
// a silent change here would let supposedly-CI-breaking conditions
// slip past a gated pipeline.
func TestResolveHighestSeverity_ConditionMap(t *testing.T) {
	truePtr := func() *bool { v := true; return &v }
	highExpectations := []struct {
		name string
		in   scanResultItem
	}{
		{"publisherChanged high", scanResultItem{PublisherChanged: truePtr()}},
		{"installScriptFetchesRemote high", scanResultItem{InstallScriptKind: "fetches_remote"}},
		{"hasHiddenUnicode high", scanResultItem{HiddenUnicodeHits: 1}},
		{"publishVelocityAnomaly high", scanResultItem{PublishVelocity24h: 50}},
		{"malware high", scanResultItem{MalwareStatus: "malicious"}},
		{"repoLinkMissing high", scanResultItem{RepoLinkStatus: "missing"}},
	}
	for _, tc := range highExpectations {
		t.Run(tc.name, func(t *testing.T) {
			in := tc.in
			in.TriggeredConditions = deriveTriggeredConditions(in)
			if got := resolveHighestSeverity(in); got != "high" {
				t.Fatalf("want severity=high, got %q (conditions=%v)", got, in.TriggeredConditions)
			}
		})
	}

	mediumExpectations := []scanResultItem{
		{InstallScriptKind: "present"},                       // hasInstallScript alone
		{VersionAnomalyFlags: []string{"semver_regression"}}, // versionAnomaly
		{TyposquatStatus: "suspected"},                       // typosquat
	}
	for _, in := range mediumExpectations {
		in.TriggeredConditions = deriveTriggeredConditions(in)
		if got := resolveHighestSeverity(in); got != "medium" {
			t.Fatalf("want severity=medium, got %q (input=%+v)", got, in)
		}
	}

	lowExpectations := []scanResultItem{
		{ProvenanceStatus: "unverified"},
		{RepoLinkStatus: "archived"},
	}
	for _, in := range lowExpectations {
		in.TriggeredConditions = deriveTriggeredConditions(in)
		if got := resolveHighestSeverity(in); got != "low" {
			t.Fatalf("want severity=low, got %q (input=%+v)", got, in)
		}
	}
}

// TestResolveHighestSeverity_PicksMaxOfCVEandCondition ensures the
// CVE-derived severity does not swamp a higher supply-chain condition
// severity and vice versa — both sides contribute to the max.
func TestResolveHighestSeverity_PicksMaxOfCVEandCondition(t *testing.T) {
	truePtr := func() *bool { v := true; return &v }
	// Low CVE + high supply-chain → high.
	in := scanResultItem{
		Status:           "vulnerable",
		Severity:         "low",
		PublisherChanged: truePtr(),
	}
	in.TriggeredConditions = deriveTriggeredConditions(in)
	if got := resolveHighestSeverity(in); got != "high" {
		t.Fatalf("want high (cve=low, cond=high), got %q", got)
	}

	// Critical CVE + medium supply-chain → critical.
	in = scanResultItem{
		Status:              "vulnerable",
		Severity:            "critical",
		VersionAnomalyFlags: []string{"major_skip"},
	}
	in.TriggeredConditions = deriveTriggeredConditions(in)
	if got := resolveHighestSeverity(in); got != "critical" {
		t.Fatalf("want critical (cve=critical, cond=medium), got %q", got)
	}
}

// TestTruncateHash covers the display-helper's edge cases.
func TestTruncateHash(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", "—"},
		{"abc", "abc"},
		{"1234567890abcdef", "1234567890abcdef"},
		{"1234567890abcdef0", "1234567890ab..."},
	}
	for _, tc := range tests {
		if got := truncateHash(tc.in); got != tc.want {
			t.Fatalf("truncateHash(%q)=%q, want %q", tc.in, got, tc.want)
		}
	}
}
