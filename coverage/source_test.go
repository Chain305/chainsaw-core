package coverage

import "testing"

func TestParseSourceAcceptsV1Allowlist(t *testing.T) {
	for _, name := range []string{
		"malware", "cve", "typosquat", "provenance",
		"registry_metadata", "checksum", "install_scripts", "hidden_unicode",
	} {
		got, err := ParseSource(name)
		if err != nil {
			t.Errorf("ParseSource(%q) returned error %v, want success", name, err)
		}
		if string(got) != name {
			t.Errorf("ParseSource(%q) = %q, want %q", name, got, name)
		}
	}
}

func TestParseSourceRejectsUnknown(t *testing.T) {
	// Risk signal IDs are deliberately NOT valid here — they are scoring
	// rules, not data sources. See decision D2.
	for _, name := range []string{"sc.known_malicious", "vuln.kev", "", "MALWARE", "kev"} {
		if _, err := ParseSource(name); err == nil {
			t.Errorf("ParseSource(%q) succeeded, want error", name)
		}
	}
}

func TestAllSourcesIsTheAllowlist(t *testing.T) {
	if len(AllSources()) != 8 {
		t.Errorf("AllSources() has %d entries, want 8", len(AllSources()))
	}
	for _, s := range AllSources() {
		if _, err := ParseSource(string(s)); err != nil {
			t.Errorf("AllSources() returned %q which ParseSource rejects", s)
		}
	}
}
