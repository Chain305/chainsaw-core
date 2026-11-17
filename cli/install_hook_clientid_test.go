package cli

import (
	"strings"
	"testing"
)

// The 2026-11-17 live pass: "cli-" + a hostname capped at 24 + "-" + 6 hex is
// up to 35 characters, and the server refuses client_ids over 32 (CHW-4803),
// so the recommended press-Enter default minted nothing on long hostnames.
func TestDefaultClientCredentialIDFitsServerRule(t *testing.T) {
	for _, host := range []string{"", "a", "macs-macbook-pro.local", strings.Repeat("x", 24), strings.Repeat("ab-", 20), "Very.Long.Corporate-Laptop-Hostname.example.com"} {
		part := sanitizeClientIDPart(host)
		if len(part) > maxClientIDHostPart {
			part = strings.TrimRight(part[:maxClientIDHostPart], "-_")
		}
		id := "cli-" + part + "-abcdef"
		if !validClientCredentialID(id) {
			t.Errorf("host %q gives %q (%d chars), which the server refuses", host, id, len(id))
		}
	}
	got, err := defaultClientCredentialID()
	if err != nil || !validClientCredentialID(got) {
		t.Fatalf("defaultClientCredentialID() = %q, %v; not a valid client_id", got, err)
	}
}

func TestValidClientCredentialID(t *testing.T) {
	for id, want := range map[string]bool{
		"ab": false, "abc": true, strings.Repeat("a", 32): true, strings.Repeat("a", 33): false,
		"Upper": false, "has.dot": false, "dash-ok_under": true, "\x04": false, "": false, "1abc": false, "-abc": false,
	} {
		if got := validClientCredentialID(id); got != want {
			t.Errorf("validClientCredentialID(%q) = %v, want %v", id, got, want)
		}
	}
}
