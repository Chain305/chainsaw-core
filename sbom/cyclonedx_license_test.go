package sbom

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestLicenseRoutingNeverForgesAnSPDXID is the guard that matters here.
//
// CycloneDX `license.id` MUST be a valid SPDX identifier; `license.name` is
// the free-text alternative. The licence Chainsaw resolves is frequently NOT
// SPDX — Metadata.LicenseExpression carries a licence NAME for most of Maven
// Central and a quarter of PyPI, and production holds values like
// "http://go.microsoft.com/fwlink/?LinkId=329770".
//
// Emitting those as `id` produces a BOM that fails schema validation
// downstream — worse for the consumer than carrying no licence at all. So the
// fix that adds licence data has to route by validity, not just populate.
func TestLicenseRoutingNeverForgesAnSPDXID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		in       string
		wantID   string
		wantName string
	}{
		{"plain spdx", "MIT", "MIT", ""},
		{"spdx with dashes", "Apache-2.0", "Apache-2.0", ""},
		{"spdx expression", "MIT OR Apache-2.0", "MIT OR Apache-2.0", ""},
		// The three shapes that must NOT become an id:
		{"a URL", "http://go.microsoft.com/fwlink/?LinkId=329770", "", "http://go.microsoft.com/fwlink/?LinkId=329770"},
		{"a free-text name", "The Apache Software License, Version 2.0", "", "The Apache Software License, Version 2.0"},
		{"vendor string", "Proprietary - see LICENSE.txt", "", "Proprietary - see LICENSE.txt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := licenseEntry(tc.in)
			if !ok {
				t.Fatalf("licenseEntry(%q) returned not-ok for a non-empty value", tc.in)
			}
			if got.License.ID != tc.wantID {
				t.Errorf("id = %q, want %q", got.License.ID, tc.wantID)
			}
			if got.License.Name != tc.wantName {
				t.Errorf("name = %q, want %q", got.License.Name, tc.wantName)
			}
			// The spec forbids both. A value in each field is as invalid as
			// the wrong field.
			if got.License.ID != "" && got.License.Name != "" {
				t.Errorf("both id (%q) and name (%q) set — CycloneDX allows exactly one",
					got.License.ID, got.License.Name)
			}
		})
	}

	// Empty must omit the array entirely rather than emit an empty object.
	if _, ok := licenseEntry("   "); ok {
		t.Error("a blank licence must not produce a licences entry")
	}
}

// TestLicenseReachesTheEmittedBOM closes the gap a unit test on licenseEntry
// alone would leave: that the helper is actually WIRED into the builder.
//
// Negative control: deleting the call site and leaving the helper in place
// keeps the test above green. This one serialises a real BOM and reads the
// bytes, so an unwired helper fails.
func TestLicenseReachesTheEmittedBOM(t *testing.T) {
	t.Parallel()
	bom := Generate([]PackageEntry{
		{Ecosystem: "npm", Name: "spdx-pkg", Version: "1.0.0", LicenseSPDX: "MIT"},
		{Ecosystem: "maven", Name: "named-pkg", Version: "2.0.0", LicenseSPDX: "The Apache Software License, Version 2.0"},
	}, "urn:uuid:00000000-0000-0000-0000-000000000000")
	raw, err := json.Marshal(bom)
	if err != nil {
		t.Fatalf("marshal bom: %v", err)
	}
	out := string(raw)

	if !strings.Contains(out, `"id":"MIT"`) {
		t.Errorf(`emitted BOM is missing "id":"MIT" — is licenseEntry wired into the builder?`+"\n%s", out)
	}
	if !strings.Contains(out, `"name":"The Apache Software License, Version 2.0"`) {
		t.Errorf(`emitted BOM is missing the free-text licence as "name"`+"\n%s", out)
	}
	// The exact regression this guards: the non-SPDX string must never
	// appear as an id.
	if strings.Contains(out, `"id":"The Apache Software License`) {
		t.Error(`a free-text licence was emitted as "id" — the BOM will fail SPDX validation`)
	}
}
