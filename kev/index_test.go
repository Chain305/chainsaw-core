package kev

import "testing"

func TestIndex_LoadFromJSON_Roundtrip(t *testing.T) {
	fixture := []byte(`{
		"vulnerabilities": [
			{
				"cveID": "CVE-2024-1111",
				"dateAdded": "2024-03-01",
				"knownRansomwareCampaignUse": "Known"
			},
			{
				"cveID": "CVE-2023-9999",
				"dateAdded": "2023-11-15",
				"knownRansomwareCampaignUse": "Unknown"
			}
		]
	}`)

	idx := New()
	if err := idx.LoadFromJSON(fixture); err != nil {
		t.Fatalf("LoadFromJSON: %v", err)
	}

	e, ok := idx.Lookup("CVE-2024-1111")
	if !ok {
		t.Fatalf("expected CVE-2024-1111 in index")
	}
	if e.DateAdded != "2024-03-01" {
		t.Errorf("dateAdded: got %q, want 2024-03-01", e.DateAdded)
	}
	if !e.KnownRansomwareCampaignUse {
		t.Errorf("KnownRansomwareCampaignUse: want true for 'Known'")
	}

	e2, ok := idx.Lookup("CVE-2023-9999")
	if !ok {
		t.Fatalf("expected CVE-2023-9999 in index")
	}
	if e2.KnownRansomwareCampaignUse {
		t.Errorf("KnownRansomwareCampaignUse: want false for 'Unknown', got true")
	}

	if _, ok := idx.Lookup("CVE-0000-0000"); ok {
		t.Errorf("Lookup for unknown CVE should miss")
	}
	if _, ok := idx.Lookup(""); ok {
		t.Errorf("Lookup on empty string must miss")
	}

	all := idx.All()
	if len(all) != 2 {
		t.Errorf("All(): got %d entries, want 2", len(all))
	}

	if idx.LastRefresh().IsZero() {
		t.Errorf("LastRefresh should be set after LoadFromJSON")
	}
}

func TestIndex_ZeroValueSafe(t *testing.T) {
	var idx Index
	if _, ok := idx.Lookup("CVE-anything"); ok {
		t.Fatalf("zero-value index must return miss")
	}
	if all := idx.All(); len(all) != 0 {
		t.Fatalf("zero-value All(): got %d, want 0", len(all))
	}
}
