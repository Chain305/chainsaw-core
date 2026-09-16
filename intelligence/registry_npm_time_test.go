package intelligence

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// unpublishedPackument is the verbatim shape of
// registry.npmjs.org/1nestjs, one of the 77 packages this defect blinded us
// to. The `unpublished` OBJECT alongside string timestamps is the whole
// problem.
const unpublishedPackument = `{
  "_id": "1nestjs",
  "name": "1nestjs",
  "time": {
    "created": "2026-09-03T22:50:50.845Z",
    "modified": "2026-09-03T23:50:03.535Z",
    "0.0.1": "2026-09-03T22:50:51.095Z",
    "unpublished": {"time": "2026-09-03T23:50:03.535Z", "versions": ["0.0.1"]}
  },
  "_rev": "2-f7486368bebfd6593d581dd77e3aaba6"
}`

// TestRunNPMDoesNotDiscardAnUnpublishedPackument drives the REAL provider,
// not a local struct that happens to use the right type.
//
// This distinction is the test itself. The first version of this guard
// declared its own `struct{ Time npmTime }`, so reverting the provider's
// field back to map[string]string — the actual bug — left it green. A guard
// that cannot fail on the defect it was written for is not a guard; it is
// decoration. Mutating the provider field must turn this red.
func TestRunNPMDoesNotDiscardAnUnpublishedPackument(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, unpublishedPackument)
	}))
	defer srv.Close()

	p := &registryMetadataProvider{
		client:    srv.Client(),
		endpoints: registryEndpoints{npm: srv.URL},
		now:       func() time.Time { return time.Unix(0, 0).UTC() },
	}
	pr, err := p.runNPM(context.Background(), "1nestjs", "0.0.1")
	if err != nil {
		t.Fatalf("runNPM: %v", err)
	}
	for _, w := range pr.Warnings {
		if w.Code == WarnRegistryDecode {
			t.Fatalf("runNPM discarded an unpublished packument as a decode error: %s\n"+
				"That is the 5.2%% blind spot -- 98 rows, 77 npm packages -- and the "+
				"document it throws away is the one carrying npm's strongest "+
				"supply-chain marker.", w.Message)
		}
	}
	if pr.Release == nil || pr.Release.CreatedAt == nil {
		t.Fatal("no facts recovered from a packument that parses fine; " +
			"the point of the fix is that the REST of the document survives")
	}
	if got := pr.Release.CreatedAt.UTC().Format(time.RFC3339Nano); got != "2026-09-03T22:50:50.845Z" {
		t.Errorf("CreatedAt = %s", got)
	}
}

// TestNPMTimeMapSurvivesAnUnpublishedPackage is a corpus finding turned into
// a guard.
//
// npm's packument `time` object is not uniformly string-valued: an
// unpublished package carries `"unpublished": {...}`, an object. Declared as
// map[string]string, encoding/json rejects the WHOLE packument, runNPM emits
// a decode warning, and every fact about the package is thrown away.
//
// Measured on the 1,885-coordinate corpus: 98 rows, 77 distinct npm
// packages, 5.2%, npm only. The failure inverts the signal it destroys —
// time.unpublished is the coa@2.0.3 / event-stream@3.3.6 marker this
// codebase cites by name, and carrying it was what made us blind.
func TestNPMTimeMapSurvivesAnUnpublishedPackage(t *testing.T) {
	// Verbatim shape of registry.npmjs.org/1nestjs, one of the 77.
	const packument = `{
	  "_id": "1nestjs",
	  "name": "1nestjs",
	  "time": {
	    "created": "2026-09-03T22:50:50.845Z",
	    "modified": "2026-09-03T23:50:03.535Z",
	    "0.0.1": "2026-09-03T22:50:51.095Z",
	    "unpublished": {"time": "2026-09-03T23:50:03.535Z", "versions": ["0.0.1"]}
	  },
	  "_rev": "2-f7486368bebfd6593d581dd77e3aaba6"
	}`

	var pack struct {
		Name string  `json:"name"`
		Time npmTime `json:"time"`
	}
	if err := json.Unmarshal([]byte(packument), &pack); err != nil {
		t.Fatalf("an unpublished packument failed to decode: %v\n"+
			"This is the 5.2%% blind spot: the whole document is discarded "+
			"because it carries npm's strongest supply-chain marker.", err)
	}
	if pack.Name != "1nestjs" {
		t.Errorf("name = %q; facts outside `time` must survive", pack.Name)
	}
	for k, want := range map[string]string{
		"created":  "2026-09-03T22:50:50.845Z",
		"modified": "2026-09-03T23:50:03.535Z",
		"0.0.1":    "2026-09-03T22:50:51.095Z",
		// The unpublished marker is LIFTED to a parseable timestamp rather
		// than dropped. Dropping it would fix the crash and keep the
		// blindness, which is the worse of the two outcomes.
		npmUnpublishedKey: "2026-09-03T23:50:03.535Z",
	} {
		if got := pack.Time.Stamps[k]; got != want {
			t.Errorf("Time[%q] = %q, want %q", k, got, want)
		}
	}
	if _, ok := parseTime(pack.Time.Stamps[npmUnpublishedKey]); !ok {
		t.Error("the unpublished timestamp must survive as something parseTime accepts, " +
			"or the fact is preserved in name only")
	}
}

// TestNPMTimeMapSkipsUnknownShapesInsteadOfFailing — the fix must be general,
// not a carve-out for one key. A future npm schema addition of any shape must
// cost us that key, never the document.
func TestNPMTimeMapSkipsUnknownShapesInsteadOfFailing(t *testing.T) {
	var m npmTime
	if err := json.Unmarshal([]byte(`{
	  "created": "2020-01-01T00:00:00.000Z",
	  "somethingNew": {"nested": true},
	  "aList": [1,2,3],
	  "aNumber": 42
	}`), &m); err != nil {
		t.Fatalf("unknown value shapes must not fail the document: %v", err)
	}
	if m.Stamps["created"] != "2020-01-01T00:00:00.000Z" {
		t.Errorf("string entries must survive alongside unknown ones, got %q", m.Stamps["created"])
	}
	for _, k := range []string{"somethingNew", "aList", "aNumber"} {
		if _, ok := m.Stamps[k]; ok {
			t.Errorf("non-string key %q should be skipped, not coerced", k)
		}
	}
	// A `time` that is not an object at all is still a real decode error --
	// skipping that would hide genuine upstream malformation.
	if err := json.Unmarshal([]byte(`"not-an-object"`), &m); err == nil {
		t.Error("a non-object `time` must still be reported as a decode error")
	}
}

// TestNPMWithdrawnIsAPerVersionClaim pins the rule npmWithdrawn implements
// and, more importantly, the case it REFUSES.
//
// Measured across the 76 corpus-v1 tombstones (2026-09-16): 76/76 packages
// had no live versions, 71/76 named the scanned version explicitly, and
// 0/76 had a sibling withdrawn while the scanned version stayed live. The
// last row never occurred, so it is not claimed — flagging a live version
// because a sibling was unpublished is a different and weaker statement.
func TestNPMWithdrawnIsAPerVersionClaim(t *testing.T) {
	for _, tc := range []struct {
		name         string
		ver          string
		unpublished  []string
		liveVersions int
		want         bool
	}{
		{"version named in the unpublished list", "1.0.0", []string{"1.0.0"}, 0, true},
		{"whole package gone, list empty", "2.3.1", nil, 0, true},
		{"whole package gone, list names another version", "2.3.1", []string{"9.9.9"}, 0, true},
		{
			// The refusal. This is the 0/76 case: do NOT claim a live
			// version is withdrawn because a sibling was.
			name: "sibling withdrawn but this version is still live",
			ver:  "2.0.0", unpublished: []string{"1.0.0"}, liveVersions: 3, want: false,
		},
		{"ordinary live package", "1.2.3", nil, 12, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := npmWithdrawn(tc.ver, tc.unpublished, tc.liveVersions); got != tc.want {
				t.Errorf("npmWithdrawn(%q, %v, %d) = %v, want %v",
					tc.ver, tc.unpublished, tc.liveVersions, got, tc.want)
			}
		})
	}
}

// TestRunNPMRaisesVersionAnomalyOnAnUnpublishedPackage drives the provider
// end to end: the tombstone must reach SupplyChain as a withdrawal flag, not
// merely fail to crash.
//
// It must ride VersionAnomaly and NOT DeprecatedByMaintainer. Release.Yanked
// routes to DeprecatedByMaintainer (risk_projection.go), which is both the
// weaker claim — "stop using this" rather than "this is gone" — and the
// signal already driving most of the corpus's benign warns. Loading it with
// withdrawals would blur the one open calibration question.
func TestRunNPMRaisesVersionAnomalyOnAnUnpublishedPackage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, unpublishedPackument)
	}))
	defer srv.Close()

	p := &registryMetadataProvider{
		client:    srv.Client(),
		endpoints: registryEndpoints{npm: srv.URL},
		now:       func() time.Time { return time.Unix(0, 0).UTC() },
	}
	pr, err := p.runNPM(context.Background(), "1nestjs", "0.0.1")
	if err != nil {
		t.Fatalf("runNPM: %v", err)
	}
	if pr.SupplyChain == nil || pr.SupplyChain.VersionAnomaly == nil || !*pr.SupplyChain.VersionAnomaly {
		t.Fatal("an unpublished coordinate must raise VersionAnomaly; " +
			"restoring the facts without raising the signal leaves the blind spot half open")
	}
	var found bool
	for _, f := range pr.SupplyChain.VersionAnomalyFlags {
		if f == FlagRegistryWithdrawn {
			found = true
		}
	}
	if !found {
		t.Errorf("VersionAnomalyFlags = %v, want it to contain %q",
			pr.SupplyChain.VersionAnomalyFlags, FlagRegistryWithdrawn)
	}
	if pr.Release != nil && pr.Release.Yanked != nil && *pr.Release.Yanked {
		t.Error("withdrawal must NOT route through Release.Yanked: that maps to " +
			"DeprecatedByMaintainer, which understates it and is the signal already " +
			"driving most benign warns in corpus v1")
	}
}
