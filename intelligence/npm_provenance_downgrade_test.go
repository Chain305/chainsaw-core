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

// TestNPMProvenanceDowngrade replays nx's 2025-08-26 shape: 21.5.0 and the
// 20.9.0 backport were published with no attestation after attested releases
// on their own lines.
func TestNPMProvenanceDowngrade(t *testing.T) {
	att := func(on bool) npmVersionMeta {
		var m npmVersionMeta
		if on {
			m.Dist.Attestations = json.RawMessage(`{"url":"https://registry.npmjs.org/-/npm/v1/attestations/nx@x","provenance":{"predicateType":"https://slsa.dev/provenance/v1"}}`)
		}
		return m
	}
	versions := map[string]npmVersionMeta{
		"19.0.0": att(false), "20.8.1": att(true), "20.8.2": att(true), "20.9.0": att(false),
		"21.3.0": att(false), "21.4.0": att(true), "21.4.1": att(true), "21.5.0": att(false),
		"21.5.1": att(true), "22.0.0-canary.1": att(false),
	}
	stamps := map[string]string{
		"19.0.0": "2024-05-01T00:00:00Z", "20.8.1": "2025-04-25T01:27:19Z", "20.8.2": "2025-05-16T17:50:22Z",
		"21.3.0": "2025-07-18T16:34:46Z", "21.4.0": "2025-08-15T20:07:43Z", "21.4.1": "2025-08-22T19:16:43Z",
		"21.5.0": "2025-08-26T22:32:25Z", "20.9.0": "2025-08-26T22:39:32Z", "21.5.1": "2025-09-08T15:12:13Z",
		"22.0.0-canary.1": "2025-09-09T00:00:00Z",
	}
	for ver, want := range map[string]string{
		"21.5.0": "21.4.1", // two attested predecessors on its line
		"20.9.0": "20.8.2", // backport: judged against 20.x, not the newer 21.4.1
		"21.3.0": "20.8.2", // new line after two attested releases: still a downgrade
		"21.5.1": "",       // attested itself
		"19.0.0": "",       // nothing before it
		// A prerelease is never judged: canary builds are routinely unattested.
		"22.0.0-canary.1": "",
	} {
		got := npmProvenanceDowngrade(versions, stamps, ver)
		if (got == nil) != (want == "") || (got != nil && got.LastAttestedVersion != want) {
			t.Errorf("%s: got %+v, want last attested %q", ver, got, want)
		}
	}
	if got := npmProvenanceDowngrade(versions, stamps, "21.5.0"); got == nil || got.PriorAttestedCount != 2 {
		t.Errorf("21.5.0: want PriorAttestedCount 2, got %+v", got)
	}

	// One attested predecessor is not enough.
	delete(versions, "21.4.0")
	if got := npmProvenanceDowngrade(versions, stamps, "21.5.0"); got != nil {
		t.Errorf("21.5.0 with one attested predecessor fired: %+v", got)
	}

	// An attestation without a provenance statement, or an odd shape, is not
	// provenance — and must not fail the decode of the whole packument.
	for _, doc := range []string{
		`{"dist":{"attestations":"weird"}}`,
		`{"dist":{"attestations":{"url":"https://registry.npmjs.org/-/npm/v1/attestations/p@1"}}}`,
		`{"dist":{"attestations":{"provenance":null}}}`,
	} {
		var meta npmVersionMeta
		if err := json.Unmarshal([]byte(doc), &meta); err != nil || npmAttested(meta) {
			t.Errorf("%s: err %v, attested %v", doc, err, npmAttested(meta))
		}
	}

	// The fact reaches the risk input.
	r := &Report{}
	r.SupplyChain.ProvenanceDowngrade = &ProvenanceDowngrade{LastAttestedVersion: "21.4.1", PriorAttestedCount: 2}
	if in := ProjectToRiskInput(r); in.ProvenanceDowngradeFrom != "21.4.1" || in.ProvenanceDowngradePriorCount != 2 {
		t.Errorf("projection lost the fact: %q/%d", in.ProvenanceDowngradeFrom, in.ProvenanceDowngradePriorCount)
	}
}

// TestRunNPMReportsProvenanceDowngrade drives the real packument reader, so
// dropping the call from runNPM or the field from npmVersionMeta goes red.
func TestRunNPMReportsProvenanceDowngrade(t *testing.T) {
	const prov = `"attestations":{"provenance":{"predicateType":"https://slsa.dev/provenance/v1"}}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"name":"p","versions":{
			"1.0.0":{"dist":{`+prov+`}},"1.0.1":{"dist":{`+prov+`}},"1.0.2":{"dist":{}}},
			"time":{"1.0.0":"2025-01-01T00:00:00Z","1.0.1":"2025-02-01T00:00:00Z","1.0.2":"2025-03-01T00:00:00Z"}}`)
	}))
	defer srv.Close()
	p := &registryMetadataProvider{
		client:    srv.Client(),
		endpoints: registryEndpoints{npm: srv.URL},
		now:       func() time.Time { return time.Unix(0, 0).UTC() },
	}
	pr, err := p.runNPM(context.Background(), "p", "1.0.2")
	if err != nil {
		t.Fatalf("runNPM: %v", err)
	}
	if pr.SupplyChain == nil || pr.SupplyChain.ProvenanceDowngrade == nil ||
		pr.SupplyChain.ProvenanceDowngrade.LastAttestedVersion != "1.0.1" {
		t.Fatalf("no provenance downgrade reported for 1.0.2: %+v", pr.SupplyChain)
	}
	if pr, _ := p.runNPM(context.Background(), "p", "1.0.1"); pr.SupplyChain != nil && pr.SupplyChain.ProvenanceDowngrade != nil {
		t.Fatalf("attested 1.0.1 reported as a downgrade: %+v", pr.SupplyChain.ProvenanceDowngrade)
	}
}
