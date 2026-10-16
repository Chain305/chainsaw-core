package intelligence

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/provenance"
)

func dDigest(c string) string { return "sha256:" + strings.Repeat(c, 64) }

// hubTagsJSON: 1.3.0 (digest a, also :latest) unsigned after three signed
// releases; 1.2 aliases 1.2.0; 0.9.9 is a later backport to an old line.
var hubTagsJSON = `{"results":[
 {"name":"latest","digest":"` + dDigest("a") + `","last_updated":"2026-05-01T00:00:00Z"},
 {"name":"0.9.9","digest":"` + dDigest("9") + `","last_updated":"2026-04-20T00:00:00Z"},
 {"name":"1.3.0","digest":"` + dDigest("a") + `","last_updated":"2026-04-01T00:00:00Z","images":[{"digest":"` + dDigest("f") + `"}]},
 {"name":"1.2","digest":"` + dDigest("b") + `","last_updated":"2026-03-01T00:00:00Z"},
 {"name":"1.2.0","digest":"` + dDigest("b") + `","last_updated":"2026-03-01T00:00:00Z"},
 {"name":"1.1.0","digest":"` + dDigest("c") + `","last_updated":"2026-02-01T00:00:00Z"},
 {"name":"1.0.0","digest":"` + dDigest("d") + `","last_updated":"2026-01-01T00:00:00Z"},
 {"name":"0.9.0","digest":"` + dDigest("e") + `","last_updated":"2025-12-01T00:00:00Z"}
]}`

type hubRT func(*http.Request) (*http.Response, error)

func (f hubRT) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func dockerStubProvider(signed map[string]bool) (*registryMetadataProvider, *[]string) {
	var checked []string
	p := newRegistryMetadataProvider()
	p.endpoints.docker = "https://hub.invalid"
	p.client = &http.Client{Transport: hubRT(func(r *http.Request) (*http.Response, error) {
		body, code := "", http.StatusOK
		switch {
		case r.URL.Path == "/v2/repositories/acme/tool/tags/" && r.URL.Query().Get("ordering") == "last_updated":
			body = hubTagsJSON
		case r.URL.Path == "/v2/repositories/acme/tool/":
			body = `{"user":"acme","name":"tool","namespace":"acme"}`
		default:
			code = http.StatusNotFound
		}
		return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)),
			Header: http.Header{"Content-Type": {"application/json"}}, Request: r}, nil
	})}
	p.ociStatus = func(_ context.Context, pkg, digest string) provenance.Status {
		checked = append(checked, digest)
		if signed[digest] {
			return provenance.StatusVerified
		}
		return provenance.StatusMissing
	}
	return p, &checked
}

func runDockerStub(t *testing.T, p *registryMetadataProvider, ver string) PartialReport {
	t.Helper()
	pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: "docker", Package: "acme/tool", Version: ver}}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return pr
}

func TestDockerProvenanceDowngrade(t *testing.T) {
	allPriors := map[string]bool{dDigest("b"): true, dDigest("c"): true, dDigest("d"): true}
	for _, tc := range []struct {
		name   string
		signed map[string]bool
		ver    string
		want   string
	}{
		{"index digest, three signed priors", allPriors, "sha256-" + strings.Repeat("a", 64), "1.2.0"},
		{"platform digest resolves to its index", allPriors, "sha256-" + strings.Repeat("f", 64), "1.2.0"},
		{"requested image is signed", map[string]bool{dDigest("a"): true, dDigest("b"): true, dDigest("c"): true, dDigest("d"): true}, "sha256-" + strings.Repeat("a", 64), ""},
		{"only two signed priors", map[string]bool{dDigest("b"): true, dDigest("c"): true}, "sha256-" + strings.Repeat("a", 64), ""},
		{"never signed", nil, "sha256-" + strings.Repeat("a", 64), ""},
		{"backport to an unsigned line", allPriors, "sha256-" + strings.Repeat("9", 64), ""},
		{"digest not in the listing", allPriors, "sha256-" + strings.Repeat("7", 64), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p, _ := dockerStubProvider(tc.signed)
			pr := runDockerStub(t, p, tc.ver)
			var got *ProvenanceDowngrade
			if pr.SupplyChain != nil {
				got = pr.SupplyChain.ProvenanceDowngrade
			}
			if (got == nil) != (tc.want == "") || (got != nil && (got.LastAttestedVersion != tc.want || got.PriorAttestedCount != 3)) {
				t.Fatalf("got %+v, want last attested %q", got, tc.want)
			}
			if len(pr.Warnings) > 0 {
				t.Fatalf("warnings: %+v", pr.Warnings)
			}
		})
	}

	// An unsigned image stops at the first unsigned prior: one check, not K+1.
	p, checked := dockerStubProvider(nil)
	runDockerStub(t, p, "sha256-"+strings.Repeat("a", 64))
	if len(*checked) != 1 || (*checked)[0] != dDigest("b") {
		t.Fatalf("checked %v, want only the nearest prior", *checked)
	}

	// No checker wired: no listing fetch, no section.
	p, _ = dockerStubProvider(allPriors)
	p.ociStatus = nil
	if pr := runDockerStub(t, p, "sha256-"+strings.Repeat("a", 64)); pr.SupplyChain != nil && pr.SupplyChain.ProvenanceDowngrade != nil {
		t.Fatalf("fired without a checker: %+v", pr.SupplyChain.ProvenanceDowngrade)
	}
}
