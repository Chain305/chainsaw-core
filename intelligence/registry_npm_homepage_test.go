package intelligence

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// arrayHomepagePackument is the shape of registry.npmjs.org/fs-extra: the
// current version carries a string homepage, an early one carries an ARRAY.
// Before npmHomepage, that one historical version failed the whole packument
// decode and fs-extra@11.4.1 scored `unknown` in the server FP corpus.
const arrayHomepagePackument = `{
  "name": "fs-extra",
  "homepage": "https://github.com/jprichardson/node-fs-extra",
  "dist-tags": {"latest": "11.4.1"},
  "time": {"0.0.1": "2011-11-11T00:00:00.000Z", "11.4.1": "2026-01-01T00:00:00.000Z"},
  "versions": {
    "0.0.1": {"name": "fs-extra", "version": "0.0.1", "homepage": ["https://example.invalid/old", "x"]},
    "11.4.1": {"name": "fs-extra", "version": "11.4.1", "license": "MIT",
               "homepage": "https://github.com/jprichardson/node-fs-extra"}
  }
}`

// TestRunNPMToleratesArrayHomepage drives the real provider. Verified by
// reverting either Homepage field to string: the decode warning comes back.
func TestRunNPMToleratesArrayHomepage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, arrayHomepagePackument)
	}))
	defer srv.Close()

	p := &registryMetadataProvider{
		client:    srv.Client(),
		endpoints: registryEndpoints{npm: srv.URL},
		now:       func() time.Time { return time.Unix(0, 0).UTC() },
	}
	for _, ver := range []string{"11.4.1", "0.0.1"} {
		pr, err := p.runNPM(context.Background(), "fs-extra", ver)
		if err != nil {
			t.Fatalf("runNPM %s: %v", ver, err)
		}
		for _, w := range pr.Warnings {
			if w.Code == WarnRegistryDecode {
				t.Fatalf("runNPM %s: an array homepage on one version failed the packument decode: %s", ver, w.Message)
			}
		}
		if pr.Metadata == nil {
			t.Fatalf("runNPM %s: no metadata", ver)
		}
		want := map[string]string{
			"11.4.1": "https://github.com/jprichardson/node-fs-extra",
			"0.0.1":  "https://example.invalid/old",
		}[ver]
		if pr.URLs == nil || pr.URLs.HomepageURL != want {
			t.Errorf("runNPM %s: homepage = %+v, want %q", ver, pr.URLs, want)
		}
	}
}
