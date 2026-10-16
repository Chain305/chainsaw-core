package intelligence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"testing"

	"github.com/chain305/chainsaw-core/risk"
)

func npmTarball(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: "package/" + name, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestDefenderTamperReachesRiskSignal: @apexacc/audit (2026-09) disabled
// Defender from shipping code. The detector existed with no caller; this pins
// provider -> merge -> projection -> sc.defender_tamper.
func TestDefenderTamperReachesRiskSignal(t *testing.T) {
	tgz := npmTarball(t, map[string]string{
		"package.json": `{"name":"audit-helper","version":"1.0.0","main":"lib/audit.js"}`,
		"lib/audit.js": "const {execSync}=require('child_process');\n" +
			"execSync('powershell -Command \"Set-MpPreference -DisableRealtimeMonitoring $true\"');\n",
	})
	part, err := newIOCScanProvider().Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "audit-helper", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: tgz},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if part.Scan == nil || part.Scan.DefenderTamper == "" {
		t.Fatalf("provider did not report Defender tampering: %+v", part.Scan)
	}

	var merged ArtifactScanSection
	MergeScan(&merged, *part.Scan)
	in := ProjectToRiskInput(&Report{Scan: merged})
	if in.DefenderTamper == "" {
		t.Fatal("DefenderTamper lost between merge and risk.Input")
	}
	for _, sig := range risk.AllSignals() {
		if sig.ID != risk.SignalSCDefenderTamper {
			continue
		}
		if fired, _, _ := sig.Fires(in); !fired {
			t.Fatal("sc.defender_tamper did not fire on a projected hit")
		}
		return
	}
	t.Fatal("sc.defender_tamper not registered")
}

// A build script that only lowers the signature update interval is not
// tampering.
func TestDefenderTamperIgnoresBenignMpPreference(t *testing.T) {
	tgz := npmTarball(t, map[string]string{
		"package.json": `{"name":"ci-helper","version":"1.0.0"}`,
		"lib/ci.js":    "run('Set-MpPreference -SignatureUpdateInterval 4')\n",
	})
	part, err := newIOCScanProvider().Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: "ci-helper", Version: "1.0.0"},
		Artifact: &ArtifactHandle{Bytes: tgz},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if part.Scan != nil && part.Scan.DefenderTamper != "" {
		t.Fatalf("benign Set-MpPreference flagged: %q", part.Scan.DefenderTamper)
	}
}
