package intelligence

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"strings"
	"testing"
)

// Shared helpers for the npm-b group of the 2026 attack review
// (attack2026_44/51/56/57/58_test.go in this package). Fixtures are
// defanged reconstructions of the documented payload shapes: fake hosts
// (*.example.invalid) unless the published IOC is a bare IP the detector
// under test keys on.

func atkBTarball(t *testing.T, files map[string]string) []byte {
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

// atkBRun runs one provider on an npm tarball the way the proxy's inline
// path (internal/server runSyncByteProviders) and the async follow-up do.
func atkBRun(t *testing.T, p Provider, pkg, version string, tgz []byte) ArtifactScanSection {
	t.Helper()
	part, err := p.Run(context.Background(), Request{
		Key:      Key{Ecosystem: "npm", Package: pkg, Version: version},
		Artifact: &ArtifactHandle{Bytes: tgz},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if part.Scan == nil {
		return ArtifactScanSection{}
	}
	return *part.Scan
}

// atkBObfuscatedJS wraps logic in the javascript-obfuscator string-array
// shape (rotated array, hex-indexed decoder, _0x identifiers) the
// Shai-Hulud / ChainDrop / Mastra droppers are documented to use. The
// detector's threshold is >24 _0x identifiers; this emits ~40.
func atkBObfuscatedJS(logic string) string {
	var b strings.Builder
	b.WriteString("const _0x4c11=['aHR0cHM6Ly9jMi5leGFtcGxlLmludmFsaWQ=','Y2hpbGRfcHJvY2Vzcw=='];\n")
	b.WriteString("(function(_0x2d8f05,_0x4b81bb){const _0x5a1c=function(_0x3e1f2a){while(--_0x3e1f2a){_0x2d8f05['push'](_0x2d8f05['shift']());}};_0x5a1c(++_0x4b81bb);}(_0x4c11,0x4c11d));\n")
	b.WriteString("const _0x1b2c=function(_0x3e1f,_0x5a2b){_0x3e1f=_0x3e1f-0x0;return Buffer.from(_0x4c11[_0x3e1f],'base64').toString();};\n")
	for i := 0; i < 32; i++ {
		fmt.Fprintf(&b, "const _0x%04x=_0x1b2c('0x%x');\n", 0xa100+i, i%2)
	}
	b.WriteString(logic)
	return b.String()
}

func atkBFired(r *Report, id string) bool {
	if r == nil || r.Risk == nil {
		return false
	}
	for _, cs := range r.Risk.DirectScore.Categories {
		for _, f := range cs.FiredSignals {
			if f.ID == id {
				return true
			}
		}
	}
	return false
}
