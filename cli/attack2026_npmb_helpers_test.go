package cli

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"strings"
	"testing"
)

// Helpers for the npm-b group of the 2026 attack review
// (attack2026_44/51/56/57/58_test.go in this package). analyzeArtifact is
// the install guard's offline byte verdict; it runs whenever the guard has
// the tarball (staged dir, warm npm cache, or deep mode).

func atkBTgz(t *testing.T, files map[string]string) []byte {
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

// atkBObf: javascript-obfuscator string-array shape, >24 _0x identifiers.
func atkBObf(logic string) string {
	var b strings.Builder
	b.WriteString("const _0x4c11=['aHR0cHM6Ly9jMi5leGFtcGxlLmludmFsaWQ='];\n")
	b.WriteString("const _0x1b2c=function(_0x3e1f){return Buffer.from(_0x4c11[_0x3e1f],'base64').toString();};\n")
	for i := 0; i < 32; i++ {
		fmt.Fprintf(&b, "const _0x%04x=_0x1b2c(0x0);\n", 0xa100+i)
	}
	b.WriteString(logic)
	return b.String()
}
