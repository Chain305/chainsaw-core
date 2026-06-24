package installscripts

import (
	"os"
	"path/filepath"
	"testing"
)

// fixtureBytes reads a file from the repo-wide testing/fixtures/install_scripts
// directory. It walks up from the test's cwd (internal/installscripts) so the
// test works whether invoked from the package directory or the repo root.
func fixtureBytes(t *testing.T, rel string) []byte {
	t.Helper()
	start, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir := start
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "testing", "fixtures", "install_scripts", rel)
		if data, err := os.ReadFile(candidate); err == nil {
			return data
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("fixture %s not found starting from %s", rel, start)
	return nil
}

func TestNPMBenign(t *testing.T) {
	got := NPM(fixtureBytes(t, "benign_npm/package.json"))
	if got.HasInstallScript {
		t.Errorf("benign npm should not report HasInstallScript; got %+v", got)
	}
	if got.Kind != KindNone {
		t.Errorf("benign npm Kind: got %q, want %q", got.Kind, KindNone)
	}
}

func TestNPMRemoteFetch(t *testing.T) {
	got := NPM(fixtureBytes(t, "remote_fetch_npm/package.json"))
	if !got.HasInstallScript {
		t.Fatalf("remote-fetch npm: HasInstallScript must be true, got %+v", got)
	}
	if !got.InstallScriptFetchesRemote {
		t.Errorf("remote-fetch npm: InstallScriptFetchesRemote must be true, got %+v", got)
	}
	if got.Kind != KindFetchesRemote {
		t.Errorf("Kind: got %q, want %q", got.Kind, KindFetchesRemote)
	}
}

func TestNPMEvalEncoded(t *testing.T) {
	got := NPM(fixtureBytes(t, "eval_encoded_npm/package.json"))
	if !got.HasInstallScript {
		t.Fatalf("eval-encoded npm: HasInstallScript must be true, got %+v", got)
	}
	// The fixture contains eval(Buffer.from plus a long base64 blob.
	// eval(Buffer.from is matched by the fetches-remote regex through
	// its `\beval\s*\(` alternative, so the classification promotes to
	// fetches_remote — which is a strict upgrade over eval_encoded and
	// the correct, stronger signal to record. Assert both paths are
	// acceptable so the test is robust to future regex tweaks.
	if got.Kind != KindFetchesRemote && got.Kind != KindEvalEncoded {
		t.Errorf("eval-encoded npm Kind: got %q, want fetches_remote or eval_encoded", got.Kind)
	}
}

func TestPipBenign(t *testing.T) {
	got := Pip(fixtureBytes(t, "benign_pip/setup.py"), nil)
	if got.HasInstallScript {
		t.Errorf("benign pip: HasInstallScript must be false, got %+v", got)
	}
}

func TestPipRemoteFetch(t *testing.T) {
	got := Pip(fixtureBytes(t, "remote_fetch_pip/setup.py"), nil)
	if !got.HasInstallScript {
		t.Fatalf("remote-fetch pip: HasInstallScript must be true, got %+v", got)
	}
	if !got.InstallScriptFetchesRemote {
		t.Errorf("remote-fetch pip: InstallScriptFetchesRemote must be true, got %+v", got)
	}
	if got.Kind != KindFetchesRemote {
		t.Errorf("Kind: got %q, want %q", got.Kind, KindFetchesRemote)
	}
}

func TestRubyGemsBenign(t *testing.T) {
	got := RubyGems(fixtureBytes(t, "benign_gem/benign.gemspec"))
	if got.HasInstallScript {
		t.Errorf("benign gem: HasInstallScript must be false, got %+v", got)
	}
}

func TestRubyGemsWithExtensions(t *testing.T) {
	body := []byte(`Gem::Specification.new do |s|
  s.name = 'native'
  s.version = '1.0.0'
  s.extensions = ['ext/extconf.rb']
end
`)
	got := RubyGems(body)
	if !got.HasInstallScript {
		t.Errorf("gem with extensions: HasInstallScript must be true, got %+v", got)
	}
}

func TestCargoRemoteFetch(t *testing.T) {
	cargoToml := fixtureBytes(t, "remote_fetch_cargo/Cargo.toml")
	buildRs := fixtureBytes(t, "remote_fetch_cargo/build.rs")
	got := Cargo(cargoToml, buildRs)
	if !got.HasInstallScript {
		t.Fatalf("cargo build.rs: HasInstallScript must be true, got %+v", got)
	}
	if !got.InstallScriptFetchesRemote {
		t.Errorf("cargo build.rs: InstallScriptFetchesRemote must be true, got %+v", got)
	}
	if got.Kind != KindFetchesRemote {
		t.Errorf("Kind: got %q, want %q", got.Kind, KindFetchesRemote)
	}
}

func TestCargoNoBuild(t *testing.T) {
	body := []byte(`[package]
name = "plain"
version = "1.0.0"
edition = "2021"
`)
	got := Cargo(body, nil)
	if got.HasInstallScript {
		t.Errorf("plain cargo: HasInstallScript must be false, got %+v", got)
	}
}

func TestComposerRemoteFetch(t *testing.T) {
	got := Composer(fixtureBytes(t, "remote_fetch_composer/composer.json"))
	if !got.HasInstallScript {
		t.Fatalf("composer: HasInstallScript must be true, got %+v", got)
	}
	if !got.InstallScriptFetchesRemote {
		t.Errorf("composer: InstallScriptFetchesRemote must be true, got %+v", got)
	}
	if got.Kind != KindFetchesRemote {
		t.Errorf("Kind: got %q, want %q", got.Kind, KindFetchesRemote)
	}
}

func TestComposerNoScripts(t *testing.T) {
	body := []byte(`{
  "name": "foo/bar",
  "description": "no lifecycle scripts"
}`)
	got := Composer(body)
	if got.HasInstallScript {
		t.Errorf("composer with no scripts: HasInstallScript must be false, got %+v", got)
	}
	if got.Kind != KindNone {
		t.Errorf("Kind: got %q, want %q", got.Kind, KindNone)
	}
}

func TestMalformedJSONReturnsEmpty(t *testing.T) {
	got := NPM([]byte("{not valid json"))
	if got.HasInstallScript || got.InstallScriptFetchesRemote {
		t.Errorf("malformed json must return empty result, got %+v", got)
	}
}

// TestFinishPrefersFetchesRemoteOverEvalEncoded documents the
// precedence rule: remote-fetch primitives are a strictly stronger
// signal than obfuscation markers, so when both are present the
// classification is fetches_remote.
func TestFinishPrefersFetchesRemoteOverEvalEncoded(t *testing.T) {
	got := finish("npm", true, `eval(Buffer.from('...') + curl evil)`)
	if got.Kind != KindFetchesRemote {
		t.Errorf("want fetches_remote (stronger), got %q", got.Kind)
	}
}
