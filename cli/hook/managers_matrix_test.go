package hook

// Table-driven coverage over EVERY manager in All().
//
// Six managers shipped with zero test files — maven, gradle, nuget, gomod,
// docker and yarn — and that is exactly where the HIGH-severity defects lived.
// These tables are keyed off All(), so a new manager inherits the whole suite
// the moment it is registered, and TestEveryManagerAppearsInMatrixTables fails
// the build if someone adds one without a fixture.
//
// Every case runs against a t.TempDir() HOME with the manager-specific
// override env vars cleared, so no test can reach the developer's real
// ~/.npmrc, ~/.cargo, ~/.m2, ~/.sbt, ~/.gradle or ~/.docker.

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"
)

const (
	testServer = "https://chain305.com"
	testOrg    = "acme-corp"
	testCreds  = "cli-abc:s3cr3t-value"
)

// homeEnvVars are every environment variable a manager consults to relocate
// its config. Cleared so a test can never touch the developer's real files.
var homeEnvVars = []string{
	"NPM_CONFIG_USERCONFIG",
	"PIP_CONFIG_FILE",
	"CARGO_HOME",
	"GOENV",
	"XDG_CONFIG_HOME",
	"VIRTUAL_ENV",
	"M2_HOME",
	"MAVEN_HOME",
	"GRADLE_USER_HOME",
	"GRADLE_HOME",
}

// sandboxHome points $HOME at a throwaway directory and clears every config
// relocation variable.
func sandboxHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for _, k := range homeEnvVars {
		t.Setenv(k, "")
	}
	return home
}

func testWireOpts() WireOpts {
	return WireOpts{
		ChainsawBinary: "/usr/local/bin/chainsaw",
		ServerURL:      testServer,
		OrgSlug:        testOrg,
		Scope:          ScopeUser,
	}
}

// managerPaths returns every file the manager writes for the given scope. All
// managers write one file; sbt writes three.
func managerPaths(t *testing.T, m Manager, scope Scope) []string {
	t.Helper()
	if r, ok := m.(repairable); ok {
		paths, _, err := r.repairTargets(scope)
		if err != nil {
			t.Fatalf("%s: repairTargets: %v", m.Name(), err)
		}
		return paths
	}
	p, err := m.ConfigPathForScope(scope)
	if err != nil {
		t.Fatalf("%s: ConfigPathForScope: %v", m.Name(), err)
	}
	return []string{p}
}

// ---------------------------------------------------------------------------
// 1. wire → status → unwire round trip
// ---------------------------------------------------------------------------

// TestEveryManagerWireStatusUnwireRoundTrip is the single highest-value test
// in this file: it fails at the first assertion for H2 (maven/nuget markers
// the matcher could never see, so the hook was permanently un-uninstallable)
// and for H3 (docker matched the substring "chainsaw", which the production
// host chain305.com does not contain).
func TestEveryManagerWireStatusUnwireRoundTrip(t *testing.T) {
	for _, m := range All() {
		t.Run(m.Name(), func(t *testing.T) {
			sandboxHome(t)
			opts := testWireOpts()

			if err := m.Wire(opts); err != nil {
				t.Fatalf("Wire: %v", err)
			}
			for _, p := range managerPaths(t, m, ScopeUser) {
				if _, err := os.Stat(p); err != nil {
					t.Fatalf("Wire did not create %s: %v", p, err)
				}
			}

			st, err := m.Status()
			if err != nil {
				t.Fatalf("Status: %v", err)
			}
			if !st.Wired {
				t.Fatalf("Status().Wired = false after Wire; the hook can never be uninstalled and `chainsaw status` lies (config: %s)", st.ConfigPath)
			}

			if err := m.Unwire(ScopeUser); err != nil {
				t.Fatalf("Unwire after Wire: %v", err)
			}

			st, err = m.Status()
			if err != nil {
				t.Fatalf("Status after Unwire: %v", err)
			}
			if st.Wired {
				t.Fatalf("Status().Wired = true after Unwire (config: %s)", st.ConfigPath)
			}

			// Unwire must genuinely remove the routing directives, not just
			// the markers. This is the assertion that would have caught a
			// removeSentinel-based XML unwire leaving <mirrorOf>*</mirrorOf>
			// live while reporting success.
			for _, p := range managerPaths(t, m, ScopeUser) {
				data, err := os.ReadFile(p)
				if errors.Is(err, os.ErrNotExist) {
					continue
				}
				if err != nil {
					t.Fatalf("read %s: %v", p, err)
				}
				for _, residue := range []string{"mirrorOf", "chain305.com", "chainproxy/repository"} {
					if strings.Contains(string(data), residue) {
						t.Errorf("Unwire left %q behind in %s:\n%s", residue, p, data)
					}
				}
			}

			// Idempotent: a second Unwire is a clean no-op.
			if err := m.Unwire(ScopeUser); !errors.Is(err, ErrNotWired) {
				t.Errorf("second Unwire = %v, want ErrNotWired", err)
			}
		})
	}
}

// TestMavenLegacyMarkerInstallIsRemovable pins the repair path for installs
// already on disk: releases up to now wrote the marker on the same line as
// the XML comment opener, which the shared matcher could never see.
func TestMavenLegacyMarkerInstallIsRemovable(t *testing.T) {
	sandboxHome(t)
	m := mavenManager{}
	path, err := m.ConfigPathForScope(ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	legacy := `<?xml version="1.0" encoding="UTF-8"?>
<!-- ` + sentinelStart + `
` + sentinelEnd + `
-->
<settings>
  <mirrors>
    <mirror>
      <id>chainsaw-maven</id>
      <url>https://chain305.com/chainproxy/repository/@acme-corp/maven-central</url>
      <mirrorOf>*</mirrorOf>
    </mirror>
  </mirrors>
</settings>
`
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := m.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Wired {
		t.Fatal("legacy same-line markers are not recognised, so the install stays orphaned forever")
	}
	if err := m.Unwire(ScopeUser); err != nil {
		t.Fatalf("Unwire of a legacy install: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("legacy settings.xml still present after Unwire (err=%v)", err)
	}
}

// TestNugetLegacyMarkerInstallIsRemovable is the nuget half of the same
// repair path (the closer carried a trailing "-->").
func TestNugetLegacyMarkerInstallIsRemovable(t *testing.T) {
	sandboxHome(t)
	m := nugetManager{}
	path, err := m.ConfigPathForScope(ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	legacy := `<?xml version="1.0" encoding="utf-8"?>
<!-- ` + sentinelStart + `
chainsaw: source installed via install-hook nuget.
` + sentinelEnd + ` -->
<configuration>
  <packageSources>
    <clear />
    <add key="Chainsaw" value="https://chain305.com/x/" />
  </packageSources>
</configuration>
`
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(legacy), 0o644); err != nil {
		t.Fatal(err)
	}
	st, err := m.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Wired {
		t.Fatal("legacy nuget markers are not recognised; the user's package sources stay wiped with no way back")
	}
	if err := m.Unwire(ScopeUser); err != nil {
		t.Fatalf("Unwire of a legacy install: %v", err)
	}
}

// TestDockerUnwireIgnoresUnrelatedMirrors pins the other half of H3: the old
// substring test deleted a user's own https://mirror.internal/chainsaw-cache.
func TestDockerUnwireIgnoresUnrelatedMirrors(t *testing.T) {
	sandboxHome(t)
	m := dockerManager{}
	path, err := m.ConfigPathForScope(ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := `{"registry-mirrors":["https://mirror.internal/chainsaw-cache"],"log-level":"warn"}`
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Wire(testWireOpts()); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	if err := m.Unwire(ScopeUser); err != nil {
		t.Fatalf("Unwire: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("daemon.json is not valid JSON after round trip: %v\n%s", err, data)
	}
	mirrors, _ := out["registry-mirrors"].([]any)
	if len(mirrors) != 1 || mirrors[0] != "https://mirror.internal/chainsaw-cache" {
		t.Fatalf("Unwire deleted an unrelated user mirror; registry-mirrors = %v", mirrors)
	}
	if out["log-level"] != "warn" {
		t.Errorf("unrelated daemon.json keys were lost: %v", out)
	}
}

// TestDockerLegacyInstallEscapeHatch covers a host wired before chainsaw
// recorded the mirror it inserted: Unwire cannot guess, but --mirror can.
func TestDockerLegacyInstallEscapeHatch(t *testing.T) {
	sandboxHome(t)
	m := dockerManager{}
	path, err := m.ConfigPathForScope(ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"registry-mirrors":["https://chain305.com"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := m.Unwire(ScopeUser); !errors.Is(err, ErrNotWired) {
		t.Fatalf("Unwire without a sidecar = %v, want ErrNotWired (guessing would delete user mirrors)", err)
	}
	if err := UnwireDockerMirror(ScopeUser, "https://chain305.com"); err != nil {
		t.Fatalf("UnwireDockerMirror: %v", err)
	}
	data, _ := os.ReadFile(path)
	if strings.Contains(string(data), "chain305.com") {
		t.Fatalf("--mirror did not remove the entry: %s", data)
	}
}

// ---------------------------------------------------------------------------
// 2. wiring must not break an existing config
// ---------------------------------------------------------------------------

// parseCase pairs a manager with a realistic pre-existing config and a real
// format validator.
type parseCase struct {
	// seed is the pre-existing config content, written to the manager's
	// user-scope config path before Wire.
	seed string
	// refuses is true when the correct behaviour on this seed is to refuse
	// and leave the file untouched (H1 maven/nuget, H6 cargo).
	refuses bool
	// validate runs against the post-Wire file for the non-refusing cases.
	validate func(t *testing.T, data []byte)
	// preserved are substrings of the seed that must survive Wire.
	preserved []string
	// noLineEndings marks a format with no line-ending convention to
	// preserve. daemon.json is re-serialised by encoding/json, which always
	// emits LF; there is nothing for a CRLF round trip to assert.
	noLineEndings bool
}

func xmlIsWellFormed(t *testing.T, data []byte) {
	t.Helper()
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	for {
		_, err := dec.Token()
		if err == io.EOF {
			return
		}
		if err != nil {
			t.Fatalf("document is not well-formed XML: %v\n%s", err, data)
		}
	}
}

func tomlParses(t *testing.T, data []byte) {
	t.Helper()
	var v map[string]any
	if _, err := toml.Decode(string(data), &v); err != nil {
		t.Fatalf("config.toml does not parse: %v\n%s", err, data)
	}
}

func jsonParses(t *testing.T, data []byte) {
	t.Helper()
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("daemon.json does not parse: %v\n%s", err, data)
	}
}

// iniSection returns the INI section a key ends up in, or "" when absent.
// Deliberately hand-rolled: the point is to model what configparser sees.
func iniSection(data []byte, key string) string {
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if k, _, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == key {
			return section
		}
	}
	return ""
}

func parseCases() map[string]parseCase {
	return map[string]parseCase{
		"npm": {
			seed:      "registry=https://registry.npmjs.org/\nsave-exact=true\n",
			preserved: []string{"save-exact=true"},
		},
		"yarn": {
			seed:      "nodeLinker: node-modules\n",
			preserved: []string{"nodeLinker: node-modules"},
		},
		"bun": {
			seed:      "registry=https://registry.npmjs.org/\nsave-exact=true\n",
			preserved: []string{"save-exact=true"},
		},
		"pip": {
			// H8's exact repro: [global] is NOT the last section.
			seed:      "[global]\ntimeout = 60\n\n[freeze]\ntimeout = 10\n",
			preserved: []string{"timeout = 60", "[freeze]"},
			validate: func(t *testing.T, data []byte) {
				if got := iniSection(data, "index-url"); got != "global" {
					t.Fatalf("index-url landed in section %q, want \"global\" — installs are not routed through the proxy at all\n%s", got, data)
				}
			},
		},
		"cargo": {
			// H6: the standard shape for anyone already on a corporate
			// mirror. Appending our [source.crates-io] makes the file
			// unparseable and cargo then aborts on EVERY subcommand.
			seed:    "[source.crates-io]\nreplace-with = \"mirror\"\n\n[source.mirror]\nregistry = \"https://mirror.internal/index\"\n",
			refuses: true,
		},
		"maven": {
			// H1: appending "#" comments to XML produced
			// `[FATAL] Non-parseable settings` on Maven 3.9.9.
			seed:    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<settings>\n  <localRepository>/opt/repo</localRepository>\n</settings>\n",
			refuses: true,
		},
		"nuget": {
			seed:    "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<configuration>\n  <packageSources>\n    <add key=\"corp\" value=\"https://nuget.internal/v3/index.json\" />\n  </packageSources>\n</configuration>\n",
			refuses: true,
		},
		"gradle": {
			seed:      "// pre-existing init script\nprintln(\"hello\")\n",
			preserved: []string{"println(\"hello\")"},
			validate: func(t *testing.T, data []byte) {
				// Kotlin has no "#" line comment, and Gradle fails the
				// build when any script in init.d will not compile.
				for i, line := range strings.Split(string(data), "\n") {
					if strings.HasPrefix(strings.TrimSpace(line), "#") {
						t.Fatalf("line %d of a .gradle.kts file starts with '#', which is not valid Kotlin: %q", i+1, line)
					}
				}
			},
		},
		"sbt": {
			seed:      "# hand-written note\n[repositories]\n  local\n",
			preserved: []string{"hand-written note"},
		},
		"go": {
			seed:      "GOFLAGS=-mod=vendor\nGOPRIVATE=github.com/acme/*\n",
			preserved: []string{"GOPRIVATE=github.com/acme/*"},
		},
		"docker": {
			seed:          "{\n  \"log-level\": \"warn\"\n}\n",
			preserved:     []string{"log-level"},
			validate:      jsonParses,
			noLineEndings: true,
		},
	}
}

// TestEveryManagerWirePreservesExistingConfigParseability pairs each manager
// with a real format validator. It catches H1 (both maven and nuget) and H6.
func TestEveryManagerWirePreservesExistingConfigParseability(t *testing.T) {
	cases := parseCases()
	for _, m := range All() {
		tc, ok := cases[m.Name()]
		if !ok {
			t.Errorf("no parse fixture for manager %q — add one to parseCases()", m.Name())
			continue
		}
		t.Run(m.Name(), func(t *testing.T) {
			sandboxHome(t)
			path, err := m.ConfigPathForScope(ScopeUser)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.seed), 0o644); err != nil {
				t.Fatal(err)
			}

			err = m.Wire(testWireOpts())
			data, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Fatalf("read back %s: %v", path, rerr)
			}

			if tc.refuses {
				if err == nil {
					t.Fatalf("Wire silently rewrote a config it does not own; resulting %s:\n%s", path, data)
				}
				if string(data) != tc.seed {
					t.Fatalf("Wire refused but still modified %s:\n%s", path, data)
				}
				// The refusal must be actionable, not a bare failure.
				if !strings.Contains(err.Error(), path) {
					t.Errorf("refusal does not name the file: %v", err)
				}
				return
			}

			if err != nil {
				t.Fatalf("Wire: %v", err)
			}
			// Format-specific validators: XML/JSON/TOML documents must
			// still parse.
			switch m.Name() {
			case "maven", "nuget":
				xmlIsWellFormed(t, data)
			case "cargo":
				tomlParses(t, data)
			}
			if tc.validate != nil {
				tc.validate(t, data)
			}
			for _, want := range tc.preserved {
				if !strings.Contains(string(data), want) {
					t.Errorf("Wire dropped user content %q from %s:\n%s", want, path, data)
				}
			}
		})
	}
}

// TestFreshXMLConfigsAreWellFormed covers the standalone (no pre-existing
// file) path for the two XML managers, including a credential containing the
// characters that break XML.
func TestFreshXMLConfigsAreWellFormed(t *testing.T) {
	for _, m := range []Manager{mavenManager{}, nugetManager{}} {
		t.Run(m.Name(), func(t *testing.T) {
			sandboxHome(t)
			opts := testWireOpts()
			opts.Credentials = "cli-abc:a&b<c>d"
			if err := m.Wire(opts); err != nil {
				t.Fatalf("Wire: %v", err)
			}
			path, _ := m.ConfigPathForScope(ScopeUser)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			xmlIsWellFormed(t, data)
			if strings.Contains(string(data), "a&b<c>d") {
				t.Errorf("credential was interpolated without XML escaping:\n%s", data)
			}
		})
	}
}

// TestFreshCargoConfigParses covers cargo's standalone path.
func TestFreshCargoConfigParses(t *testing.T) {
	sandboxHome(t)
	m := cargoManager{}
	opts := testWireOpts()
	opts.Credentials = testCreds
	if err := m.Wire(opts); err != nil {
		t.Fatalf("Wire: %v", err)
	}
	path, _ := m.ConfigPathForScope(ScopeUser)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	tomlParses(t, data)
}

// ---------------------------------------------------------------------------
// 3. idempotency
// ---------------------------------------------------------------------------

// TestEveryManagerWireIsIdempotent guards H9 (a second Wire must replace, not
// stack another block) and H6's exclusion of tables inside our own sentinel
// (without it the SECOND `install-hook cargo` refuses and re-wiring breaks).
func TestEveryManagerWireIsIdempotent(t *testing.T) {
	for _, m := range All() {
		t.Run(m.Name(), func(t *testing.T) {
			sandboxHome(t)
			opts := testWireOpts()

			if err := m.Wire(opts); err != nil {
				t.Fatalf("first Wire: %v", err)
			}
			first := map[string]string{}
			for _, p := range managerPaths(t, m, ScopeUser) {
				b, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				first[p] = string(b)
			}

			if err := m.Wire(opts); err != nil {
				t.Fatalf("second Wire: %v", err)
			}
			for p, want := range first {
				got, err := os.ReadFile(p)
				if err != nil {
					t.Fatal(err)
				}
				if normalizeGeneratedAt(string(got)) != normalizeGeneratedAt(want) {
					t.Errorf("second Wire changed %s:\n--- first ---\n%s\n--- second ---\n%s", p, want, got)
				}
				if n := strings.Count(string(got), sentinelBodyStart); n > 1 {
					t.Errorf("%s carries %d start markers after two Wires; the file grows without bound", p, n)
				}
			}

			// wire → wire → unwire → status must still come out clean.
			if err := m.Unwire(ScopeUser); err != nil {
				t.Fatalf("Unwire after two Wires: %v", err)
			}
			st, err := m.Status()
			if err != nil {
				t.Fatal(err)
			}
			if st.Wired {
				t.Errorf("Status().Wired = true after Unwire")
			}
		})
	}
}

// normalizeGeneratedAt blanks the timestamp line so two runs compare equal.
func normalizeGeneratedAt(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		t = strings.TrimPrefix(t, "//")
		t = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(t), "#"))
		if strings.HasPrefix(t, "generated-at:") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}

// TestCargoWireWireUnwireStatusWithForeignTable is H6's full sequence with a
// user table present that does NOT collide.
func TestCargoWireWireUnwireStatusWithForeignTable(t *testing.T) {
	sandboxHome(t)
	m := cargoManager{}
	path, _ := m.ConfigPathForScope(ScopeUser)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	seed := "[net]\nretry = 3\n"
	if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := testWireOpts()
	for i := 0; i < 2; i++ {
		if err := m.Wire(opts); err != nil {
			t.Fatalf("Wire %d: %v", i+1, err)
		}
		data, _ := os.ReadFile(path)
		tomlParses(t, data)
	}
	if err := m.Unwire(ScopeUser); err != nil {
		t.Fatalf("Unwire: %v", err)
	}
	data, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "retry = 3") {
		t.Errorf("user's [net] table lost: %s", data)
	}
	st, _ := m.Status()
	if st.Wired {
		t.Error("Status().Wired = true after Unwire")
	}
}

// ---------------------------------------------------------------------------
// 4. go's GOFLAGS
// ---------------------------------------------------------------------------

// TestGoWirePreservesExistingGOFLAGS catches H10: the block used to emit a
// bare `GOFLAGS=`, and Go's readEnvFile takes the LAST occurrence — so a user
// with `GOFLAGS=-mod=vendor` silently lost it and vendored builds switched to
// module mode.
func TestGoWirePreservesExistingGOFLAGS(t *testing.T) {
	cases := []struct {
		name        string
		seed        string
		wantGoflags string
		wantDropped []string
	}{
		{
			name:        "vendor flag survives",
			seed:        "GOFLAGS=-mod=vendor\n",
			wantGoflags: "-mod=vendor",
		},
		{
			name:        "multiple flags survive",
			seed:        "GOFLAGS=-mod=vendor -trimpath\n",
			wantGoflags: "-mod=vendor -trimpath",
		},
		{
			name:        "documented bypass token is stripped and reported",
			seed:        "GOFLAGS=-mod=vendor -insecure\n",
			wantGoflags: "-mod=vendor",
			wantDropped: []string{"-insecure"},
		},
		{
			name:        "no existing value stays empty",
			seed:        "GOPRIVATE=github.com/acme/*\n",
			wantGoflags: "",
		},
		{
			name:        "an earlier chainsaw empty GOFLAGS is not sticky",
			seed:        "GOFLAGS=-mod=vendor\nGOPROXY=x\nGOFLAGS=\n",
			wantGoflags: "-mod=vendor",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sandboxHome(t)
			m := goModManager{}
			path, _ := m.ConfigPathForScope(ScopeUser)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.seed), 0o644); err != nil {
				t.Fatal(err)
			}
			var notes []string
			opts := testWireOpts()
			opts.Notify = func(msg string) { notes = append(notes, msg) }
			if err := m.Wire(opts); err != nil {
				t.Fatalf("Wire: %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			// Go resolves the LAST occurrence, which is what a build sees.
			if got := existingGoflagsRaw(data); got != tc.wantGoflags {
				t.Errorf("effective GOFLAGS = %q, want %q\n%s", got, tc.wantGoflags, data)
			}
			for _, want := range tc.wantDropped {
				found := false
				for _, n := range notes {
					if strings.Contains(n, want) {
						found = true
					}
				}
				if !found {
					t.Errorf("dropped %q from GOFLAGS without telling the user; notes = %v", want, notes)
				}
			}
		})
	}
}

// existingGoflagsRaw returns the LAST GOFLAGS value in a go env file,
// including an empty one — exactly what Go's readEnvFile resolves to.
func existingGoflagsRaw(data []byte) string {
	lines, _ := splitLines(data)
	out := ""
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "GOFLAGS=") {
			out = strings.TrimSpace(strings.TrimPrefix(t, "GOFLAGS="))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// 5. file modes
// ---------------------------------------------------------------------------

// TestEveryManagerCredentialFileMode catches H5 (secret-bearing configs
// created world-readable 0644 while a comment claimed 0600) AND guards
// against the rejected blanket-0600 over-fix, which would have made a
// root-owned /etc/npmrc unreadable by every non-root user.
func TestEveryManagerCredentialFileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	for _, m := range All() {
		t.Run(m.Name(), func(t *testing.T) {
			sandboxHome(t)
			opts := testWireOpts()
			opts.Credentials = testCreds
			if err := m.Wire(opts); err != nil {
				t.Fatalf("Wire: %v", err)
			}
			for _, p := range managerPaths(t, m, ScopeUser) {
				info, err := os.Stat(p)
				if err != nil {
					t.Fatalf("stat %s: %v", p, err)
				}
				if got := info.Mode().Perm(); got != 0o600 {
					t.Errorf("%s mode = %04o, want 0600 (the wire embedded a client secret)", p, got)
				}
			}
		})
	}
}

// TestSystemScopeConfigsStayGroupReadable is the guard against the rejected
// over-fix. writeAtomicMode is also the ScopeSystem write path (/etc/npmrc,
// /etc/pip.conf, /etc/go/env); 0600 there breaks the tool for every non-root
// user on the box.
func TestSystemScopeConfigsStayGroupReadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "npmrc")
	opts := WireOpts{Credentials: testCreds, Scope: ScopeSystem}
	if err := writeConfigFile(path, []byte("registry=x\n"), opts); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Fatalf("system-scope config mode = %04o, want 0644 — a 0600 /etc/npmrc is unreadable by every non-root user", got)
	}
}

// TestCredentialFileModePolicy pins the decision table directly.
func TestCredentialFileModePolicy(t *testing.T) {
	cases := []struct {
		name        string
		opts        WireOpts
		wantMode    os.FileMode
		wantTighten bool
	}{
		{"user scope with credentials", WireOpts{Credentials: testCreds, Scope: ScopeUser}, 0o600, true},
		{"project scope with credentials", WireOpts{Credentials: testCreds, Scope: ScopeProject}, 0o600, true},
		{"empty scope with credentials", WireOpts{Credentials: testCreds}, 0o600, true},
		{"system scope with credentials", WireOpts{Credentials: testCreds, Scope: ScopeSystem}, 0o644, false},
		{"user scope without credentials", WireOpts{Scope: ScopeUser}, 0o644, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode, tighten := credentialFileMode(tc.opts)
			if mode != tc.wantMode || tighten != tc.wantTighten {
				t.Fatalf("credentialFileMode = (%04o, %v), want (%04o, %v)", mode, tighten, tc.wantMode, tc.wantTighten)
			}
		})
	}
}

// TestExistingLooseConfigIsTightenedWhenSecretsLand covers the upgrade path:
// files already on disk at 0644 stay 0644 forever unless we chmod them down,
// because writeAtomicMode preserves an existing file's mode.
func TestExistingLooseConfigIsTightenedWhenSecretsLand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}
	sandboxHome(t)
	m := npmManager{}
	path, _ := m.ConfigPathForScope(ScopeUser)
	if err := os.WriteFile(path, []byte("save-exact=true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var notes []string
	opts := testWireOpts()
	opts.Credentials = testCreds
	opts.Notify = func(msg string) { notes = append(notes, msg) }
	if err := m.Wire(opts); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("existing 0644 config was not tightened; mode = %04o", got)
	}
	tightened := false
	for _, n := range notes {
		if strings.Contains(n, "0600") {
			tightened = true
		}
	}
	if !tightened {
		t.Errorf("tightened the file mode without telling the user; notes = %v", notes)
	}
}

// ---------------------------------------------------------------------------
// 6. CRLF
// ---------------------------------------------------------------------------

// TestEveryManagerRoundTripUnderCRLF pins that a Windows-authored config
// survives wire → wire → unwire with its content and line endings intact.
func TestEveryManagerRoundTripUnderCRLF(t *testing.T) {
	cases := parseCases()
	for _, m := range All() {
		tc, ok := cases[m.Name()]
		if !ok || tc.refuses || tc.seed == "" || tc.noLineEndings {
			// Managers that refuse an existing foreign config have nothing
			// to round-trip, and a re-serialised JSON document has no line
			// endings of its own to preserve.
			continue
		}
		t.Run(m.Name(), func(t *testing.T) {
			sandboxHome(t)
			seed := strings.ReplaceAll(tc.seed, "\n", "\r\n")
			path, err := m.ConfigPathForScope(ScopeUser)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(seed), 0o644); err != nil {
				t.Fatal(err)
			}
			opts := testWireOpts()
			if err := m.Wire(opts); err != nil {
				t.Fatalf("first Wire: %v", err)
			}
			if err := m.Wire(opts); err != nil {
				t.Fatalf("second Wire: %v", err)
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.ReplaceAll(string(data), "\r\n", ""), "\n") {
				t.Errorf("mixed line endings after Wire on a CRLF file:\n%q", data)
			}
			st, err := m.Status()
			if err != nil {
				t.Fatal(err)
			}
			if !st.Wired {
				t.Fatalf("Status().Wired = false on a CRLF config")
			}
			if err := m.Unwire(ScopeUser); err != nil {
				t.Fatalf("Unwire: %v", err)
			}
			after, err := os.ReadFile(path)
			if errors.Is(err, os.ErrNotExist) {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got, want := normalizeTrailing(string(after)), normalizeTrailing(seed); got != want {
				t.Errorf("CRLF round trip did not restore the original:\ngot  %q\nwant %q", got, want)
			}
		})
	}
}

func normalizeTrailing(s string) string { return strings.TrimRight(s, "\r\n") }

// ---------------------------------------------------------------------------
// registry completeness
// ---------------------------------------------------------------------------

// TestEveryManagerAppearsInMatrixTables makes it impossible to add a manager
// to All() without giving it a fixture here. Six managers previously shipped
// with no test file at all, and that is where every HIGH-severity hook defect
// was found.
func TestEveryManagerAppearsInMatrixTables(t *testing.T) {
	cases := parseCases()
	for _, m := range All() {
		if _, ok := cases[m.Name()]; !ok {
			t.Errorf("manager %q is registered in All() but has no entry in parseCases(); every manager must be covered by the wire/status/unwire, parseability, idempotency, file-mode and CRLF tables", m.Name())
		}
	}
	for name := range cases {
		if _, err := ByName(name); err != nil {
			t.Errorf("parseCases() has a fixture for %q, which is not a registered manager", name)
		}
	}
}
