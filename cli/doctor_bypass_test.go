package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParsePipIndexURL(t *testing.T) {
	body := `[global]
index-url = https://chainsaw.example.com/repository/pypi/simple
extra-index-url = https://example.com/extra
`
	got := parsePipIndexURL(body)
	want := "https://chainsaw.example.com/repository/pypi/simple"
	if got != want {
		t.Fatalf("parsePipIndexURL: got %q want %q", got, want)
	}
}

// The 2026-11-05 report: crates.io replaced by a hand-pasted [source.chainsaw]
// pointing at a proxy decommissioned a year earlier. Every cargo fetch 502'd
// and doctor said nothing, because the old scan only looked for `index =`.
const deadCargoConfig = `[source.crates-io]
replace-with = "chainsaw"

[source.chainsaw]
registry = "sparse+https://z-auto:s3cret@old-proxy.example.net/chainproxy/repository/crates-io/"
`

func TestParseCargoUpstream(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"replaced source (the docs shape)", deadCargoConfig, "sparse+https://z-auto:s3cret@old-proxy.example.net/chainproxy/repository/crates-io/"},
		{"replace-with names a registry", "[source.crates-io]\nreplace-with = \"corp\"\n[registries.corp]\nindex = \"sparse+https://corp.example/idx/\"\n", "sparse+https://corp.example/idx/"},
		{"chained replacement", "[source.crates-io]\nreplace-with = \"a\"\n[source.a]\nreplace-with = \"b\"\n[source.b]\nregistry = \"https://b.example/\"\n", "https://b.example/"},
		{"a named registry alone does not reroute crates.io", "[registries.chainsaw]\nindex = \"sparse+https://c.example/\"\n", ""},
		{"cycle terminates", "[source.crates-io]\nreplace-with = \"a\"\n[source.a]\nreplace-with = \"crates-io\"\n", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		got, err := parseCargoUpstream(c.body)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}
	if _, err := parseCargoUpstream("[source\n"); err == nil {
		t.Error("broken TOML parsed clean")
	}
}

func TestDoctorReportsDeadForeignCargoUpstream(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CARGO_HOME", filepath.Join(home, ".cargo"))
	t.Setenv("GOENV", filepath.Join(home, "goenv"))
	t.Setenv("GOPROXY", "")
	t.Setenv("PIP_CONFIG_FILE", "")
	t.Setenv("PIP_INDEX_URL", "")
	if err := os.MkdirAll(filepath.Join(home, ".cargo"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".cargo", "config.toml"), []byte(deadCargoConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	var probed []string
	old := probeUpstream
	t.Cleanup(func() { probeUpstream = old })
	probeUpstream = func(_ context.Context, target string) (int, error) {
		probed = append(probed, target)
		return 502, nil
	}

	fs := upstreamFindings("", true)
	var cargo bypassFinding
	for _, f := range fs {
		if f.Ecosystem == "cargo" {
			cargo = f
		}
	}
	if !cargo.Unreachable || cargo.InBlock || cargo.Probe != "HTTP 502" {
		t.Fatalf("cargo finding %+v", cargo)
	}
	if len(probed) != 1 || probed[0] != "https://old-proxy.example.net/chainproxy/repository/crates-io/config.json" {
		t.Fatalf("probed %v (credentials must be stripped; sparse index probes config.json)", probed)
	}
	var out strings.Builder
	printUpstreams(&out, fs, true)
	for _, want := range []string{"old-proxy.example.net", "HTTP 502", "outside any chainsaw block", "every cargo install routed here fails", "[source.crates-io]"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("doctor output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), "s3cret") {
		t.Fatal("doctor printed the registry password")
	}
	if f, ok := foreignUpstream("cargo"); !ok || f.ConfigPath != filepath.Join(home, ".cargo", "config.toml") {
		t.Fatalf("uninstall-hook would not name the foreign redirect: %+v %v", f, ok)
	}
}

func TestUpstreamProbeVerdicts(t *testing.T) {
	old := probeUpstream
	t.Cleanup(func() { probeUpstream = old })
	for _, c := range []struct {
		code        int
		err         error
		unreachable bool
	}{{200, nil, false}, {401, nil, false}, {404, nil, false}, {503, nil, true}, {0, errors.New("dial tcp: connection refused"), true}} {
		probeUpstream = func(context.Context, string) (int, error) { return c.code, c.err }
		fs := []bypassFinding{{Ecosystem: "npm", Configured: "https://r.example/"}}
		probeUpstreams(fs)
		if fs[0].Unreachable != c.unreachable {
			t.Errorf("code %d err %v: unreachable=%v", c.code, c.err, fs[0].Unreachable)
		}
	}
}

func TestPublicRegistryIsNotAFinding(t *testing.T) {
	var out strings.Builder
	printUpstreams(&out, []bypassFinding{{Ecosystem: "npm", Configured: "https://registry.npmjs.org/", Probe: "HTTP 200"}}, true)
	if out.Len() != 0 {
		t.Fatalf("public default printed: %q", out.String())
	}
}

func TestDriftCompare(t *testing.T) {
	cases := []struct {
		name                       string
		configured, expected, want string
	}{
		{"missing", "", "https://chainsaw.example.com", "missing"},
		{"identical", "https://chainsaw.example.com", "https://chainsaw.example.com", "ok"},
		{"trailing-slash", "https://chainsaw.example.com/", "https://chainsaw.example.com", "ok"},
		{"path-deeper-on-configured", "https://chainsaw.example.com/repository/pypi/simple", "https://chainsaw.example.com", "ok"},
		{"path-deeper-on-expected", "https://chainsaw.example.com", "https://chainsaw.example.com/repo/pypi", "ok"},
		{"different-host", "https://registry.npmjs.org", "https://chainsaw.example.com", "drift"},
		{"no-expected-passthrough", "https://example.com", "", "ok"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := driftCompare(c.configured, c.expected)
			if got != c.want {
				t.Fatalf("driftCompare(%q,%q)=%q want %q", c.configured, c.expected, got, c.want)
			}
		})
	}
}

// TestCheckGemrcMissingIsNotAnError exercises the "missing config
// file" path — should report n/a, not error.
func TestCheckGemrcMissingIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if got := checkGemrc("https://chainsaw.example.com").Status; got != "n/a" {
		t.Fatalf("expected n/a status for missing .gemrc, got %q", got)
	}
}

// TestCheckNpmrcDriftDetected: a .npmrc that points away from the
// configured chainsaw URL must report drift.
func TestCheckNpmrcDriftDetected(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"),
		[]byte("registry=https://registry.npmjs.org/\n"), 0o644); err != nil {
		t.Fatalf("write .npmrc: %v", err)
	}
	got := checkNpmrc("https://chainsaw.example.com")
	if got.Status != "drift" {
		t.Fatalf("expected drift, got %q (configured=%q)", got.Status, got.Configured)
	}
}

func TestCheckNpmrcOK(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"),
		[]byte("registry=https://chainsaw.example.com/repository/npm/\n"), 0o644); err != nil {
		t.Fatalf("write .npmrc: %v", err)
	}
	got := checkNpmrc("https://chainsaw.example.com")
	if got.Status != "ok" {
		t.Fatalf("expected ok, got %q (configured=%q)", got.Status, got.Configured)
	}
}

// npm applies the LAST registry= line. A file that names Chainsaw first and
// the public registry last bypasses Chainsaw and must report drift.
func TestCheckNpmrcLastRegistryWins(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	body := "registry=https://chainsaw.example.com/repository/npm/\n; comment\n@acme:registry=https://chainsaw.example.com/repository/npm/\nregistry=https://registry.npmjs.org/\n"
	if err := os.WriteFile(filepath.Join(dir, ".npmrc"), []byte(body), 0o644); err != nil {
		t.Fatalf("write .npmrc: %v", err)
	}
	if got := checkNpmrc("https://chainsaw.example.com"); got.Status != "drift" {
		t.Fatalf("a trailing public registry= must drift, got %q (configured=%q)", got.Status, got.Configured)
	}
}
