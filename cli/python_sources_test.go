package cli

// P1b (docs/PLANS_INTELLIGENCE.md#plan-non-registry-sources): the install
// guard's pip sweep and pr-scan read Pipfile.lock / poetry.lock / uv.lock
// through core/depparser — the server's parsers — and decide each package's
// source the guard's way (pythonSource). requirements files keep their own
// reader on the guard (readPipFile) and gain sources in pr-scan.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// fixture reads one of the depparser parsers' real-format test files.
func fixture(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "depparser", "parser", "python", rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func withMirrors(t *testing.T, hosts ...string) {
	t.Helper()
	prev := viper.Get("registry_mirrors")
	t.Cleanup(func() { viper.Set("registry_mirrors", prev) })
	if len(hosts) == 0 {
		viper.Set("registry_mirrors", nil)
		return
	}
	viper.Set("registry_mirrors", hosts)
}

func specLines(specs []packageSpec) []string {
	var out []string
	for _, s := range specs {
		l := s.Name + "@" + s.Version
		switch {
		case s.Local:
			l += " local"
		case s.Origin != "":
			l += " " + s.Origin
		}
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// TestPipSweepUVLockSources: a bare `pip install` in a uv project (real uv
// output, HathorNetwork/hathor-core and OpenTrafficCam/OTVision). The git
// dependency and an undeclared index carry their Origin; the editable
// project and local paths are Local (first-party, malware lookup only — they
// used to be checked as their PyPI namesakes); PyPI and a PyPI file URL are
// registry specs; a registry_mirrors host is the registry. Break it like
// this: make pythonSource return the registry coordinate for every Origin.
func TestPipSweepUVLockSources(t *testing.T) {
	withMirrors(t)
	lock := fixture(t, "uv/testdata/uv.lock")
	dir := chdirTemp(t)
	mustWrite(t, filepath.Join(dir, "uv.lock"), string(lock))
	got := specLines(expandLockfile("pip", []string{"install"}))
	want := []string{
		"aiohappyeyeballs@2.3.5",
		"from-url@1.0 https://example.com/dist/from_url-1.0.tar.gz",
		"hathor-ct-crypto@ local",
		"hathor@0.72.0 local",
		"hathorlib@0.15.0 local",
		"local-dir@0.2 local",
		"local-path@0.1 file:../wheels/local_path-0.1-py3-none-any.whl", // a vendored wheel is not local code
		"private-index@3.0 registry+https://nexus.example/repository/pypi/simple",
		"pypi-url@2.0",
		"rocksdb@0.10.1 git+https://github.com/hathornetwork/python-rocksdb.git#8c20974458995ab7a1a64e046a40311e58450ffd",
		"tensorrt-cu12-bindings@10.12.0.36 registry+https://pypi.nvidia.com/",
		"workspace-root@ local",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	withMirrors(t, "nexus.example")
	for _, l := range specLines(expandLockfile("pip", []string{"install"})) {
		if strings.HasPrefix(l, "private-index@") && l != "private-index@3.0" {
			t.Errorf("declared mirror: %q, want a registry spec", l)
		}
	}
}

// TestPipSweepPoetryAndPipfileSources: the same rule for poetry.lock (real
// poketwo/hhru/OpenMined packages) and Pipfile.lock. A git package used to be
// a PyPI spec; a lockfile of only VCS/editable entries used to parse to zero
// and scan nothing.
func TestPipSweepPoetryAndPipfileSources(t *testing.T) {
	withMirrors(t)
	lock := fixture(t, "poetry/testdata/poetry.lock")
	dir := chdirTemp(t)
	mustWrite(t, filepath.Join(dir, "poetry.lock"), string(lock))
	got := strings.Join(specLines(expandLockfile("pip", []string{"install"})), "\n")
	for _, want := range []string{
		"discord-ext-menus@1.0.0a32+g8686b5d git+https://github.com/Rapptz/discord-ext-menus.git#8686b5d1bbc1d3c862292eb436ab630d6e9c9b53",
		"consul@1.0.0 registry+https://devpi.pyn.ru/hh/hhdev/+simple",
		"absl-py@2.4.0\n", // a legacy source that is pypi.org
		"localdir@0.1.0 local",
		"fromurl@0.3.0 https://example.com/fromurl-0.3.0.tar.gz",
	} {
		if !strings.Contains(got+"\n", want) {
			t.Errorf("poetry sweep lacks %q:\n%s", want, got)
		}
	}

	dir = chdirTemp(t)
	mustWrite(t, filepath.Join(dir, "Pipfile.lock"), `{"_meta": {"sources": [{"name": "pypi", "url": "https://pypi.org/simple"}]},
 "default": {"mylib": {"git": "https://github.com/example/mylib.git", "ref": "abc1234", "editable": true}}, "develop": {}}`)
	if got := specLines(expandLockfile("pip", []string{"install"})); len(got) != 1 || got[0] != "mylib@ git+https://github.com/example/mylib.git#abc1234" {
		t.Errorf("VCS-only Pipfile.lock: %v", got)
	}
}

// TestPRScanPythonLockSources: pr-scan diffs a Python lockfile as
// coordinates and reports a newly added git/index package as not from PyPI,
// never as its namesake.
func TestPRScanPythonLockSources(t *testing.T) {
	withMirrors(t)
	base := []byte("version = 1\n\n[[package]]\nname = \"attrs\"\nversion = \"25.1.0\"\nsource = { registry = \"https://pypi.org/simple\" }\n")
	head := append(append([]byte(nil), base...), []byte(`
[[package]]
name = "attrs"
version = "23.1.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "rocksdb"
version = "0.10.1"
source = { git = "https://github.com/hathornetwork/python-rocksdb.git#8c20974458995ab7a1a64e046a40311e58450ffd" }

[[package]]
name = "corp"
version = "1.0"
source = { registry = "https://artifactory.example/api/pypi/pypi-remote/simple" }

[[package]]
name = "proj"
version = "0.1"
source = { editable = "." }
`)...)
	added, upgraded, err := diffManifest(kindUVLock, "uv.lock", base, head)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range append(added, upgraded...) {
		got = append(got, e.Name+"@"+e.Version+" "+e.Origin)
	}
	sort.Strings(got)
	want := []string{
		"attrs@23.1.0 ", // a second line of attrs beside 25.1.0: an addition, kept apart
		"corp@1.0 registry+https://artifactory.example/api/pypi/pypi-remote/simple",
		"rocksdb@0.10.1 git+https://github.com/hathornetwork/python-rocksdb.git#8c20974458995ab7a1a64e046a40311e58450ffd",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if r := nonRegistryReason("pip", "git+https://github.com/x/y#abc"); !strings.HasPrefix(r, "not from PyPI: not assessed") {
		t.Errorf("reason %q", r)
	}
	if _, _, err := diffManifest(kindPoetryLock, "poetry.lock", nil, []byte("[[package]\nname=")); err == nil {
		t.Error("a malformed poetry.lock must be a parse error, not an empty diff")
	}
}

// TestPRScanRequirementsSources: requirements source lines (real corpus
// lines) become not-assessed rows instead of vanishing; a non-PyPI
// --index-url moves every index requirement — ranges included — off PyPI
// unless the host is a declared mirror.
func TestPRScanRequirementsSources(t *testing.T) {
	withMirrors(t)
	src := fixture(t, "requirements/testdata/sources.txt")
	reg, nonReg := parsePipRequirementsSources(src)
	if reg["accelerate"] != "1.2.1" || reg["flash-attn"] != "2.7.3" {
		t.Errorf("registry = %v", reg)
	}
	var names []string
	for _, d := range nonReg {
		names = append(names, d.Name+"@"+d.Version)
	}
	sort.Strings(names)
	if want := "aiohec@ beignet@ chromecontroller@ flash-attn@2.7.3+cu12torch2.5cxx11abiFalse mdx-outline@"; strings.Join(names, " ") != want {
		t.Errorf("non-registry = %v, want %s", names, want)
	}

	idx := []byte("--index-url https://nexus.corp.example/repository/pypi/simple\nrequests==2.31.0\nflask>=3.0\n")
	reg, nonReg = parsePipRequirementsSources(idx)
	if len(reg) != 0 || len(nonReg) != 2 || nonReg[0].Origin != "registry+https://nexus.corp.example/repository/pypi/simple" {
		t.Errorf("undeclared index: reg=%v nonReg=%+v", reg, nonReg)
	}
	withMirrors(t, "nexus.corp.example")
	if reg, nonReg = parsePipRequirementsSources(idx); len(reg) != 2 || len(nonReg) != 0 {
		t.Errorf("declared mirror: reg=%v nonReg=%+v", reg, nonReg)
	}
}

// TestPipSpecWheelVersionNormalisedName: `flash-attn @ …/flash_attn-2.7.3…whl`
// (corpus: prescient-design/lobster) names the wheel's version; the project
// names differ only in PEP 503 spelling.
func TestPipSpecWheelVersionNormalisedName(t *testing.T) {
	s := parsePipSpec("flash-attn @ https://github.com/Dao-AILab/flash-attention/releases/download/v2.7.3/flash_attn-2.7.3+cu12torch2.5cxx11abiFalse-cp310-cp310-linux_x86_64.whl ; python_full_version < '3.11'")
	if s.Name != "flash-attn" || s.Version != "2.7.3+cu12torch2.5cxx11abiFalse" || s.Origin == "" {
		t.Errorf("%+v", s)
	}
}
