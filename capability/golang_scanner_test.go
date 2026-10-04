package capability_test

import (
	"strings"
	"testing"

	"github.com/chain305/chainsaw-core/capability"
)

// nativeCase is one scanner fixture: files to write, capabilities that must
// fire and capabilities that must not.
type nativeCase struct {
	name   string
	files  map[string]string
	want   []capability.Capability
	absent []capability.Capability
}

func runNativeCases(t *testing.T, eco string, cases []nativeCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			for name, src := range tc.files {
				writeTestFile(t, dir, name, src)
			}
			rep, err := capability.Analyze(dir, eco)
			if err != nil {
				t.Fatal(err)
			}
			if rep.Unsupported {
				t.Fatalf("%s reported unsupported", eco)
			}
			for _, c := range tc.want {
				if !rep.Has(c) {
					t.Errorf("%s did not fire; got %v", c, rep.Capabilities)
				}
			}
			for _, c := range tc.absent {
				if rep.Has(c) {
					t.Errorf("%s fired: %+v", c, rep.Capabilities[c])
				}
			}
		})
	}
}

var nativeAllCaps = []capability.Capability{
	capability.CapNetwork, capability.CapShell, capability.CapFilesystemWrite, capability.CapFilesystemRead,
	capability.CapEnvAccess, capability.CapNativeCode, capability.CapDynamicEval,
}

func goSrc(imports, body string) string {
	return "package p\n\nimport (\n" + imports + "\n)\n\nfunc f() {\n" + body + "\n}\n"
}

func TestScanGo(t *testing.T) {
	t.Parallel()
	c := capability.CapShell
	runNativeCases(t, "go", []nativeCase{
		// positives
		{name: "os/exec import", files: map[string]string{"a.go": goSrc(`"os/exec"`, `exec.Command("sh").Run()`)}, want: []capability.Capability{c}},
		{name: "aliased os/exec", files: map[string]string{"a.go": goSrc(`run "os/exec"`, `run.Command("sh").Run()`)}, want: []capability.Capability{c}},
		{name: "syscall.Exec", files: map[string]string{"a.go": goSrc(`"syscall"`, `syscall.Exec("/bin/sh", nil, nil)`)}, want: []capability.Capability{c}},
		{name: "os.Getenv", files: map[string]string{"a.go": goSrc(`"os"`, `_ = os.Getenv("HOME")`)}, want: []capability.Capability{capability.CapEnvAccess}},
		{name: "aliased os.LookupEnv", files: map[string]string{"a.go": goSrc(`sys "os"`, `_, _ = sys.LookupEnv("HOME")`)}, want: []capability.Capability{capability.CapEnvAccess}},
		{name: "os.WriteFile", files: map[string]string{"a.go": goSrc(`"os"`, `_ = os.WriteFile("x", nil, 0o600)`)}, want: []capability.Capability{capability.CapFilesystemWrite}},
		{name: "OpenFile with write flags", files: map[string]string{"a.go": goSrc(`"os"`, "f, _ := os.OpenFile(\"x\",\n\tos.O_RDWR|os.O_CREATE, 0o600)\n_ = f")}, want: []capability.Capability{capability.CapFilesystemWrite}},
		{name: "OpenFile read-only is a read", files: map[string]string{"a.go": goSrc(`"os"`, `f, _ := os.OpenFile("x", os.O_RDONLY, 0); _ = f`)},
			want: []capability.Capability{capability.CapFilesystemRead}, absent: []capability.Capability{capability.CapFilesystemWrite}},
		{name: "os.ReadFile", files: map[string]string{"a.go": goSrc(`"os"`, `_, _ = os.ReadFile("x")`)}, want: []capability.Capability{capability.CapFilesystemRead}},
		{name: "http.ListenAndServe", files: map[string]string{"a.go": goSrc(`"net/http"`, `_ = http.ListenAndServe(":80", nil)`)}, want: []capability.Capability{capability.CapNetwork}},
		{name: "net.Dial", files: map[string]string{"a.go": goSrc(`"net"`, `_, _ = net.Dial("tcp", "x:1")`)}, want: []capability.Capability{capability.CapNetwork}},
		{name: "grpc import", files: map[string]string{"a.go": goSrc(`"google.golang.org/grpc"`, `_ = grpc.NewServer()`)}, want: []capability.Capability{capability.CapNetwork}},
		{name: "cgo", files: map[string]string{"a.go": "package p\n\n// #include <stdio.h>\nimport \"C\"\n\nfunc f() { C.puts(nil) }\n"}, want: []capability.Capability{capability.CapNativeCode}},
		{name: "syso object", files: map[string]string{"a.go": "package p\n", "rsrc_windows_amd64.syso": "\x00"}, want: []capability.Capability{capability.CapNativeCode}},
		{name: "plugin", files: map[string]string{"a.go": goSrc(`"plugin"`, `_, _ = plugin.Open("x.so")`)}, want: []capability.Capability{capability.CapDynamicEval}},

		// false-positive traps
		{name: "comment", files: map[string]string{"a.go": goSrc(`"os"`, "// os.Getenv(\"HOME\")\n/* exec.Command(\"sh\") */\n_ = os.Args")}, absent: nativeAllCaps},
		{name: "template string holding an import", files: map[string]string{"a.go": "package p\n\nvar tmpl = `package main\nimport \"os/exec\"\nfunc main() { exec.Command(\"sh\") }`\n"}, absent: nativeAllCaps},
		{name: "local shadows the package", files: map[string]string{"a.go": goSrc(`"os"`, "_ = os.Args\nos := struct{ Getenv func(string) string }{}\n_ = os.Getenv(\"HOME\")")}, absent: nativeAllCaps},
		{name: "different package named exec", files: map[string]string{"a.go": goSrc(`"example.com/exec"`, `exec.Command("x")`)}, absent: nativeAllCaps},
		{name: "net for parsing only", files: map[string]string{"a.go": goSrc(`"net"`, `_ = net.ParseIP("1.2.3.4")`)}, absent: nativeAllCaps},
		{name: "net/http types and in-memory requests", files: map[string]string{"a.go": goSrc(`"net/http"`, `r, _ := http.NewRequest("GET", "/", nil); _ = r; _ = http.StatusOK`)}, absent: nativeAllCaps},
		{name: "unsafe and reflect are nothing", files: map[string]string{"a.go": goSrc("\"reflect\"\n\"unsafe\"", `var x int; _ = unsafe.Pointer(&x); _ = reflect.TypeOf(x)`)}, absent: nativeAllCaps},
		{name: "go assembly is not native", files: map[string]string{"a.go": "package p\n\nfunc add(a, b int) int\n", "add_amd64.s": "TEXT ·add(SB),4,$0\n\tRET\n"}, absent: nativeAllCaps},
		{name: "_test.go file", files: map[string]string{"a_test.go": goSrc(`"os/exec"`, `exec.Command("sh")`)}, absent: nativeAllCaps},
		{name: "build-ignored generator", files: map[string]string{"gen.go": "//go:build ignore\n\n" + goSrc(`"os/exec"`, `exec.Command("sh")`)}, absent: nativeAllCaps},
		{name: "go:generate-tagged generator", files: map[string]string{"gen.go": "//go:build generate\n\n" + goSrc(`"os"`, `_ = os.WriteFile("x", nil, 0)`)}, absent: nativeAllCaps},
		{name: "skipped dirs", files: map[string]string{
			"testdata/a.go":         goSrc(`"os/exec"`, `exec.Command("sh")`),
			"vendor/x/a.go":         goSrc(`"os/exec"`, `exec.Command("sh")`),
			"_tools/a.go":           goSrc(`"os/exec"`, `exec.Command("sh")`),
			"internal/testenv/a.go": goSrc(`"os/exec"`, `exec.Command("sh")`),
			"acme/acmetest/a.go":    goSrc(`"os/exec"`, `exec.Command("sh")`),
		}, absent: nativeAllCaps},
	})
}

func TestScanGo_EvidenceAndCount(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	writeTestFile(t, dir, "sub/a.go", goSrc(`"os"`, "_ = os.Getenv(\"A\")\n_ = os.Getenv(\"B\")\n_, _ = os.Getenv(\"C\"), os.Getenv(\"D\")"))
	rep, err := capability.Analyze(dir, "golang")
	if err != nil {
		t.Fatal(err)
	}
	// Four calls on three lines: counts are per line, like the other scanners.
	if got := rep.Counts[capability.CapEnvAccess]; got != 3 {
		t.Fatalf("count = %d, want 3", got)
	}
	ev := rep.Capabilities[capability.CapEnvAccess][0]
	if ev.File != "sub/a.go" || ev.Line != 8 || !strings.Contains(ev.Snippet, `os.Getenv("A")`) {
		t.Fatalf("evidence = %+v", ev)
	}
}

// A module zip nests every file under the module PATH, and a path segment that
// is also a skipped directory name (examples, tests, vendor, ...) must not hide
// the module. The test directory INSIDE the module is still skipped.
func TestScanGo_ModulePathSegmentsAreNotSkipDirs(t *testing.T) {
	t.Parallel()
	runNativeCases(t, "go", []nativeCase{
		{
			name: "vitess examples module",
			files: map[string]string{
				"vitess.io/vitess/examples/are-you-alive@v0.0.0-20201226175325-4df037de0a7d/pkg/client/client.go": goSrc(`"net/http"`, `_, _ = http.Get("http://vtgate:15001")`),
				"vitess.io/vitess/examples/are-you-alive@v0.0.0-20201226175325-4df037de0a7d/test/fake.go":         goSrc(`"os/exec"`, `_ = exec.Command("sh")`),
			},
			want:   []capability.Capability{capability.CapNetwork},
			absent: []capability.Capability{capability.CapShell},
		},
		{
			name: "kops tests module",
			files: map[string]string{
				"k8s.io/kops/tests/e2e@v0.0.0-20260505071424-48f41f4149cd/pkg/env.go": goSrc(`"os"`, `_ = os.Getenv("KOPS_STATE_STORE")`),
			},
			want: []capability.Capability{capability.CapEnvAccess},
		},
	})
}
