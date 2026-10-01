package capability

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures are real class files, compiled by javac 26 (--release 17) and
// stored gzip+base64.
//
// Pos.java calls Runtime.exec, URL.openConnection, System.getenv,
// new FileOutputStream, Files.readAllBytes, System.loadLibrary,
// ScriptEngine.eval and ClassLoader.defineClass(String, byte[], int, int),
// and declares a native method.
//
// Neg.java carries the capability names as string constants ("exec",
// "java/lang/ProcessBuilder", "getenv openConnection loadLibrary defineClass
// eval"), references Runtime (availableProcessors), URL (toString),
// ProcessBuilder.Redirect, reflection (Method.invoke, Class.forName) and a
// lambda — and calls nothing that grants a capability.

const posClassB64 = "" +
	"H4sIAAAAAAAC/4VU61bTQBD+lhYS0ggSRRBvgLe2KFG8W0RtBUXLRSrUirdtu9Rw0oSTpBzwPXwP" +
	"/QNVjz6AD+VxNhQBLdofmc7sfDPfXHZ//PzyHcAdLGloQURBVEcr2hi6l/kqN23uVMyMzX0/6/Ky" +
	"8BjaRi3HCsYYIvHEggYV7Qo0HTHoDF07mLmaE1hVwaBVRPBb6Y4nsn/5pBR0MBzcsecCz3IqKg4y" +
	"tPjvVBgkL5ZkrsM6unGEISrWRIkhHl/M/glL7c4w67kl4fuUoZdBD+2OCMz5uayGHvTJUo9JVk2i" +
	"LEiPEzpO4hRDh7sinIzrOKIUWK7D0LddSCPczllKxQARfDQzNa7hNM4oOKvjHM7vrXDdD0SVmknN" +
	"Ec4qw7n4vwtpmBQkGHpDs+WaE5YtZmrBSi2gY8GrKoZoLG4t0BBHn4ph6pvlaLiEywpGdFzBVYZD" +
	"W7QJvkRwc5YH73xCERGGVBMW+3d4T4yUhuu4oeCmjlu4/VcaSZXS6ESzfN+20+uBVHvjzSIlFtMq" +
	"RhnYe9nAMR135ZBiNi1g1ip63FtXcJ+hX0LXTL/kWSuBmQvFuFOxHDHFHV4RnoZ7iKh4QF1Y9qUy" +
	"oeMhHjF0UrFbnun1aS730ty3/U0TpGJ4jCcKsjqmMM1wdF9Puaqr3P7/gGeKy7Q/tDyzNIy14YKG" +
	"OeQUPNMxjwUyzbrUr1hZLFHQ8D4yJJpNKz05uTts6JoiFhm3TGQ6swSfrlWLwnvGi7akV+UW7fOR" +
	"pjeJEmvjayWxIhfbV/Bqe66h1+8TiiKHIy/SYrpZ9vacVXF4UPOEnHkTn9HkGLlp5GOtigy37fB5" +
	"mSRTzq15JSHXh0GlJgxLJAaoOy2QvyiYfK/omyftBElGsjW5CfaJ/jA8p2/blhHtKOAFAaXrh4aV" +
	"16G0fcOBQsTozBWiRleu0JqMjOQ2cCj/FT2FZHRkE0c3cDxv9NcxSLZ4waDwF/LGxQjh6jDruJY3" +
	"UnXc+Yp7hU2kjcwGxpOtI58xSbl2aAzSCwYoOEYyQWRMaHRZYpiAjic4gLfowGKjppckX+NNg+xp" +
	"Ii/rjSWNmaHI0PcNPP34R3VdBAc5cVKKKIWn5dAifgGvQSq25AUAAA=="

const negClassB64 = "" +
	"H4sIAAAAAAAC/51We1cbRRT/DQlsCEuBpRSoFqGFSlCylfoqYEVSEDSkSICU4muSTJKFzW66O8HE" +
	"9/ur+Lf+AZz26Afw+Jk83t2lTTDQekzO7uTeue/7uzP58++HfwB4Cz9H0YaQgrCKdnQw9O7xA66b" +
	"3Crqd7N7IicZOuYNy5C3GUKTse0oIuhUEFXRBZWhryG+UbWkURYM0aKQT4iByViyRWbOs3JBRQ96" +
	"Gfpp1zB51hTrjp0Trms7ru9rNQKNobPqCidesssiiosYUHBJxSCGTkWarrtSlBm6yDMZqQhH1hmu" +
	"TzZ5TkvHsIpzsVaWgssMqs+2hNS3NpIRPM+glaSszOq6qPFyxRTxnF2OYhgjXp1e8PI6w/i2JzGm" +
	"4iquMUSkHfAZLk6e4bcTE7iu4EUVk4gxjDUETuqwWDXMvHDGN0TecPxOKKuplaWN1U2Ga8lnilNi" +
	"L1EdU6IYwTRDuMwNS4HO0NNQTZjcdRW8Ql3YbY0wijhuqngVr1EbqLRrQpbsPMPCGbk3q/tWT5Xa" +
	"EQWTQtIDC2T4Dbyp4JaKWcwxDJ0nSNgzrAN7n3B0q9lngMxTPk9YsVaW5uFcxW28TdVwqhbDpX9j" +
	"0vLQR/V65zEQDFtfNkwRQYKB1aJYwIj3WlbxLlYoKlEzXBmg9L5XpfdUvI8kNahgOynu4X7iGeAL" +
	"ahRFCncVrKv4ABsMg/5+VRomFaIoavo6l1I4FLJC8KtQRAzT5xtuVZyLgMDC6p6fbRUZ3CNTZS5z" +
	"JeEw3Gw2lShxJy0eVIWVE2cYXAuUKOL72FXwoYqPvEoMniNHeCsYFjWQpWmUWiNm6E7Yliu5Jbe5" +
	"WaVKZ0lF1ESOVDYjEKdQcRrhJLEVQYlhhjAprINRGniLrFnUbcO2Rk2b55NG1uFOfTQvKAzhF3tU" +
	"HHCTnCTsPFnvSRI/VS1nhbPpdd9Dxe5ZI03n2VItJyqeaRoV6kV/Q+rJDuVj8nI2z8e9MRu/QVpp" +
	"u+rkxLLftAhNYdxTo2Nr0balKx1eCTDu9qKjpwPVKKZwoML2KYJcHZ8r+ELFl/iK4WrDZTAQetL3" +
	"RiZ4geek7dB511Vupv5qbu6JUuBxhVt5U7jjSdver1bmWpM+T3GzXhH/bzNw+XTdWOtugptm2pCC" +
	"4KKuUn8dv5GC2uDV9PFBp+B7mrf/lKyCHxlGni5K4x0IY4xa0kanRwhD+BifgOFTotrAic410Xmi" +
	"C010kTSYd53S2yDOFVoZre1TR2C/0g+GPXp3BEx0Yhr7pOaJ/kLcdlqLx1AO0T2v9R2jP/MIwzva" +
	"c0e4cojRzG8YX9OmtJfDvyO+E9JupA8xk5pmRLbthKaIej3zEPPAbPgRFna0xSPcOcRSZio0c4zV" +
	"jLZ4jDWNpLYOsZNpBBOn+xz0KFDRTd/LuIARuqB19NK/hD7cgUZnVD/u0SVcwABMkg6Tbrk36mH2" +
	"JNNhBJ+WLPuoJBW/OA/g0KoS9zPiuZD0fE0cjfYm8A2+DXfiO/yAnzD8D2sAQAClCAAA"

func unfixture(t *testing.T, b64 string) []byte {
	t.Helper()
	gz, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	r, err := gzip.NewReader(bytes.NewReader(gz))
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// writeFixtureTree writes files (slash paths) under a temp dir.
func writeFixtureTree(t *testing.T, files map[string][]byte) string {
	t.Helper()
	dir := t.TempDir()
	for name, b := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func mustAnalyze(t *testing.T, dir, eco string) *Report {
	t.Helper()
	r, err := Analyze(dir, eco)
	if err != nil {
		t.Fatal(err)
	}
	if r.Unsupported {
		t.Fatalf("%s reported unsupported", eco)
	}
	return r
}

func TestMavenPositiveClass(t *testing.T) {
	dir := writeFixtureTree(t, map[string][]byte{"com/example/Pos.class": unfixture(t, posClassB64)})
	r := mustAnalyze(t, dir, "maven")
	want := map[Capability]string{
		CapShell:           "java/lang/Runtime.exec",
		CapNetwork:         "java/net/URL.openConnection",
		CapEnvAccess:       "java/lang/System.getenv",
		CapFilesystemWrite: "java/io/FileOutputStream.<init>",
		CapFilesystemRead:  "java/nio/file/Files.readAllBytes",
		CapNativeCode:      "",
		CapDynamicEval:     "",
	}
	for c, snip := range want {
		evs := r.Capabilities[c]
		if len(evs) == 0 {
			t.Errorf("%s not detected", c)
			continue
		}
		if evs[0].File != "com/example/Pos.class" || evs[0].Line != 0 {
			t.Errorf("%s evidence location = %+v", c, evs[0])
		}
		if !strings.Contains(evs[0].Snippet, snip) {
			t.Errorf("%s snippet = %q, want it to name %q", c, evs[0].Snippet, snip)
		}
		if r.Counts[c] != 1 {
			t.Errorf("%s count = %d, want 1 (one file)", c, r.Counts[c])
		}
	}
	// Both dynamic-eval routes are in Pos: check each is recognised alone.
	refs, native, err := parseClassRefs(unfixture(t, posClassB64))
	if err != nil || !native {
		t.Fatalf("parse: native=%v err=%v", native, err)
	}
	var sawEval, sawDefine bool
	for _, ref := range refs {
		sawEval = sawEval || ref.owner == "javax/script/ScriptEngine" && ref.name == "eval"
		sawDefine = sawDefine || ref.name == "defineClass" && strings.Contains(ref.desc, "[B")
	}
	if !sawEval || !sawDefine {
		t.Errorf("ScriptEngine.eval seen=%v, defineClass([B) seen=%v", sawEval, sawDefine)
	}
}

func TestMavenNegativeClass(t *testing.T) {
	b := unfixture(t, negClassB64)
	r := mustAnalyze(t, writeFixtureTree(t, map[string][]byte{"com/example/Neg.class": b}), "maven")
	if len(r.Capabilities) != 0 {
		t.Fatalf("Neg.class fired %v", r.Capabilities)
	}

	// The guard is resolving Methodrefs instead of matching bytes. Prove the
	// fixture would defeat a byte grep, so this test fails if that guard goes:
	// the owner classes are referenced and the method names are in the pool.
	for _, s := range []string{"java/lang/Runtime", "exec", "java/lang/ProcessBuilder", "getenv", "defineClass", "java/net/URL", "openConnection"} {
		if !bytes.Contains(b, []byte(s)) {
			t.Errorf("fixture no longer contains %q; it has stopped testing the guard", s)
		}
	}
	// And the owner half alone is not enough: Runtime and URL ARE called.
	refs, _, err := parseClassRefs(b)
	if err != nil {
		t.Fatal(err)
	}
	owners := map[string]bool{}
	for _, ref := range refs {
		owners[ref.owner] = true
	}
	for _, o := range []string{"java/lang/Runtime", "java/net/URL", "java/lang/reflect/Method"} {
		if !owners[o] {
			t.Errorf("fixture no longer calls a method on %s", o)
		}
	}
}

// A class under a package named "test" ships and loads like any other.
func TestMavenDoesNotSkipTestPackages(t *testing.T) {
	dir := writeFixtureTree(t, map[string][]byte{"com/example/test/Pos.class": unfixture(t, posClassB64)})
	if r := mustAnalyze(t, dir, "gradle"); !r.Has(CapShell) {
		t.Fatal("class under a test package was skipped")
	}
}

func TestMavenNestedJarAndNativeLib(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create("com/example/Pos.class")
	_, _ = w.Write(unfixture(t, posClassB64))
	w, _ = zw.Create("jni/arm64-v8a/libfoo.so")
	_, _ = w.Write([]byte("\x7fELF"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	dir := writeFixtureTree(t, map[string][]byte{"classes.jar": buf.Bytes()})
	r := mustAnalyze(t, dir, "maven")
	if evs := r.Capabilities[CapShell]; len(evs) == 0 || evs[0].File != "classes.jar!/com/example/Pos.class" {
		t.Errorf("nested jar class: %+v", evs)
	}
	var sawSo bool
	for _, ev := range r.Capabilities[CapNativeCode] {
		sawSo = sawSo || ev.File == "classes.jar!/jni/arm64-v8a/libfoo.so"
	}
	if !sawSo {
		t.Errorf("nested .so not reported: %+v", r.Capabilities[CapNativeCode])
	}
}

// WebJars and mvnpm jars are npm packages; their JS is scanned.
func TestMavenWebJarJavaScript(t *testing.T) {
	dir := writeFixtureTree(t, map[string][]byte{
		"META-INF/resources/webjars/x/1.0/index.js": []byte("const cp = require('child_process');\ncp.exec(cmd);\n"),
	})
	if r := mustAnalyze(t, dir, "maven"); !r.Has(CapShell) {
		t.Fatalf("webjar JS not scanned: %v", r.Capabilities)
	}
}

func TestMavenMalformedClass(t *testing.T) {
	good := unfixture(t, posClassB64)
	dir := writeFixtureTree(t, map[string][]byte{
		"a/Trunc.class": good[:len(good)/2],
		"a/Junk.class":  []byte("\xca\xfe\xba\xbe\x00\x00\x00\x3d\xff\xff\x63"),
		"a/Empty.class": nil,
	})
	if r := mustAnalyze(t, dir, "maven"); len(r.Capabilities) != 0 {
		t.Fatalf("malformed classes produced %v", r.Capabilities)
	}
}

func TestMavenRegistered(t *testing.T) {
	for _, e := range []string{"maven", "Gradle"} {
		if !Supported(e) {
			t.Errorf("%s not supported", e)
		}
	}
}
