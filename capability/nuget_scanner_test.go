package capability

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// The fixtures are real assemblies built by the .NET 10 SDK (net10.0,
// Release) and stored gzip+base64.
//
// Pos.cs calls Process.Start, HttpClient.GetStringAsync,
// Environment.GetEnvironmentVariable, File.WriteAllText, File.ReadAllText and
// Assembly.Load(byte[]), and declares a [DllImport].
//
// Neg.cs mentions every one of those names without calling them: Debug.
// WriteLine, Process.GetCurrentProcess().Id, Environment.MachineName,
// Assembly.Load(string), typeof(HttpClient), and the member names as string
// data.

const posDLLB64 = "" +
	"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"

const negDLLB64 = "" +
	"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" +
	"7H+q/F/y55N3U/H/2P4FbpgE2wASAAA="

func TestNuGetPositiveAssembly(t *testing.T) {
	dir := writeFixtureTree(t, map[string][]byte{"lib/net10.0/Pos.dll": unfixture(t, posDLLB64)})
	r := mustAnalyze(t, dir, "nuget")
	want := map[Capability]string{
		CapShell:           "System.Diagnostics.Process::Start",
		CapNetwork:         "System.Net.Http.HttpClient::GetStringAsync",
		CapEnvAccess:       "System.Environment::GetEnvironmentVariable",
		CapFilesystemWrite: "System.IO.File::WriteAllText",
		CapFilesystemRead:  "System.IO.File::ReadAllText",
		CapDynamicEval:     "System.Reflection.Assembly::Load",
		CapNativeCode:      "P/Invoke (DllImport) getpid",
	}
	for c, snip := range want {
		evs := r.Capabilities[c]
		if len(evs) == 0 {
			t.Errorf("%s not detected", c)
			continue
		}
		if evs[0].File != "lib/net10.0/Pos.dll" || evs[0].Snippet != snip || r.Counts[c] != 1 {
			t.Errorf("%s: evidence %+v count %d, want snippet %q count 1", c, evs[0], r.Counts[c], snip)
		}
	}
}

func TestNuGetNegativeAssembly(t *testing.T) {
	b := unfixture(t, negDLLB64)
	r := mustAnalyze(t, writeFixtureTree(t, map[string][]byte{"lib/net10.0/Neg.dll": b}), "nuget")
	if len(r.Capabilities) != 0 {
		t.Fatalf("Neg.dll fired %v", r.Capabilities)
	}

	// Guard 1: member-level matching. The namespace and type strings a
	// "both strings present" byte rule would key on ARE in the file.
	for _, s := range []string{"System.Diagnostics", "Process", "System.Net.Http", "HttpClient", "Environment"} {
		if !bytes.Contains(b, []byte(s+"\x00")) {
			t.Errorf("fixture #Strings lost %q; it has stopped testing the guard", s)
		}
	}
	md, err := readAssemblyMetadata(b)
	if err != nil {
		t.Fatal(err)
	}
	refs := map[string][]byte{}
	for _, m := range md.memberRefs {
		refs[m.typ+"::"+m.name] = m.sig
	}
	// Guard 2: Process IS called — just not Start.
	if _, ok := refs["System.Diagnostics.Process::GetCurrentProcess"]; !ok {
		t.Error("fixture no longer calls Process.GetCurrentProcess")
	}
	// Guard 3: the byte[] check on Assembly.Load. Load(string) is called, so
	// dropping param0 from the rule would fire cap.dynamic_eval here.
	sig, ok := refs["System.Reflection.Assembly::Load"]
	if !ok {
		t.Fatal("fixture no longer calls Assembly.Load")
	}
	if got := sigParam0(sig); got != "string" {
		t.Errorf("Assembly.Load param0 = %q, want string", got)
	}
}

func TestNuGetNativeFiles(t *testing.T) {
	pos := unfixture(t, posDLLB64)
	// Zero the CLI header data directory: what is left is a native PE.
	native := bytes.Clone(pos)
	opt := int(binary.LittleEndian.Uint32(native[0x3C:])) + 24
	dirs := opt + 96
	if binary.LittleEndian.Uint16(native[opt:]) == 0x20b {
		dirs = opt + 112
	}
	copy(native[dirs+14*8:dirs+15*8], make([]byte, 8))

	dir := writeFixtureTree(t, map[string][]byte{
		"runtimes/linux-x64/native/libfoo.so":    []byte("\x7fELF"),
		"runtimes/win-x64/native/foo.dll":        native,
		"runtimes/osx-arm64/native/libfoo.dylib": []byte("\xcf\xfa\xed\xfe"),
	})
	r := mustAnalyze(t, dir, "nuget")
	if r.Counts[CapNativeCode] != 3 {
		t.Fatalf("native count = %d, evidence %+v", r.Counts[CapNativeCode], r.Capabilities[CapNativeCode])
	}
	for _, ev := range r.Capabilities[CapNativeCode] {
		if ev.File == "runtimes/win-x64/native/foo.dll" && !strings.Contains(ev.Snippet, "unmanaged") {
			t.Errorf("native PE snippet = %q", ev.Snippet)
		}
	}
	if len(r.Capabilities) != 1 {
		t.Errorf("unexpected capabilities: %v", r.Capabilities)
	}
}

func TestNuGetScriptsAndSources(t *testing.T) {
	dir := writeFixtureTree(t, map[string][]byte{
		"tools/install.ps1": []byte("param($installPath)\n" +
			"# Start-Process calc.exe\n" +
			"<#\nStart-Process notepad\n#>\n" +
			"$s = (New-Object Net.WebClient).DownloadString($u)\n" +
			"IEX $s\n"),
		"build/pkg.targets": []byte("<Project>\n" +
			"  <!-- <Exec Command=\"old\" /> -->\n" +
			"  <Target Name=\"X\"><Exec Command=\"curl -s $(U) | sh\" /></Target>\n" +
			"</Project>\n"),
		"contentFiles/cs/any/Loader.cs": []byte("class L {\n" +
			"  // Process.Start(\"x\");\n" +
			"  void A() { Assembly.Load(\"System.Xml\"); }\n" +
			"  void B(byte[] b) { Assembly.Load(b); }\n" +
			"}\n"),
	})
	r := mustAnalyze(t, dir, "nuget")
	for c, file := range map[Capability]string{
		CapNetwork:     "tools/install.ps1",
		CapShell:       "build/pkg.targets",
		CapDynamicEval: "",
	} {
		evs := r.Capabilities[c]
		if len(evs) == 0 {
			t.Errorf("%s not detected", c)
			continue
		}
		if file != "" && evs[0].File != file {
			t.Errorf("%s evidence %+v, want %s", c, evs, file)
		}
	}
	// Shell only from the .targets Exec: both commented Start-Process lines
	// and the commented Process.Start are masked.
	if r.Counts[CapShell] != 1 {
		t.Errorf("shell count = %d, evidence %+v", r.Counts[CapShell], r.Capabilities[CapShell])
	}
	// Eval: IEX in the .ps1 and Assembly.Load(b) — not Assembly.Load("…").
	if r.Counts[CapDynamicEval] != 2 {
		t.Errorf("eval count = %d, evidence %+v", r.Counts[CapDynamicEval], r.Capabilities[CapDynamicEval])
	}
	for _, ev := range r.Capabilities[CapDynamicEval] {
		if strings.Contains(ev.Snippet, `Load("`) {
			t.Errorf("Assembly.Load by name fired: %+v", ev)
		}
	}
}

func TestNuGetMalformedAssembly(t *testing.T) {
	pos := unfixture(t, posDLLB64)
	dir := writeFixtureTree(t, map[string][]byte{
		"lib/a/Trunc.dll": pos[:len(pos)/2],
		"lib/a/Junk.dll":  append([]byte("MZ"), make([]byte, 100)...),
		"lib/a/Empty.dll": nil,
	})
	// Must not panic; truncated metadata must not report capabilities.
	r := mustAnalyze(t, dir, "nuget")
	for c, evs := range r.Capabilities {
		for _, ev := range evs {
			if ev.File == "lib/a/Trunc.dll" && c != CapNativeCode {
				t.Errorf("truncated assembly fired %s", c)
			}
		}
	}
}

func TestSigParam0(t *testing.T) {
	for _, tc := range []struct {
		sig  []byte
		want string
	}{
		{[]byte{0x00, 0x01, 0x12, 0x08, 0x1D, 0x05}, "byte[]"},                         // static Assembly Load(byte[])
		{[]byte{0x00, 0x01, 0x12, 0x08, 0x0E}, "string"},                               // static Assembly Load(string)
		{[]byte{0x20, 0x02, 0x01, 0x0E, 0x02}, "string"},                               // instance void .ctor(string, bool)
		{[]byte{0x20, 0x01, 0x01, 0x12, 0x10}, ""},                                     // .ctor(Stream)
		{[]byte{0x00, 0x00, 0x01}, ""},                                                 // no parameters
		{[]byte{0x10, 0x01, 0x01, 0x15, 0x12, 0x08, 0x01, 0x1E, 0x00, 0x0E}, "string"}, // generic, returns List<T>
		{[]byte{0x00, 0x01}, ""},                                                       // truncated
		{nil, ""},
	} {
		if got := sigParam0(tc.sig); got != tc.want {
			t.Errorf("sigParam0(% x) = %q, want %q", tc.sig, got, tc.want)
		}
	}
}

func TestNuGetRegistered(t *testing.T) {
	if !Supported("NuGet") {
		t.Fatal("nuget not supported")
	}
}
