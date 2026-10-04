package codesmell

import (
	"encoding/binary"
	"os"
	"testing"
)

// Fixtures in testdata/native are real bytes, not hand-made headers:
//
//	Hello.class               javac --release 8 output (class file 52.0)
//	ilonly.dll                a netstandard2.0 class library, dotnet build
//	e_sqlite3-x86-headers.dll the first 1 KiB of SQLitePCLRaw.lib.e_sqlite3
//	                          2.1.10 runtimes/win-x86/native/e_sqlite3.dll
//	r2r-kestrel-namedpipes-headers.dll  the first 4 KiB of a ReadyToRun
//	                          assembly from Microsoft.AspNetCore.App.Runtime.
//	                          osx-x64 9.0.3 (CLI flags 0xc: IL_LIBRARY, no ILONLY)
//	fat-macho-header.bin      the first 64 bytes of macOS /usr/bin/true, a
//	                          two-slice universal binary
func nativeFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/native/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestScanNativeBinary_JavaClassIsNotFatMachO(t *testing.T) {
	if k := detectBinaryByMagic(nativeFixture(t, "Hello.class")); k != "" {
		t.Fatalf("Java class sniffed as %q", k)
	}
	if k := detectBinaryByMagic(nativeFixture(t, "fat-macho-header.bin")); k != "Mach-O" {
		t.Fatalf("fat Mach-O sniffed as %q", k)
	}
	res := ScanNativeBinary(map[string][]byte{
		"com/example/Hello.class": nativeFixture(t, "Hello.class"),
		"bin/tool":                nativeFixture(t, "fat-macho-header.bin"),
	})
	if len(res.Matches) != 1 || res.Matches[0].Path != "bin/tool" {
		t.Fatalf("want only the fat binary, got %+v", res.Matches)
	}
}

func TestScanNativeBinary_ILOnlyDLLIsNotNative(t *testing.T) {
	il := nativeFixture(t, "ilonly.dll")
	native := nativeFixture(t, "e_sqlite3-x86-headers.dll")
	if !peILOnly(il) {
		t.Fatal("IL-only assembly not recognised")
	}
	if peILOnly(native) {
		t.Fatal("native DLL read as IL-only")
	}
	if !peILOnly(nativeFixture(t, "r2r-kestrel-namedpipes-headers.dll")) {
		t.Fatal("ReadyToRun assembly read as native")
	}
	res := ScanNativeBinary(map[string][]byte{
		"lib/netstandard2.0/tiny.dll":           il,
		"lib/netstandard2.0/tiny-renamed":       il, // magic path, no extension
		"runtimes/win-x86/native/e_sqlite3":     native,
		"runtimes/win-x86/native/e_sqlite3.dll": native,
	})
	got := map[string]bool{}
	for _, m := range res.Matches {
		got[m.Path] = true
	}
	if got["lib/netstandard2.0/tiny.dll"] || got["lib/netstandard2.0/tiny-renamed"] {
		t.Errorf("IL-only assembly counted as native: %+v", res.Matches)
	}
	if !got["runtimes/win-x86/native/e_sqlite3.dll"] || !got["runtimes/win-x86/native/e_sqlite3"] {
		t.Errorf("native DLL lost: %+v", res.Matches)
	}
}

// Mixed-mode (C++/CLI) assemblies clear COMIMAGE_FLAGS_ILONLY and carry
// native code, so they stay native. Built from the real IL-only fixture by
// clearing that one bit.
func TestScanNativeBinary_MixedModeStaysNative(t *testing.T) {
	b := append([]byte(nil), nativeFixture(t, "ilonly.dll")...)
	cli := cliHeaderOffset(t, b)
	binary.LittleEndian.PutUint32(b[cli+16:], binary.LittleEndian.Uint32(b[cli+16:])&^1)
	if peILOnly(b) {
		t.Fatal("mixed-mode assembly read as IL-only")
	}
	if res := ScanNativeBinary(map[string][]byte{"lib/x.dll": b}); !res.Fired {
		t.Fatal("mixed-mode assembly not reported native")
	}
	// A header cut off before the CLI header is unreadable: keep native.
	if peILOnly(b[:cli+8]) {
		t.Fatal("truncated assembly read as IL-only")
	}
}

// cliHeaderOffset finds the CLI header independently of peILOnly, through
// the fixture's single section mapping.
func cliHeaderOffset(t *testing.T, b []byte) int {
	t.Helper()
	le := binary.LittleEndian
	pe := int(le.Uint32(b[0x3C:]))
	opt := pe + 24
	rva := int(le.Uint32(b[opt+96+14*8:]))
	secs := opt + int(le.Uint16(b[pe+20:]))
	for i := 0; i < int(le.Uint16(b[pe+6:])); i++ {
		s := secs + 40*i
		va, size, ptr := int(le.Uint32(b[s+12:])), int(le.Uint32(b[s+16:])), int(le.Uint32(b[s+20:]))
		if rva >= va && rva < va+size {
			return rva - va + ptr
		}
	}
	t.Fatal("fixture has no CLI header")
	return 0
}
