package homebrew

import (
	"bytes"
	"os"
	"runtime"
	"strings"
	"testing"
)

// The test binary itself is a thin 64-bit Mach-O on macOS: flip one code
// byte and the hash moves; rewrite only what a pour rewrites (an install
// name, given the matching relocation) and it does not.
func TestMachOHash(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("needs a Mach-O fixture")
	}
	exe, _ := os.Executable()
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	base := MachOHash(b, nil)
	if base == "" {
		t.Fatal("test binary not hashed")
	}
	if MachOHash([]byte("#!/bin/sh\n"), nil) != "" {
		t.Fatal("a script hashed as Mach-O")
	}

	flip := append([]byte(nil), b...)
	flip[len(flip)/2] ^= 1
	if MachOHash(flip, nil) == base {
		t.Error("a changed byte in the middle of the binary kept the hash")
	}

	const real, moved = "/usr/lib/libSystem.B.dylib", "/usr/lib/libSystem.Q.dylib"
	if !bytes.Contains(b, []byte(real)) {
		t.Skip("binary does not link libSystem by name")
	}
	renamed := bytes.Replace(b, []byte(real), []byte(moved), 1)
	if MachOHash(renamed, nil) == base {
		t.Error("an install-name change kept the hash")
	}
	if got := MachOHash(renamed, strings.NewReplacer(moved, real)); got != base {
		t.Error("the relocation that undoes the rename did not restore the hash")
	}
}

func TestRelocationReplacer(t *testing.T) {
	r, err := Relocation{Prefix: "/usr/local", Perl: "/usr/bin/perl5.34"}.Replacer()
	if err != nil {
		t.Fatal(err)
	}
	got := r.Replace("@@HOMEBREW_PREFIX@@ @@HOMEBREW_CELLAR@@ @@HOMEBREW_REPOSITORY@@ @@HOMEBREW_LIBRARY@@ #!@@HOMEBREW_PERL@@ @@HOMEBREW_JAVA@@")
	if got != "/usr/local /usr/local/Cellar /usr/local/Homebrew /usr/local/Homebrew/Library #!/usr/bin/perl5.34 @@HOMEBREW_JAVA@@" {
		t.Errorf("got %q", got)
	}
	for _, bad := range []Relocation{{Prefix: "/tmp"}, {Prefix: "/opt/homebrew", Java: "rel/path"}, {Prefix: "/opt/homebrew", Perl: "/usr/../bin/perl"}} {
		if _, err := bad.Replacer(); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
