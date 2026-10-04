package codesmell

import (
	"bytes"
	"encoding/binary"
	"path"
	"strings"
)

// nativeBinaryExts is the extension set that indicates an artifact ships
// a pre-compiled native binary — the classic install-time-code-execution
// vehicle for npm / pip packages.
var nativeBinaryExts = map[string]struct{}{
	".node":  {}, // Node-API addon
	".so":    {}, // ELF shared object
	".dll":   {}, // Windows dynamic link library
	".dylib": {}, // macOS dynamic library
	".a":     {}, // static archive
	".lib":   {}, // Windows static library / import library
	".pyd":   {}, // Python extension module
	".wasm":  {}, // WebAssembly module — still code the host will execute
}

// binaryBuildArtifacts is the filename set that indicates a build
// recipe for native code even when no compiled binary ships with the
// package (binding.gyp runs at `npm install` time).
//
// A Makefile is NOT in it. It names no language and runs at no install step:
// on the 2026-10 corpus it was the only native evidence on 36 packages (22 Go
// modules, 11 PyPI sdists) and socket.dev's hasNativeCode agreed on none.
var binaryBuildArtifacts = map[string]struct{}{
	"binding.gyp": {},
	"cargo.toml":  {}, // handled separately — only a signal when a [lib] section is present
}

// ScanNativeBinary fires when any path in the map carries a native
// binary extension OR a recognised build-artifact basename. The match
// list includes every offending file so the UI can point at them;
// Fired is true as soon as we find the first one (scan continues to
// populate Matches up to the cap).
//
// binding.gyp is treated as a fire on its own because its presence is
// enough to run a native-compile step at install time on npm — which is
// the threat the signal targets.
func ScanNativeBinary(files map[string][]byte) Result {
	var res Result
	if len(files) == 0 {
		return res
	}
	visited := 0
	for _, name := range sortedNames(files) {
		if visited >= MaxFilesPerScan*4 {
			// Native-binary scan is cheaper than regex scans — we can
			// afford a wider cap, but still bound so a million-file
			// archive can't OOM the match list.
			break
		}
		visited++
		base := strings.ToLower(path.Base(name))
		ext := strings.ToLower(path.Ext(base))
		if _, ok := nativeBinaryExts[ext]; ok {
			// A .dll is usually a managed assembly, not native code: every
			// nupkg's lib/ is full of them. IL-only ones are skipped.
			if ext == ".dll" && peILOnly(files[name]) {
				continue
			}
			res.addMatch(Match{Path: name, Kind: "native-binary"})
			continue
		}
		if _, ok := binaryBuildArtifacts[base]; ok {
			// Skip Cargo.toml — the native signal for Cargo is [lib]
			// cdylib and that requires content inspection, handled by
			// the install-scripts provider.
			if base == "cargo.toml" {
				continue
			}
			res.addMatch(Match{Path: name, Kind: "build-recipe"})
			continue
		}
		// Extension miss — fall back to magic-byte sniff so a binary
		// renamed to `.txt` (or no extension at all) still flags. A
		// repackaging trick used by malicious npm/pip drops to evade
		// extension-only scanners.
		if kind := detectBinaryByMagic(files[name]); kind != "" && !(kind == "PE" && peILOnly(files[name])) {
			res.addMatch(Match{Path: name, Kind: "native-binary:" + kind})
		}
	}
	return res
}

// detectBinaryByMagic inspects the first ≤16 bytes of a file body for
// the well-known executable / object-file magic numbers. Returns "" when
// the bytes do not match any known shape.
//
//	ELF:    \x7fELF
//	Mach-O: \xfe\xed\xfa\xce, \xfe\xed\xfa\xcf  (32/64 BE)
//	        \xce\xfa\xed\xfe, \xcf\xfa\xed\xfe  (32/64 LE)
//	        \xca\xfe\xba\xbe                    (universal/fat, see below)
//	PE:     "MZ" at offset 0
//
// 0xCAFEBABE is also the Java class-file magic, so every .class in a jar
// read as a fat Mach-O. They are told apart the way file(1) does: a fat
// header's next big-endian u32 is nfat_arch, a handful of slices; a class
// file's is minor<<16|major, and major is at least 45.
func detectBinaryByMagic(b []byte) string {
	if len(b) < 4 {
		return ""
	}
	head := b
	if len(head) > 16 {
		head = head[:16]
	}
	switch {
	case bytes.HasPrefix(head, []byte{0x7f, 'E', 'L', 'F'}):
		return "ELF"
	case bytes.HasPrefix(head, []byte{0xfe, 0xed, 0xfa, 0xce}),
		bytes.HasPrefix(head, []byte{0xfe, 0xed, 0xfa, 0xcf}),
		bytes.HasPrefix(head, []byte{0xce, 0xfa, 0xed, 0xfe}),
		bytes.HasPrefix(head, []byte{0xcf, 0xfa, 0xed, 0xfe}):
		return "Mach-O"
	case bytes.HasPrefix(head, []byte{0xca, 0xfe, 0xba, 0xbe}):
		if len(head) >= 8 {
			if n := binary.BigEndian.Uint32(head[4:8]); n > 0 && n < 45 {
				return "Mach-O"
			}
		}
		return ""
	case bytes.HasPrefix(head, []byte{'M', 'Z'}):
		return "PE"
	}
	return ""
}

// peILOnly reports whether b is a .NET assembly with no native code of its
// own: its CLI header sets COMIMAGE_FLAGS_ILONLY (pure IL) or
// COMIMAGE_FLAGS_IL_LIBRARY (a ReadyToRun image: the package's own IL plus
// machine code the .NET toolchain precompiled from it, as in every
// Microsoft.*.App.Runtime pack's lib/). Neither is a native binary. A
// mixed-mode (C++/CLI) assembly sets neither and still counts as native. Anything unreadable — not a PE, no CLI directory,
// a header past the retained bytes — returns false, which keeps the old
// answer: native.
func peILOnly(b []byte) bool {
	le := binary.LittleEndian
	in := func(off, n int) bool { return off >= 0 && n >= 0 && off+n <= len(b) }
	if !in(0, 0x40) || b[0] != 'M' || b[1] != 'Z' {
		return false
	}
	pe := int(le.Uint32(b[0x3C:]))
	if !in(pe, 24) || string(b[pe:pe+4]) != "PE\x00\x00" {
		return false
	}
	nsec := int(le.Uint16(b[pe+6:]))
	optSize := int(le.Uint16(b[pe+20:]))
	opt := pe + 24
	if !in(opt, optSize) || optSize < 2 {
		return false
	}
	var nDirs, dirs int
	switch le.Uint16(b[opt:]) {
	case 0x10b: // PE32
		nDirs, dirs = 92, 96
	case 0x20b: // PE32+
		nDirs, dirs = 108, 112
	default:
		return false
	}
	// Data directory 14 is the CLI header.
	if dirs+15*8 > optSize || le.Uint32(b[opt+nDirs:]) < 15 {
		return false
	}
	// A native PE leaves it zero, which no section maps.
	cliRVA := int(le.Uint32(b[opt+dirs+14*8:]))
	secs := opt + optSize
	for i := 0; i < nsec && i < 96; i++ {
		s := secs + 40*i
		if !in(s, 40) {
			return false
		}
		va, vs, raw, ptr := int(le.Uint32(b[s+12:])), int(le.Uint32(b[s+8:])), int(le.Uint32(b[s+16:])), int(le.Uint32(b[s+20:]))
		if cliRVA >= va && cliRVA < va+max(vs, raw) {
			cli := cliRVA - va + ptr
			// IMAGE_COR20_HEADER.Flags is at offset 16.
			return in(cli, 20) && le.Uint32(b[cli+16:])&(0x1|0x4) != 0
		}
	}
	return false
}
