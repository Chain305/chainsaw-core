package codesmell

import (
	"bytes"
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
var binaryBuildArtifacts = map[string]struct{}{
	"binding.gyp": {},
	"makefile":    {},
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
	for name := range files {
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
		if kind := detectBinaryByMagic(files[name]); kind != "" {
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
//	        \xca\xfe\xba\xbe                    (universal/fat)
//	PE:     "MZ" at offset 0
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
		bytes.HasPrefix(head, []byte{0xcf, 0xfa, 0xed, 0xfe}),
		bytes.HasPrefix(head, []byte{0xca, 0xfe, 0xba, 0xbe}):
		return "Mach-O"
	case bytes.HasPrefix(head, []byte{'M', 'Z'}):
		return "PE"
	}
	return ""
}
