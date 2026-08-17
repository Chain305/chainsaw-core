//go:build windows

package cli

import "golang.org/x/sys/windows"

// nativeConsoleSupportsUnicode reports whether the Windows console output
// codepage can encode the Unicode status glyphs.
//
// Only 65001 (CP_UTF8) qualifies. The legacy defaults — 437 (US OEM), 850,
// 1252, and the CJK OEM pages — cannot represent ✓ U+2713, ✗ U+2717,
// ↻ U+21BB, ⚠ U+26A0, or ℹ U+2139, and render each as the SAME replacement
// box, which is worse than an ASCII marker because it destroys the distinction
// between states rather than merely uglifying it.
//
// This is a separate question from ANSI escapes. ansi_windows.go turns on
// ENABLE_VIRTUAL_TERMINAL_PROCESSING, which governs how the console
// INTERPRETS escape sequences; the output codepage governs how it DECODES
// bytes into glyphs. A console can have VT processing on and still be on
// CP437, which is precisely the broken configuration this guards.
//
// We deliberately do NOT call SetConsoleOutputCP(65001) to "fix" the console.
// That is process-global, outlives chainsaw in some host shells, and has
// historically broken unrelated programs' output in the same window. Adapting
// what we print is the reversible choice; mutating the user's console is not.
// On error we return TRUE (keep Unicode). GetConsoleOutputCP only fails when
// the process has no console attached at all — a service, or a child process
// whose output is a pipe — and in that case the bytes are going to a file or
// a log collector where UTF-8 is the right assumption and no codepage is
// involved. Erring to ASCII there would degrade output for every non-console
// Windows caller in order to protect a console that does not exist.
func nativeConsoleSupportsUnicode() bool {
	cp, err := windows.GetConsoleOutputCP()
	if err != nil {
		return true
	}
	return cp == cpUTF8
}

// cpUTF8 is CP_UTF8 from the Windows SDK — the only console output codepage
// that can encode the full Unicode glyph set.
const cpUTF8 = 65001
