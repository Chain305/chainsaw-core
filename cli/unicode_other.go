//go:build !windows

package cli

// nativeConsoleSupportsUnicode reports Unicode capability on non-Windows
// platforms, where it is unconditionally true: macOS and Linux terminals are
// UTF-8 by default and have no per-console codepage to interrogate. The
// codepage failure this guards is Windows-only (see unicode_windows.go).
//
// Users on an exotic non-UTF-8 locale still have an escape hatch:
// CHAINSAW_NO_UNICODE, checked in unicodeEnabled() ahead of this probe.
func nativeConsoleSupportsUnicode() bool { return true }
