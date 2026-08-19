//go:build !windows

package cli

import (
	"os"
	"runtime"
)

// nativeConsoleSupportsUnicode is the non-Windows adapter for decideUnicode.
//
// The ladder short-circuits at rule 3 here (goos != windows -> true), so
// stdoutIsConsole is never read and there is nothing to probe: macOS and Linux
// terminals are UTF-8 and do runtime font fallback, and there is no
// per-console codepage to interrogate. Routing through decideUnicode anyway
// keeps ONE ladder rather than two divergent ones, and makes the Windows-only
// rules provably inert on this platform (pinned by
// TestDecideUnicode_PlatformMatrix).
//
// Users on an exotic non-UTF-8 locale still have CHAINSAW_NO_UNICODE, which is
// rule 1 and applies on every platform.
func nativeConsoleSupportsUnicode() bool {
	return decideUnicode(consoleEnv{
		goos:   runtime.GOOS,
		lookup: os.LookupEnv,
	})
}
