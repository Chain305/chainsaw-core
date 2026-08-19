//go:build windows

package cli

import (
	"os"

	"golang.org/x/sys/windows"
)

// nativeConsoleSupportsUnicode is the Windows adapter for decideUnicode. It
// gathers the environment the ladder reads and gets out of the way; the
// reasoning — and the reason the previous codepage probe was answering the
// wrong question — lives in unicode_decide.go.
func nativeConsoleSupportsUnicode() bool {
	return decideUnicode(consoleEnv{
		goos:            "windows",
		stdoutIsConsole: stdoutIsWindowsConsole(),
		lookup:          os.LookupEnv,
	})
}

// stdoutIsWindowsConsole reports whether STDOUT ITSELF is a console handle.
//
// GetConsoleMode is the right call for this and GetConsoleOutputCP was not:
// GetConsoleMode is asked about a specific handle and fails with
// ERROR_INVALID_HANDLE when that handle is a pipe or a file, whereas
// GetConsoleOutputCP is a process-wide query that succeeds whenever ANY
// console is attached. That difference is the whole of bug 2 — under the old
// probe, `chainsaw doctor --offline > report.txt` run from a legacy window
// wrote the fallback set into the file.
func stdoutIsWindowsConsole() bool {
	var mode uint32
	err := windows.GetConsoleMode(windows.Handle(os.Stdout.Fd()), &mode)
	return err == nil
}
