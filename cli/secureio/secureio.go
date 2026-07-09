// Package secureio centralises writes of files that should be readable only
// by the current user. Unix honours 0600/0700 modes directly; Windows relies
// on %APPDATA% inheritance (see secureio_windows.go).
package secureio

// WriteFile writes data to path with permissions intended to restrict access
// to the current user. On Unix the file ends up at 0600 under a 0700 parent.
// Windows semantics live in secureio_windows.go.
func WriteFile(path string, data []byte) error {
	return writeFile(path, data)
}
