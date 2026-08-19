// Package secureio centralises writes of files that should be readable only
// by the current user. Unix honours 0600/0700 modes directly; Windows replaces
// the file's DACL with a protected, owner-only one (see secureio_windows.go).
package secureio

// WriteFile writes data to path with permissions intended to restrict access
// to the current user. On Unix the file ends up at 0600 under a 0700 parent.
// Windows semantics live in secureio_windows.go.
func WriteFile(path string, data []byte) error {
	return writeFile(path, data)
}

// RestrictToCurrentUser tightens an EXISTING file so only the current user can
// read it, using whatever the platform's real mechanism is.
//
// On Windows it replaces the file's DACL with a protected ACL granting full
// control to the current user's SID only, so the file cannot be read through
// permissions inherited from a permissive parent directory. On Unix it is a
// deliberate no-op: POSIX mode bits are the mechanism there, and every caller
// in this repo already sets 0600 through its own write path.
//
// L-09: exported because callers outside this package need it. hook's
// tightenExistingFile returned immediately on Windows while three rendered
// config bodies claimed the file was kept at "mode 0600" — a claim with
// nothing behind it on that platform. Callers get a build-tag-free entry point
// so the hook package never has to grow a _windows.go of its own.
//
// Errors are returned, not fatal: a failure to tighten is worth a warning, but
// refusing to write a working config over it would be worse.
func RestrictToCurrentUser(path string) error {
	return restrictToCurrentUser(path)
}
