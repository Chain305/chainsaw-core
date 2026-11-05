//go:build windows

package cli

import "errors"

// rootOwnedNotWritable: Homebrew does not run on Windows.
func rootOwnedNotWritable(string) error { return errors.New("not supported on Windows") }
