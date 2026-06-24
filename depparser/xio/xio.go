// Package xio mirrors github.com/aquasecurity/trivy/pkg/x/io.
//
// Vendored parsers take their input as a ReadSeekerAt because some formats
// (e.g. jar, wheel) need to seek inside a zip archive. Chainsaw parsers
// that only read once can wrap an os.File or a bytes.Reader.
package xio

import "io"

// ReadSeekerAt is the union of io.Reader, io.Seeker, and io.ReaderAt.
// *os.File and *bytes.Reader both satisfy it.
type ReadSeekerAt interface {
	io.Reader
	io.Seeker
	io.ReaderAt
}
