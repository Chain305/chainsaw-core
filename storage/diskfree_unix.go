//go:build unix

package storage

import "golang.org/x/sys/unix"

// diskFreeFraction is the share of dir's filesystem available to an
// unprivileged writer; known is false when it cannot be read.
func diskFreeFraction(dir string) (free float64, known bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil || st.Blocks == 0 {
		return 0, false
	}
	return float64(st.Bavail) / float64(st.Blocks), true
}
