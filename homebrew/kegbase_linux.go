package homebrew

import (
	"io/fs"
	"strconv"
	"syscall"
)

// statKey changes whenever the file's bytes can have: a new inode (a swap),
// a new size, or a new ctime (any write or metadata change; the user cannot
// set it).
func statKey(fi fs.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return "?"
	}
	ct := st.Ctim
	return strconv.FormatUint(uint64(st.Ino), 10) + ":" + strconv.FormatInt(fi.Size(), 10) + ":" +
		strconv.FormatInt(ct.Sec, 10) + "." + strconv.FormatInt(ct.Nsec, 10)
}

// allocatedBytes is the space the file really occupies on disk.
func allocatedBytes(fi fs.FileInfo) (int64, bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return int64(st.Blocks) * 512, true
}
