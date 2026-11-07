//go:build unix

package platform

import (
	"io/fs"
	"strconv"
	"syscall"
)

// NoBlock is the open flag that keeps opening a FIFO from waiting for a
// writer: a file a VM could swap in for one devvm reads.
const NoBlock = syscall.O_NONBLOCK

// NoFollow is the open flag that fails on a symlink rather than opening
// what it points to: a file a VM could swap for a link out of its folder.
const NoFollow = syscall.O_NOFOLLOW

// SameDevice reports whether two files are on the same file system.
func SameDevice(a, b fs.FileInfo) bool {
	sa, oka := a.Sys().(*syscall.Stat_t)
	sb, okb := b.Sys().(*syscall.Stat_t)
	return oka && okb && sa.Dev == sb.Dev
}

// allocated is the disk space a file takes: its blocks, not its length,
// so a sparse disk image counts what it holds.
func allocated(fi fs.FileInfo) int64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Blocks * 512
	}
	return fi.Size()
}

// Owner returns a file's uid and gid, false when fi has none.
func Owner(fi fs.FileInfo) (uid, gid uint32, ok bool) {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, false
	}
	return st.Uid, st.Gid, true
}

// DevIno returns a file's device and inode as "dev:ino", "" when fi has
// none: what the file is, whatever its name.
func DevIno(fi fs.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return strconv.FormatUint(uint64(st.Dev), 10) + ":" + strconv.FormatUint(st.Ino, 10) //nolint:gosec,unconvert,nolintlint // Dev's type differs between systems: each needs one of the two
}
