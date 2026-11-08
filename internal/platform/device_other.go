//go:build !unix

package platform

import "io/fs"

// NoBlock is the open flag that keeps opening a FIFO from waiting: none
// on this system.
const NoBlock = 0

// NoFollow is the open flag that fails on a symlink: none on this system.
const NoFollow = 0

// SameDevice reports whether two files are on the same file system: on
// this system, always yes.
func SameDevice(fs.FileInfo, fs.FileInfo) bool { return true }

// allocated is the disk space a file takes: on this system, its length.
func allocated(fi fs.FileInfo) int64 { return fi.Size() }

// Owner returns a file's uid and gid: none on this system.
func Owner(fs.FileInfo) (uid, gid uint32, ok bool) { return 0, 0, false }

// DevIno returns a file's device and inode: none on this system.
func DevIno(fs.FileInfo) string { return "" }
