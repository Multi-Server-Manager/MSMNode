//go:build linux

package node

import (
	"syscall"
	"unsafe"
)

// isTTY reports whether fd is a terminal. It is a real ioctl, not a device
// check: /dev/null is a character device too, and a detached node's stdin is
// exactly that.
func isTTY(fd uintptr) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall6(
		syscall.SYS_IOCTL, fd, syscall.TCGETS,
		uintptr(unsafe.Pointer(&termios)), 0, 0, 0,
	)
	return errno == 0
}
