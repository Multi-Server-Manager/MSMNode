//go:build darwin

package node

import (
	"syscall"
	"unsafe"
)

// isTTY reports whether fd is a terminal. Darwin answers the same question
// with TIOCGETA rather than Linux's TCGETS.
func isTTY(fd uintptr) bool {
	var termios syscall.Termios
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL, fd, syscall.TIOCGETA,
		uintptr(unsafe.Pointer(&termios)),
	)
	return errno == 0
}
