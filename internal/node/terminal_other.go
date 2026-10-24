//go:build !linux && !darwin

package node

// isTTY is false where this package has no ioctl: the node never asks a
// question it cannot see an answer to.
func isTTY(uintptr) bool { return false }
