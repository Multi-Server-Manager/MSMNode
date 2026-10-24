//go:build !linux

package node

// isNodeProcess cannot inspect another process without /proc. The node ships
// for Linux; elsewhere a restart trusts the pid file it wrote itself.
func isNodeProcess(int) bool { return true }
