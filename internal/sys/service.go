package sys

import "os"

// HasSystemd reports whether systemd is the running init system.
//
// The check is the runtime directory systemd creates, not whether the binary
// happens to be installed: a container image can ship systemctl and still have
// no init system to talk to.
func HasSystemd() bool {
	info, err := os.Stat("/run/systemd/system")
	return err == nil && info.IsDir()
}

// RestartArgv is the argv that restarts one service unit.
func RestartArgv(unit string) []string {
	return []string{"systemctl", "restart", unit}
}

// RebootArgv is the argv that reboots the machine.
func RebootArgv() []string {
	return []string{"systemctl", "reboot"}
}
