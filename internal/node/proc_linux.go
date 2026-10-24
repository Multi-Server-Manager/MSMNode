//go:build linux

package node

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// isNodeProcess reports whether pid's command line names msm-node. An
// unreadable command line is treated as "not a node", so a restart never
// signals a process it cannot identify.
func isNodeProcess(pid int) bool {
	raw, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	if err != nil || len(raw) == 0 {
		return false
	}
	argv0 := string(raw)
	if end := strings.IndexByte(argv0, 0); end >= 0 {
		argv0 = argv0[:end]
	}
	name := filepath.Base(argv0)
	return name == "msm-node" || strings.HasPrefix(name, "msm-node-")
}
