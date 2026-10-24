package node

import (
	"errors"
	"fmt"
	"strconv"
	"syscall"
	"time"
)

// restartGrace is how long the old node gets to shut down on its own before it
// is killed.
const restartGrace = 10 * time.Second

// stopExisting stops the node that owns dir, so a new process can bind its
// ports and take its lock. It reports whether it stopped anything.
//
// Only a process whose command line names msm-node is signalled: a stale or
// recycled pid must never let a restart kill an unrelated program.
func stopExisting(dir string, grace time.Duration) (bool, error) {
	pid := readPidFile(dir)
	if pid == "" {
		return false, nil
	}
	number, err := strconv.Atoi(pid)
	if err != nil || number <= 0 {
		return false, nil
	}
	if !isNodeProcess(number) {
		return false, nil
	}

	if err := syscall.Kill(number, syscall.SIGTERM); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return false, nil
		}
		return false, fmt.Errorf("cannot stop pid %d: %w", number, err)
	}
	if waitForExit(number, grace) {
		return true, nil
	}

	// A node that ignores SIGTERM (or is stuck in a syscall) still has to go,
	// or the new process cannot take the lock and the ports.
	if err := syscall.Kill(number, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return false, fmt.Errorf("pid %d did not stop and cannot be killed: %w", number, err)
	}
	if waitForExit(number, 2*time.Second) {
		return true, nil
	}
	return false, fmt.Errorf("pid %d is still running after SIGKILL", number)
}

// waitForExit reports whether pid is gone before the limit. A zombie is gone
// for the caller's purposes: it holds no sockets and no lock.
func waitForExit(pid int, limit time.Duration) bool {
	deadline := time.Now().Add(limit)
	for {
		if err := syscall.Kill(pid, 0); err != nil {
			if errors.Is(err, syscall.ESRCH) {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}
