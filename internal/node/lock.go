package node

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// instanceLock keeps one node per state directory.
//
// The lock is an flock(2), so the kernel releases it when the process dies:
// a crash never leaves a lock that blocks the next start. The pid file next to
// it is only a hint for the operator, never the source of truth.
type instanceLock struct {
	file *os.File
}

// acquireInstanceLock takes the state directory's lock, or explains who holds
// it. The directory must already exist (state.LoadOrCreate makes it).
func acquireInstanceLock(dir string) (*instanceLock, error) {
	path := filepath.Join(dir, "msm-node.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cannot open %s: %w", path, err)
	}

	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			if pid := readPidFile(dir); pid != "" {
				return nil, fmt.Errorf(
					"another msm-node is already running (pid %s); follow its log with: tail -f %s; restart it with: kill %s && msm-node",
					pid, filepath.Join(dir, "msm-node.log"), pid)
			}
			return nil, fmt.Errorf("another msm-node is already running in %s", dir)
		}
		return nil, fmt.Errorf("cannot lock %s: %w", path, err)
	}

	pid := strconv.Itoa(os.Getpid())
	if err := os.WriteFile(filepath.Join(dir, "msm-node.pid"), []byte(pid+"\n"), 0o600); err != nil {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
		return nil, fmt.Errorf("cannot write the pid file: %w", err)
	}
	return &instanceLock{file: file}, nil
}

// release removes the pid file, then drops the lock. Safe to call twice.
func (l *instanceLock) release() {
	if l == nil || l.file == nil {
		return
	}
	_ = os.Remove(filepath.Join(filepath.Dir(l.file.Name()), "msm-node.pid"))
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
	l.file = nil
}

// readPidFile returns the recorded pid, or "" when it is missing or not a
// number.
func readPidFile(dir string) string {
	raw, err := os.ReadFile(filepath.Join(dir, "msm-node.pid"))
	if err != nil {
		return ""
	}
	pid := strings.TrimSpace(string(raw))
	if _, err := strconv.Atoi(pid); err != nil {
		return ""
	}
	return pid
}
