package node

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
)

// upgradeCheck is how often a running node looks at its own binary. A package
// upgrade replaces that file, and the node re-execs itself onto the new one.
const upgradeCheck = 10 * time.Second

// detach hands the serving node to a background copy of itself and returns, so
// the shell prompt comes back.
//
// The child is the same binary with the same arguments plus `--foreground`, its
// own session (setsid), stdin on /dev/null and stdout/stderr in the state
// directory. Everything that must not be inherited is closed first: the
// operational listener is closed explicitly and the lock is dropped, so the
// child can take both.
func (n *Node) detach(operational net.Listener) error {
	_ = operational.Close()
	n.releaseLock()

	logPath := filepath.Join(n.opts.StateDir, "msm-node.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("cannot open %s: %w", logPath, err)
	}

	executable, err := os.Executable()
	if err != nil {
		_ = logFile.Close()
		return fmt.Errorf("cannot find the node binary: %w", err)
	}

	cmd := exec.Command(executable, foregroundArgs(os.Args)[1:]...)
	cmd.Dir = n.opts.StateDir
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("cannot start the background node: %w", err)
	}
	_ = logFile.Close()

	fmt.Fprintf(n.out, "BACKGROUND pid=%d log=%s\n", cmd.Process.Pid, logPath)
	return nil
}

// foregroundArgs adds `--foreground` unless it is already there, so the
// background child can never try to detach again.
func foregroundArgs(args []string) []string {
	for _, arg := range args[1:] {
		if arg == "--" {
			break
		}
		if arg == "--foreground" || arg == "-foreground" {
			return args
		}
	}
	return append(append([]string{}, args...), "--foreground")
}

// sameBinary reports whether the file on disk is still the one this process
// was started from. A package manager swaps the file by rename, which changes
// the inode; a build tool may rewrite it in place, which only changes the size
// or the timestamp.
func sameBinary(a, b os.FileInfo) bool {
	return os.SameFile(a, b) && a.ModTime().Equal(b.ModTime()) && a.Size() == b.Size()
}

// watchExecutable replaces this process with the binary on disk when a package
// upgrade has swapped it. The node's state, pid and ports survive because the
// exec happens in place; the listeners and the lock are close-on-exec, so the
// new image binds the same ports and takes the same lock.
//
// Debug runs are excluded: `--debug` is a foreground trace, and silently
// restarting it would drop the stream the operator is watching.
func (n *Node) watchExecutable(ctx context.Context) {
	if n.debug != nil {
		return
	}

	path, err := os.Executable()
	if err != nil {
		return
	}
	initial, err := os.Stat(path)
	if err != nil {
		return
	}

	ticker := time.NewTicker(upgradeCheck)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current, err := os.Stat(path)
			if err != nil || sameBinary(initial, current) {
				continue
			}
			n.logf("UPGRADE binary=%s version=%s pid=%d restarting", path, n.opts.Version, os.Getpid())
			if err := syscall.Exec(path, os.Args, os.Environ()); err != nil {
				// Keep serving the old image rather than exit mid-upgrade,
				// and do not retry this same file every ten seconds.
				n.logf("UPGRADE restart failed=%v", err)
				initial = current
			}
			return
		}
	}
}
