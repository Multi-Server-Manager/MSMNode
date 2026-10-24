package node

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// waitForNode waits until pid's command line is readable, so the test does not
// race the child's exec.
func waitForNode(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !isNodeProcess(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("pid %d never looked like msm-node", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// writePid records pid in dir the way a running node does.
func writePid(t *testing.T, dir string, pid int) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "msm-node.pid"), []byte(strconv.Itoa(pid)+"\n"), 0o600); err != nil {
		t.Fatalf("write pid file: %v", err)
	}
}

// Test_stop_existing_stops_a_node proves --restart can replace the instance
// serving a state directory.
func Test_stop_existing_stops_a_node(t *testing.T) {
	dir := t.TempDir()

	cmd := exec.Command("/bin/sleep", "60")
	cmd.Args[0] = "msm-node"
	if err := cmd.Start(); err != nil {
		t.Fatalf("start stand-in node: %v", err)
	}
	reaped := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(reaped)
	}()
	// The child is forked before it is exec'd; its command line appears a
	// moment later.
	waitForNode(t, cmd.Process.Pid)
	writePid(t, dir, cmd.Process.Pid)

	stopped, err := stopExisting(dir, 5*time.Second)
	if err != nil {
		t.Fatalf("stopExisting: %v", err)
	}
	if !stopped {
		t.Fatal("stopExisting reported nothing to stop")
	}
	select {
	case <-reaped:
	case <-time.After(5 * time.Second):
		t.Fatal("the stand-in node was not reaped")
	}
}

// Test_stop_existing_ignores_a_stale_pid proves a pid file alone never makes
// the agent signal anything.
func Test_stop_existing_ignores_a_stale_pid(t *testing.T) {
	dir := t.TempDir()
	writePid(t, dir, 999999)

	stopped, err := stopExisting(dir, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("stopExisting: %v", err)
	}
	if stopped {
		t.Fatal("a nonexistent pid was reported as stopped")
	}
}

// Test_stop_existing_leaves_other_processes_alone proves the command-line
// check: a recycled pid belonging to something else is not killed.
func Test_stop_existing_leaves_other_processes_alone(t *testing.T) {
	dir := t.TempDir()

	cmd := exec.Command("/bin/sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start bystander: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	writePid(t, dir, cmd.Process.Pid)

	stopped, err := stopExisting(dir, time.Second)
	if err != nil {
		t.Fatalf("stopExisting: %v", err)
	}
	if stopped {
		t.Fatal("a process that is not msm-node was stopped")
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("the bystander was signalled: %v", err)
	}
}

// Test_check_accepts_a_fresh_state_dir proves the preflight an upgrade runs
// succeeds where a real start would, without a terminal.
func Test_check_accepts_a_fresh_state_dir(t *testing.T) {
	dir := t.TempDir()
	if err := Check(Options{StateDir: dir}); err != nil {
		t.Fatalf("Check: %v", err)
	}
}

// Test_check_refuses_an_unreadable_config proves the preflight is a real gate:
// a binary that would fail to start is not allowed to replace a working one.
func Test_check_refuses_an_unreadable_config(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"version":9}`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if err := Check(Options{StateDir: dir}); err == nil {
		t.Fatal("Check accepted an unreadable config")
	}
}
