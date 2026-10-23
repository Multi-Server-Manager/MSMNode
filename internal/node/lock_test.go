package node

import (
	"strings"
	"testing"
)

// Test_instance_lock_refuses_a_second_node proves two nodes cannot share one
// state directory, and that the lock is usable again once released.
func Test_instance_lock_refuses_a_second_node(t *testing.T) {
	dir := t.TempDir()

	first, err := acquireInstanceLock(dir)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}

	_, err = acquireInstanceLock(dir)
	if err == nil {
		t.Fatal("a second lock was granted")
	}
	if !strings.Contains(err.Error(), "already running") {
		t.Fatalf("second lock error = %q", err)
	}
	if !strings.Contains(err.Error(), "kill ") {
		t.Fatalf("second lock error names no way to stop it: %q", err)
	}

	first.release()
	first.release() // releasing twice must not panic or remove a live pid file

	second, err := acquireInstanceLock(dir)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	second.release()
}

// Test_background_child_is_forced_foreground proves the detach child cannot
// detach again, and that an explicit flag is not duplicated.
func Test_background_child_is_forced_foreground(t *testing.T) {
	args := foregroundArgs([]string{"msm-node", "--state-dir", "/tmp/x"})
	if args[len(args)-1] != "--foreground" {
		t.Fatalf("args = %v", args)
	}

	already := []string{"msm-node", "--foreground", "--detach"}
	got := foregroundArgs(already)
	if len(got) != len(already) {
		t.Fatalf("duplicated --foreground: %v", got)
	}
}
