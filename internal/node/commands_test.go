package node

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/MSM/MSMNode/internal/proto"
)

// exchange runs one handler against a connected console and returns its result.
func exchange(t *testing.T, n *Node, handle func(conn net.Conn)) *proto.Result {
	t.Helper()

	nodeConn, consoleConn := net.Pipe()
	defer consoleConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer nodeConn.Close()
		handle(nodeConn)
	}()

	message, err := proto.ReadMessage(consoleConn)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	result, ok := message.(*proto.Result)
	if !ok {
		t.Fatalf("decoded %T, want *proto.Result", message)
	}

	// The handler releases its lock as it returns; wait for that before the
	// next request, or the test races its own mutex.
	<-done
	return result
}

func newTestNode() *Node {
	ring := newLogRing(10)
	ring.add("first")
	ring.add("second")
	return &Node{out: io.Discard, logs: ring}
}

// Test_logs_tail_bounds proves n outside 1…500 is refused before any read and
// that a bounded request returns the newest lines (PROTOCOL.md §8.10).
func Test_logs_tail_bounds(t *testing.T) {
	for _, lines := range []int{0, -1, proto.MaxLogLines + 1} {
		node := newTestNode()
		node.cmdMu.Lock()
		result := exchange(t, node, func(conn net.Conn) { node.handleLogs(conn, "req-1", lines) })

		if result.OK {
			t.Fatalf("logs.tail %d was accepted", lines)
		}
		if result.Code != proto.CodeBadArgument {
			t.Fatalf("logs.tail %d code = %s, want %s", lines, result.Code, proto.CodeBadArgument)
		}
		if result.Data != nil {
			t.Fatalf("refusal %d carried a payload: %v", lines, result.Data)
		}
	}

	node := newTestNode()
	node.cmdMu.Lock()
	result := exchange(t, node, func(conn net.Conn) { node.handleLogs(conn, "req-1", 1) })
	if !result.OK {
		t.Fatalf("logs.tail 1 refused: %s %s", result.Code, result.Detail)
	}

	encoded, err := json.Marshal(result.Data)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	if string(encoded) != `{"dropped":0,"lines":["second"]}` {
		t.Fatalf("payload = %s", encoded)
	}
}

// Test_dispatch_busy proves a second command is refused, not queued.
func Test_dispatch_busy(t *testing.T) {
	node := newTestNode()
	node.cmdMu.Lock()
	defer node.cmdMu.Unlock()

	result := exchange(t, node, func(conn net.Conn) {
		node.dispatch(conn, &proto.MetricsSample{T: proto.TypeMetricsSample, V: proto.Version, ID: "req-2"})
	})
	if result.OK || result.Code != proto.CodeBusy {
		t.Fatalf("dispatch while busy = ok:%v code:%s", result.OK, result.Code)
	}
}

// Test_ssh_authorize proves the node installs one validated key and refuses
// anything that is not a plain ssh-ed25519 line (PROTOCOL.md §8.11).
func Test_ssh_authorize(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	node := newTestNode()
	send := func(key string) *proto.Result {
		return exchange(t, node, func(conn net.Conn) {
			node.dispatch(conn, &proto.SSHAuthorize{
				T: proto.TypeSSHAuthorize, V: proto.Version, ID: "req-1", Key: key,
			})
		})
	}

	for _, bad := range []string{
		"",
		"ssh-rsa AAAA msm-console",
		`command="/bin/sh" ssh-ed25519 AAAA msm-console`,
		"ssh-ed25519 not-base64 msm-console",
	} {
		result := send(bad)
		if result.OK || result.Code != proto.CodeBadArgument {
			t.Fatalf("key %q: ok=%v code=%s, want bad_argument", bad, result.OK, result.Code)
		}
	}

	blob := append([]byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"), bytes.Repeat([]byte{7}, 32)...)
	line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " msm-console"

	result := send(line)
	if !result.OK {
		t.Fatalf("a valid key was refused: %s %s", result.Code, result.Detail)
	}
	payload, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("payload is %T, want an object", result.Data)
	}
	wantPath := filepath.Join(home, ".ssh", "authorized_keys")
	if payload["path"] != wantPath || payload["added"] != true {
		t.Fatalf("payload = %+v, want path %s and added true", payload, wantPath)
	}

	// Pairing twice must not duplicate the line.
	again := send(line)
	if !again.OK {
		t.Fatalf("second install was refused: %s %s", again.Code, again.Detail)
	}
	if second, _ := again.Data.(map[string]any); second["added"] != false {
		t.Fatalf("second install reported %v, want added false", second["added"])
	}
}

// Test_dispatch_bad_request_id proves an unusable id is refused rather than
// echoed into a result that could not address anything.
func Test_dispatch_bad_request_id(t *testing.T) {
	node := newTestNode()
	result := exchange(t, node, func(conn net.Conn) {
		node.dispatch(conn, &proto.PkgInstall{T: proto.TypePkgInstall, V: proto.Version, ID: "two words", Name: "aero"})
	})
	if result.OK || result.Code != proto.CodeBadArgument {
		t.Fatalf("dispatch with bad id = ok:%v code:%s", result.OK, result.Code)
	}
}

// fakeManager puts a script named after a package manager first on PATH, so the
// node's real dispatch path can be exercised without touching this host's
// packages. It returns the manager name dnf/apt/pacman/apk.
func fakeManager(t *testing.T, name, output string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" + output + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// decodePackage reads a package payload the way a console does: through JSON,
// so the test covers the wire shape and not just the Go struct.
func decodePackage(t *testing.T, data any) proto.PackageResult {
	t.Helper()
	encoded, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	var payload proto.PackageResult
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatalf("parse payload: %v", err)
	}
	return payload
}

// Test_pkg_update_says_what_happened proves the sentence the console reads comes
// from the manager's own report, not from the exit code (PROTOCOL.md §8.5).
func Test_pkg_update_says_what_happened(t *testing.T) {
	fakeManager(t, "dnf", "echo 'Transaction Summary:'\necho ' Upgrading:         3 packages'")

	node := newTestNode()
	node.cmdMu.Lock()
	result := exchange(t, node, func(conn net.Conn) { node.handlePkgUpdate(conn, "req-1") })

	if !result.OK {
		t.Fatalf("pkg.update failed: %s %s", result.Code, result.Detail)
	}
	payload := decodePackage(t, result.Data)
	if payload.Summary != "3 packages were updated" {
		t.Fatalf("summary = %q, want %q", payload.Summary, "3 packages were updated")
	}
}

// Test_pkg_install_reports_an_already_installed_package covers the other half:
// a manager that reports nothing to do is not a silent success.
func Test_pkg_install_reports_an_already_installed_package(t *testing.T) {
	fakeManager(t, "dnf", "echo 'Package \"cowsay-3.8.4-5.fc44.noarch\" is already installed.'\necho\necho 'Nothing to do.'")

	node := newTestNode()
	node.cmdMu.Lock()
	result := exchange(t, node, func(conn net.Conn) { node.handlePkgInstall(conn, "req-1", "cowsay") })

	if !result.OK {
		t.Fatalf("pkg.install failed: %s %s", result.Code, result.Detail)
	}
	payload := decodePackage(t, result.Data)
	if payload.Summary != "cowsay was already installed" {
		t.Fatalf("summary = %q, want %q", payload.Summary, "cowsay was already installed")
	}
}

// Test_pkg_update_failure_keeps_the_reason and never invents a summary: a
// half-written transaction report must not be read as work that happened.
func Test_pkg_update_failure_keeps_the_reason(t *testing.T) {
	dir := t.TempDir()
	script := "#!/bin/sh\necho 'Error: Failed to download metadata for repo' >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "dnf"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake dnf: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))

	node := newTestNode()
	node.cmdMu.Lock()
	result := exchange(t, node, func(conn net.Conn) { node.handlePkgUpdate(conn, "req-1") })

	if result.OK {
		t.Fatal("pkg.update with a failing manager was reported as ok")
	}
	if result.Code != proto.CodeFailed {
		t.Fatalf("code = %s, want %s", result.Code, proto.CodeFailed)
	}
	if !strings.Contains(result.Detail, "Failed to download metadata") {
		t.Fatalf("detail = %q, want the manager's own reason", result.Detail)
	}
	if payload := decodePackage(t, result.Data); payload.Summary != "" {
		t.Fatalf("summary = %q, want none on a failure", payload.Summary)
	}
}
