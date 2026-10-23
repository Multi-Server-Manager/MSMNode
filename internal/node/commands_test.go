package node

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"path/filepath"
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
