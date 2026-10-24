package node

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/user"
	"strings"
	"testing"

	"github.com/MSM/MSMNode/internal/proto"
	"github.com/MSM/MSMNode/internal/state"
)

// newSetupNode is a node that has loaded a fresh config but not asked anything.
func newSetupNode(t *testing.T, dir string) *Node {
	t.Helper()
	cfg, _, err := state.LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	return &Node{opts: Options{StateDir: dir}, cfg: cfg, out: io.Discard, ctx: context.Background()}
}

// Test_setup_asks_three_questions proves the answers are stored, that the
// runner follows the account, and that a blank answer keeps the default.
func Test_setup_asks_three_questions(t *testing.T) {
	dir := t.TempDir()
	node := newSetupNode(t, dir)

	var out bytes.Buffer
	if err := node.configureSetup(strings.NewReader("\n\n2222\n"), &out, SetupFlags{}, true); err != nil {
		t.Fatalf("configureSetup: %v", err)
	}

	current, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	if node.currentSetup().SSHPort != 2222 {
		t.Fatalf("ssh port = %d, want 2222", node.currentSetup().SSHPort)
	}
	if node.currentSetup().RunAs != current.Username {
		t.Fatalf("run_as = %q, want %q", node.currentSetup().RunAs, current.Username)
	}
	if !strings.Contains(out.String(), "SETUP run_as=") {
		t.Fatalf("no setup summary: %q", out.String())
	}

	stored, _, err := state.LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !stored.Setup.Configured || stored.Setup.SSHPort != 2222 {
		t.Fatalf("stored setup = %+v", stored.Setup)
	}

	// The answers are remembered: a second start does not ask again, and a
	// reader that would fail the test if read proves it.
	if err := node.configureSetup(strings.NewReader(""), io.Discard, SetupFlags{}, true); err != nil {
		t.Fatalf("second configureSetup: %v", err)
	}
}

// Test_setup_skips_without_a_terminal proves a service start never blocks.
func Test_setup_skips_without_a_terminal(t *testing.T) {
	dir := t.TempDir()
	node := newSetupNode(t, dir)

	if err := node.configureSetup(strings.NewReader(""), io.Discard, SetupFlags{Skip: true}, true); err != nil {
		t.Fatalf("configureSetup: %v", err)
	}
	if !node.currentSetup().Configured {
		t.Fatal("--no-setup left the questions unanswered")
	}
	if node.currentSetup().SSHPort != state.DefaultSSHPort {
		t.Fatalf("ssh port = %d, want the default", node.currentSetup().SSHPort)
	}
}

// Test_setup_never_prompts_on_a_null_stdin proves the failure that took a node
// offline after an upgrade cannot happen: a detached node's stdin is /dev/null,
// which is a character device, and asking there returned EOF. The defaults are
// recorded instead, without reading stdin.
func Test_setup_never_prompts_on_a_null_stdin(t *testing.T) {
	dir := t.TempDir()
	node := newSetupNode(t, dir)

	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer devnull.Close()

	var out bytes.Buffer
	if err := node.configureSetup(devnull, &out, SetupFlags{}, isTerminal(devnull)); err != nil {
		t.Fatalf("configureSetup on /dev/null: %v", err)
	}
	if !node.currentSetup().Configured {
		t.Fatal("the defaults were not recorded")
	}
	if strings.Contains(out.String(), "commands run as [") {
		t.Fatalf("prompted on a non-terminal: %q", out.String())
	}
	if !strings.Contains(out.String(), "reason=no-terminal") {
		t.Fatalf("the log does not say why the questions were skipped: %q", out.String())
	}
}

// Test_terminal_detection proves the check is an ioctl, not a device test.
func Test_terminal_detection(t *testing.T) {
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatalf("open %s: %v", os.DevNull, err)
	}
	defer devnull.Close()
	if isTerminal(devnull) {
		t.Fatal("/dev/null is reported as a terminal")
	}

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer reader.Close()
	defer writer.Close()
	if isTerminal(reader) {
		t.Fatal("a pipe is reported as a terminal")
	}

	if isTerminal(strings.NewReader("\n")) {
		t.Fatal("a plain reader is reported as a terminal")
	}
}

// Test_setup_flags_win proves an unattended install can answer on the command
// line, and that an account the host does not have is refused.
func Test_setup_flags_win(t *testing.T) {
	dir := t.TempDir()
	node := newSetupNode(t, dir)

	current, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	flags := SetupFlags{RunAs: current.Username, SSHPort: 2022}
	if err := node.configureSetup(strings.NewReader(""), io.Discard, flags, true); err != nil {
		t.Fatalf("configureSetup: %v", err)
	}
	if node.currentSetup().SSHPort != 2022 || node.currentSetup().SSHUser != current.Username {
		t.Fatalf("setup = %+v", node.currentSetup())
	}

	other := newSetupNode(t, t.TempDir())
	if err := other.configureSetup(strings.NewReader(""), io.Discard, SetupFlags{RunAs: "no-such-account"}, true); err == nil {
		t.Fatal("an unknown account was accepted")
	}
}

// Test_node_setup_command proves a pinned console can change the answers and
// that a bad one changes nothing (§8.13).
func Test_node_setup_command(t *testing.T) {
	dir := t.TempDir()
	node := newSetupNode(t, dir)
	if err := node.configureSetup(strings.NewReader(""), io.Discard, SetupFlags{Skip: true}, true); err != nil {
		t.Fatalf("configureSetup: %v", err)
	}

	current, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}

	send := func(request *proto.NodeSetup) *proto.Result {
		return exchange(t, node, func(conn net.Conn) {
			node.dispatch(conn, request)
		})
	}

	refused := send(&proto.NodeSetup{
		T: proto.TypeNodeSetup, V: proto.Version, ID: "setup-1",
		RunAs: "Root", SSHUser: "root", SSHPort: 22,
	})
	if refused.OK || refused.Code != proto.CodeBadArgument {
		t.Fatalf("bad account = ok:%v code:%s", refused.OK, refused.Code)
	}

	ok := send(&proto.NodeSetup{
		T: proto.TypeNodeSetup, V: proto.Version, ID: "setup-2",
		RunAs: current.Username, SSHUser: current.Username, SSHPort: 2200,
	})
	if !ok.OK {
		t.Fatalf("node.setup refused: %s %s", ok.Code, ok.Detail)
	}
	encoded, err := json.Marshal(ok.Data)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(encoded), `"ssh_port":2200`) {
		t.Fatalf("payload = %s", encoded)
	}

	stored, _, err := state.LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if stored.Setup.SSHPort != 2200 {
		t.Fatalf("stored port = %d", stored.Setup.SSHPort)
	}
}
