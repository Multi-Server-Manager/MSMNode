package node

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/MSM/MSMNode/internal/proto"
	"github.com/MSM/MSMNode/internal/sshkey"
	"github.com/MSM/MSMNode/internal/state"
	"github.com/MSM/MSMNode/internal/sys"
)

const (
	// packageTimeout bounds one package operation.
	packageTimeout = 5 * time.Minute
	// serviceTimeout bounds one service or power operation.
	serviceTimeout = 30 * time.Second
	// replyDeadline bounds a reply that needs no work of its own.
	replyDeadline = 10 * time.Second
	// selfUnit is the name that means "this agent" in svc.restart.
	selfUnit = "msm-node"
)

// dispatch routes one authenticated request (PROTOCOL.md §8.3).
//
// A command holds cmdMu for its whole run, so a second console gets `busy`
// instead of two package managers fighting over one database lock.
func (n *Node) dispatch(conn net.Conn, message proto.Message) {
	n.debugf("command %s: dispatching %s", conn.RemoteAddr(), message.Type())
	if _, ok := message.(*proto.Info); ok {
		n.handleInfo(conn)
		return
	}

	id := requestID(message)
	if !proto.ValidRequestID(id) {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeBadArgument,
			"request id must be 1-64 characters from [A-Za-z0-9_-]"))
		return
	}
	if !n.cmdMu.TryLock() {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeBusy, "another command is already running on this node"))
		return
	}

	switch m := message.(type) {
	case *proto.PkgUpdate:
		n.handlePkgUpdate(conn, id)
	case *proto.PkgInstall:
		n.handlePkgInstall(conn, id, m.Name)
	case *proto.SvcRestart:
		n.handleSvcRestart(conn, id, m.Unit)
	case *proto.HostReboot:
		n.handleHostReboot(conn, id, m.Confirm)
	case *proto.MetricsSample:
		n.handleMetrics(conn, id)
	case *proto.LogsTail:
		n.handleLogs(conn, id, m.Lines)
	case *proto.SSHAuthorize:
		n.handleSSHAuthorize(conn, id, m.Key, m.User)
	case *proto.NodeSetup:
		n.handleNodeSetup(conn, id, m)
	default:
		n.cmdMu.Unlock()
		n.sendResult(conn, proto.NewFailure(id, proto.CodeUnknownType,
			fmt.Sprintf("unsupported request %q", message.Type())))
	}
}

// requestID extracts the correlation id a request carries.
func requestID(message proto.Message) string {
	switch m := message.(type) {
	case *proto.PkgUpdate:
		return m.ID
	case *proto.PkgInstall:
		return m.ID
	case *proto.SvcRestart:
		return m.ID
	case *proto.HostReboot:
		return m.ID
	case *proto.MetricsSample:
		return m.ID
	case *proto.LogsTail:
		return m.ID
	case *proto.SSHAuthorize:
		return m.ID
	case *proto.NodeSetup:
		return m.ID
	default:
		return ""
	}
}

// sendResult writes one result envelope, giving the peer time to read it.
func (n *Node) sendResult(conn net.Conn, result *proto.Result) {
	n.extend(conn, replyDeadline)
	n.debugf("command %s: result id=%s ok=%v code=%s", conn.RemoteAddr(), result.ID, result.OK, result.Code)
	_ = proto.WriteMessage(conn, result)
}

// extend resets the connection deadline for the next step.
func (n *Node) extend(conn net.Conn, window time.Duration) {
	_ = conn.SetDeadline(time.Now().Add(window))
}

// logf records one line for the terminal and for logs.tail.
func (n *Node) logf(format string, args ...any) {
	fmt.Fprintf(n.out, format+"\n", args...)
}

func (n *Node) handlePkgUpdate(conn net.Conn, id string) {
	defer n.cmdMu.Unlock()
	n.runPackage(conn, id, "")
}

func (n *Node) handlePkgInstall(conn net.Conn, id, name string) {
	defer n.cmdMu.Unlock()

	if !proto.ValidPackageName(name) {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeBadArgument,
			"package name must be 1-64 characters from [a-zA-Z0-9._:+-], not starting with - + . :"))
		return
	}
	n.runPackage(conn, id, name)
}

// runPackage executes the manager's argv sequence, one process at a time.
func (n *Node) runPackage(conn net.Conn, id, name string) {
	manager, ok := sys.DetectManager()
	if !ok {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeUnsupported,
			"no supported package manager (dnf, apt, pacman, apk) found"))
		return
	}

	commands := manager.UpdateArgv()
	if name != "" {
		commands = [][]string{manager.InstallArgv(name)}
	}

	n.extend(conn, packageTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), packageTimeout)
	defer cancel()

	runner := n.commandRunner()
	var output strings.Builder
	var executed [][]string
	exitCode := 0
	failure := ""

	for _, argv := range commands {
		actual := runner.Argv(argv)
		executed = append(executed, actual)
		n.logf("COMMAND %s", strings.Join(actual, " "))
		result, err := runner.Run(ctx, argv)
		output.WriteString(result.Output)

		if err != nil {
			// The runner already phrased this: no account, no passwordless
			// sudo, or a binary the host does not have.
			failure = err.Error()
			exitCode = -1
			break
		}
		if ctx.Err() != nil {
			failure = "the command did not finish within 5m"
			exitCode = -1
			break
		}
		if result.ExitCode != 0 {
			// The manager's own last line is the reason: a dnf run without
			// root says so in plain words, and "exited with 1" alone leaves
			// an operator guessing.
			failure = fmt.Sprintf("%s exited with %d", argv[0], result.ExitCode)
			if tail := sys.TailLine(result.Output); tail != "" {
				failure += ": " + tail
			}
			exitCode = result.ExitCode
			break
		}
	}

	payload := &proto.PackageResult{
		Manager:  manager.Name,
		Commands: executed,
		ExitCode: exitCode,
		Output:   sys.TrimOutput(output.String()),
	}
	if failure != "" {
		n.logf("COMMAND failed=%s", failure)
		result := proto.NewFailure(id, proto.CodeFailed, failure)
		result.Data = payload
		n.sendResult(conn, result)
		return
	}
	n.sendResult(conn, proto.NewResult(id, payload))
}

func (n *Node) handleSvcRestart(conn net.Conn, id, unit string) {
	defer n.cmdMu.Unlock()

	if unit == "" || unit == selfUnit || unit == "self" {
		n.logf("RESTART unit=%s method=exec", selfUnit)
		n.sendResult(conn, proto.NewResult(id, &proto.ServiceResult{Unit: selfUnit, Method: "exec"}))
		n.restartSelf()
		return
	}
	if !proto.ValidUnit(unit) {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeBadArgument,
			"unit must be 1-64 characters from [a-zA-Z0-9@._:-], not starting with - + . :"))
		return
	}
	if !sys.HasSystemd() {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeUnsupported, "systemd is not running on this host"))
		return
	}
	if runner := n.commandRunner(); !runner.IsRoot() {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeFailed, n.notRoot(runner, "systemctl restart")))
		return
	}

	n.extend(conn, serviceTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), serviceTimeout)
	defer cancel()

	argv := sys.RestartArgv(unit)
	result, err := n.commandRunner().Run(ctx, argv)
	if err != nil {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeFailed, err.Error()))
		return
	}
	if result.ExitCode != 0 {
		detail := fmt.Sprintf("systemctl restart %s exited with %d", unit, result.ExitCode)
		if tail := sys.TailLine(result.Output); tail != "" {
			detail += ": " + tail
		}
		n.sendResult(conn, proto.NewFailure(id, proto.CodeFailed, detail))
		return
	}
	n.logf("RESTART unit=%s method=systemctl", unit)
	n.sendResult(conn, proto.NewResult(id, &proto.ServiceResult{Unit: unit, Method: "systemctl"}))
}

// restartSelf re-executes the agent in place, keeping its pid and state.
func (n *Node) restartSelf() {
	// Let the acknowledgement reach the console before the process image goes.
	time.Sleep(150 * time.Millisecond)

	executable, err := os.Executable()
	if err != nil {
		n.logf("RESTART failed: %v", err)
		os.Exit(1)
	}
	n.logf("RESTART exec=%s pid=%d", executable, os.Getpid())
	if err := syscall.Exec(executable, os.Args, os.Environ()); err != nil {
		n.logf("RESTART failed: %v", err)
		os.Exit(1)
	}
}

func (n *Node) handleHostReboot(conn net.Conn, id, confirm string) {
	defer n.cmdMu.Unlock()

	if confirm != proto.RebootConfirmation {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeConfirmationRequired,
			`host.reboot requires confirm="`+proto.RebootConfirmation+`"`))
		return
	}
	if !sys.HasSystemd() {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeUnsupported, "systemd is not running on this host"))
		return
	}
	if runner := n.commandRunner(); !runner.IsRoot() {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeFailed, n.notRoot(runner, "systemctl reboot")))
		return
	}

	n.logf("REBOOT requested")
	n.sendResult(conn, proto.NewResult(id, &proto.RebootResult{Method: "systemctl"}))

	n.extend(conn, serviceTimeout)
	ctx, cancel := context.WithTimeout(context.Background(), serviceTimeout)
	defer cancel()
	if result, err := n.commandRunner().Run(ctx, sys.RebootArgv()); err != nil || result.ExitCode != 0 {
		n.logf("REBOOT failed")
	}
}

// handleSSHAuthorize installs the console's public key (§8.11).
func (n *Node) handleSSHAuthorize(conn net.Conn, id, key, user string) {
	defer n.cmdMu.Unlock()

	if len(key) > proto.MaxSSHKeyLineLen || !sshkey.Valid(key) {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeBadArgument,
			"key must be one ssh-ed25519 authorized_keys line"))
		return
	}
	if user == "" {
		user = n.currentSetup().SSHUser
	}
	if user == "" {
		// A node that has never run the setup questions still accepts the
		// console key, for the account it runs as.
		user = state.DefaultSetup().SSHUser
	}
	if !proto.ValidAccount(user) {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeBadArgument,
			"user must be an account name of 1-32 characters from [a-z0-9_.-]"))
		return
	}

	path, added, err := sshkey.AuthorizeFor(user, key)
	if err != nil {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeFailed, err.Error()))
		return
	}

	state := "already-present"
	if added {
		state = "added"
	}
	n.logf("SSH authorize user=%s path=%s state=%s", user, path, state)
	n.sendResult(conn, proto.NewResult(id, &proto.SSHAuthorizeResult{Path: path, Added: added, User: user}))
}

// handleNodeSetup changes the answers a later pairing would otherwise ask for
// (§8.13). A console cannot make the node run as an account it cannot find, so
// the runner is rebuilt before anything is stored.
func (n *Node) handleNodeSetup(conn net.Conn, id string, request *proto.NodeSetup) {
	defer n.cmdMu.Unlock()

	if !proto.ValidAccount(request.RunAs) {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeBadArgument,
			"run_as must be an account name of 1-32 characters from [a-z0-9_.-]"))
		return
	}
	if !proto.ValidAccount(request.SSHUser) {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeBadArgument,
			"ssh_user must be an account name of 1-32 characters from [a-z0-9_.-]"))
		return
	}
	if !proto.ValidPort(request.SSHPort) {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeBadArgument, "ssh_port must be 1-65535"))
		return
	}

	setup := state.Setup{Configured: true, RunAs: request.RunAs, SSHUser: request.SSHUser, SSHPort: request.SSHPort}
	warning, err := n.applySetup(setup, io.Discard)
	if err != nil {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeFailed, err.Error()))
		return
	}

	n.logf("SETUP changed run_as=%s ssh_user=%s ssh_port=%d", setup.RunAs, setup.SSHUser, setup.SSHPort)
	n.sendResult(conn, proto.NewResult(id, &proto.SetupResult{
		RunAs: setup.RunAs, SSHUser: setup.SSHUser, SSHPort: setup.SSHPort, Warn: warning,
	}))
}

// handleMetrics answers one usage sample.
func (n *Node) handleMetrics(conn net.Conn, id string) {
	defer n.cmdMu.Unlock()

	metrics, err := sys.Sample()
	if err != nil {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeUnsupported,
			"cannot read the kernel counters: "+err.Error()))
		return
	}
	n.sendResult(conn, proto.NewResult(id, &proto.MetricsResult{
		Load1:          metrics.Load1,
		Load5:          metrics.Load5,
		Load15:         metrics.Load15,
		CPUCount:       metrics.CPUCount,
		MemTotalKB:     metrics.MemTotalKB,
		MemAvailableKB: metrics.MemAvailableKB,
		UptimeS:        metrics.UptimeS,
		DiskTotalKB:    metrics.DiskTotalKB,
		DiskAvailKB:    metrics.DiskAvailKB,
	}))
}

func (n *Node) handleLogs(conn net.Conn, id string, lines int) {
	defer n.cmdMu.Unlock()

	if lines < 1 || lines > proto.MaxLogLines {
		n.sendResult(conn, proto.NewFailure(id, proto.CodeBadArgument,
			fmt.Sprintf("lines must be between 1 and %d", proto.MaxLogLines)))
		return
	}
	tail, dropped := n.logs.tail(lines)
	n.sendResult(conn, proto.NewResult(id, &proto.LogsResult{Lines: tail, Dropped: dropped}))
}
