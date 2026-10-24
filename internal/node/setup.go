package node

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/user"
	"strconv"
	"strings"

	"github.com/MSM/MSMNode/internal/state"
	"github.com/MSM/MSMNode/internal/sys"
)

// SetupFlags are the answers an operator can give on the command line, so an
// unattended install never has to invent them.
type SetupFlags struct {
	RunAs   string
	SSHUser string
	SSHPort int
	Skip    bool
}

// needsSetup reports whether the questions still need an answer.
//
// Only a node that has never answered them and has never been paired. A node
// already in service has answers by definition — its console sent them when it
// paired, or the install defaults did — so a restart, an upgrade and the re-exec
// onto a new binary never bring the questions back.
func (n *Node) needsSetup() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return !n.cfg.Setup.Configured && len(n.cfg.Clients) == 0
}

// configureSetup asks the first-run questions on the node's own terminal.
//
// The node is the only side that can know which account it may command as, so
// the question is asked here, once, before the pairing code is printed. A node
// started by systemd, from a pipe or with --no-setup keeps the defaults and
// never blocks on a prompt nobody is watching.
func (n *Node) configureSetup(in io.Reader, out io.Writer, flags SetupFlags, ask bool) error {
	setup := n.cfg.Setup

	// Explicit flags win and count as answered: nothing is asked on top.
	if flags.RunAs != "" || flags.SSHUser != "" || flags.SSHPort != 0 {
		if flags.RunAs != "" {
			if !accountExists(flags.RunAs) {
				return fmt.Errorf("--run-as: no account named %q on this host", flags.RunAs)
			}
			setup.RunAs = flags.RunAs
			if flags.SSHUser == "" {
				setup.SSHUser = flags.RunAs
			}
		}
		if flags.SSHUser != "" {
			if !accountExists(flags.SSHUser) {
				return fmt.Errorf("--ssh-user: no account named %q on this host", flags.SSHUser)
			}
			setup.SSHUser = flags.SSHUser
		}
		if flags.SSHPort != 0 {
			if flags.SSHPort < 1 || flags.SSHPort > 65535 {
				return fmt.Errorf("--ssh-port: %d is not a port", flags.SSHPort)
			}
			setup.SSHPort = flags.SSHPort
		}
		setup.Configured = true
		_, err := n.applySetup(setup, out)
		return err
	}

	if !n.needsSetup() {
		// Already answered, or already serving a console: an upgrade must not
		// ask an operator to answer for a node that is in service.
		return n.keepAnswers(setup, out, "already-configured")
	}

	if flags.Skip || !ask {
		// Nothing was asked, so the defaults stand until someone asks. This is
		// the path a service, a detached child and an upgrade's --check take; it
		// must never read stdin, because there is nobody to answer.
		reason := "no-terminal"
		if flags.Skip {
			reason = "no-setup"
		}
		return n.keepAnswers(setup, out, reason)
	}

	reader := bufio.NewReader(in)
	fmt.Fprintf(out, "SETUP first run: three questions, then the pairing code.\n")

	runAs, err := askAccount(reader, out, "commands run as", setup.RunAs)
	if err != nil {
		return err
	}
	setup.RunAs = runAs

	sshUser, err := askAccount(reader, out, "SSH logins land in", setup.SSHUser)
	if err != nil {
		return err
	}
	setup.SSHUser = sshUser

	port, err := askPort(reader, out, "SSH port", setup.SSHPort)
	if err != nil {
		return err
	}
	setup.SSHPort = port
	setup.Configured = true

	_, err = n.applySetup(setup, out)
	return err
}

// keepAnswers records the answers that will stand instead of asking for them.
//
// The reason says why nothing was asked (`no-terminal`, `no-setup`, or
// `already-configured`), so the log explains a silent first start on a service,
// and an upgrade that never re-asks.
func (n *Node) keepAnswers(setup state.Setup, out io.Writer, reason string) error {
	if setup.Configured {
		return nil
	}
	fmt.Fprintf(out, "SETUP unanswered=1 reason=%s defaults=run_as:%s,ssh_user:%s,ssh_port:%d\n",
		reason, setup.RunAs, setup.SSHUser, setup.SSHPort)
	setup.Configured = true
	_, err := n.applySetup(setup, out)
	return err
}

// applySetup records the answers, rebuilds the command runner and says what
// they mean, including the one case that will not work: an agent that cannot
// escalate to the account it was told to use.
func (n *Node) applySetup(setup state.Setup, out io.Writer) (string, error) {
	runner, err := sys.RunnerFor(setup.RunAs)
	if err != nil {
		return "", err
	}

	n.mu.Lock()
	previousSetup, previousRunner := n.setup, n.runner
	previousCfg := n.cfg.Setup
	n.setup = setup
	n.runner = runner
	n.cfg.Setup = setup
	err = state.Save(n.opts.StateDir, n.cfg)
	if err != nil {
		n.setup, n.runner, n.cfg.Setup = previousSetup, previousRunner, previousCfg
	}
	n.mu.Unlock()
	if err != nil {
		return "", err
	}

	fmt.Fprintf(out, "SETUP run_as=%s sudo=%v ssh_user=%s ssh_port=%d\n",
		setup.RunAs, runner.NeedsSwitch(), setup.SSHUser, setup.SSHPort)

	if runner.NeedsSwitch() {
		ctx := n.ctx
		if ctx == nil {
			ctx = context.Background()
		}
		if _, err := runner.Run(ctx, []string{"true"}); err != nil {
			// Worth reporting, not worth refusing to start: an operator can fix
			// the sudoers rule while the node is already reachable, and the
			// console shows the same sentence instead of letting commands fail
			// one by one with no explanation.
			warning := strings.ReplaceAll(err.Error(), "\n", " ")
			fmt.Fprintf(out, "SETUP warn=%s\n", warning)
			return warning, nil
		}
	}
	return "", nil
}

// askAccount reads one account name, re-asking while it does not exist.
func askAccount(reader *bufio.Reader, out io.Writer, question, def string) (string, error) {
	for range 3 {
		fmt.Fprintf(out, "  %s [%s]: ", question, def)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return "", err
		}
		answer := strings.TrimSpace(line)
		if answer == "" {
			return def, nil
		}
		if accountExists(answer) {
			return answer, nil
		}
		fmt.Fprintf(out, "  no account named %q; try again, or Enter for %s\n", answer, def)
	}
	return def, nil
}

// askPort reads one TCP port.
func askPort(reader *bufio.Reader, out io.Writer, question string, def int) (int, error) {
	for range 3 {
		fmt.Fprintf(out, "  %s [%d]: ", question, def)
		line, err := reader.ReadString('\n')
		if err != nil && line == "" {
			return 0, err
		}
		answer := strings.TrimSpace(line)
		if answer == "" {
			return def, nil
		}
		port, convErr := strconv.Atoi(answer)
		if convErr == nil && port >= 1 && port <= 65535 {
			return port, nil
		}
		fmt.Fprintf(out, "  %q is not a port between 1 and 65535\n", answer)
	}
	return def, nil
}

// commandRunner is the account package and service commands run as. A test
// node without configuration runs commands as the current account.
func (n *Node) commandRunner() *sys.Runner {
	if n.runner != nil {
		return n.runner
	}
	n.runner = sys.Direct()
	return n.runner
}

// currentSetup is a copy of the answers, safe against a concurrent change.
func (n *Node) currentSetup() state.Setup {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.setup
}

// notRoot explains a command that needs root while commands run as someone
// else, naming the one place that fixes it.
func (n *Node) notRoot(runner *sys.Runner, action string) string {
	return fmt.Sprintf("%s needs root, but commands run as %s; change it in msm with e (run as), or start msm-node as root",
		action, runner.Name())
}

func accountExists(name string) bool {
	if name == "" {
		return false
	}
	_, err := user.Lookup(name)
	return err == nil
}

// isTerminal reports whether a reader is a real keyboard, so a service never
// waits for an answer.
//
// A device check is not enough: /dev/null is a character device, and that is
// exactly what a detached node's stdin is. Asking there returned EOF, which
// took the node offline on its first background start after an upgrade.
func isTerminal(in io.Reader) bool {
	file, ok := in.(*os.File)
	if !ok {
		return false
	}
	return isTTY(file.Fd())
}
