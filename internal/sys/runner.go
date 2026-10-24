package sys

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/MSM/MSMNode/internal/proto"
)

// ErrNoPrivilege reports that a command must run as another account but the
// agent cannot become that account.
var ErrNoPrivilege = errors.New("no way to run commands as the configured account")

// currentAccount is resolved once: every command needs the comparison.
var currentAccount = sync.OnceValue(func() string {
	if u, err := user.Current(); err == nil {
		return u.Username
	}
	return ""
})

// Runner starts processes as one account.
//
// A node that already runs as that account starts the process directly. A node
// running as root switches credentials in the child, so no helper binary is
// needed. Anything else goes through `sudo -n`, which never prompts: a node
// that cannot escalate says so instead of leaving a command waiting for a
// password that will never arrive.
type Runner struct {
	// name is the account the commands run as.
	name string
	// uid is the target uid; -1 means "the account the agent runs as".
	uid int
	gid int
	// groups are the supplementary groups of the target account, filled only
	// when this process is root and switches credentials itself.
	groups []uint32
	// switchUser is set when the agent is root and the child must drop to uid.
	switchUser bool
	home       string
	// sudo means every command is prefixed with `sudo -n -u <name> --`.
	sudo bool
	// checked records the one-time probe of passwordless sudo.
	checked   bool
	available bool
	mu        sync.Mutex
}

// Direct is a runner for the account this process already is: no switch, no
// sudo, no lookup that can fail.
func Direct() *Runner {
	return &Runner{name: currentAccount(), uid: os.Geteuid()}
}

// RunnerFor resolves the account commands should run as.
//
// An empty name means "whatever account the agent runs as", which needs no
// privilege at all.
func RunnerFor(name string) (*Runner, error) {
	current, err := user.Current()
	if err != nil {
		return nil, fmt.Errorf("cannot determine the current account: %w", err)
	}
	currentUID, err := strconv.Atoi(current.Uid)
	if err != nil {
		return nil, fmt.Errorf("cannot parse the current uid %q: %w", current.Uid, err)
	}

	if name == "" || name == current.Username {
		// $HOME wins for the agent's own account: that is the directory its
		// shell (and anything it starts) treats as home.
		home := current.HomeDir
		if fromEnv, err := os.UserHomeDir(); err == nil {
			home = fromEnv
		}
		return &Runner{name: current.Username, uid: currentUID, home: home}, nil
	}

	target, err := user.Lookup(name)
	if err != nil {
		return nil, fmt.Errorf("no account named %q on this host", name)
	}
	uid, err := strconv.Atoi(target.Uid)
	if err != nil {
		return nil, fmt.Errorf("account %q has an unusable uid %q", name, target.Uid)
	}
	gid, err := strconv.Atoi(target.Gid)
	if err != nil {
		return nil, fmt.Errorf("account %q has an unusable gid %q", name, target.Gid)
	}

	runner := &Runner{name: name, uid: uid, gid: gid, home: target.HomeDir}
	switch {
	case uid == currentUID:
		// The configured account is this one; no switch is needed.
		runner.uid = currentUID
	case os.Geteuid() == 0:
		runner.switchUser = true
		if ids, err := target.GroupIds(); err == nil {
			for _, id := range ids {
				if value, err := strconv.ParseUint(id, 10, 32); err == nil {
					runner.groups = append(runner.groups, uint32(value))
				}
			}
		}
	default:
		runner.sudo = true
	}
	return runner, nil
}

// Name is the account the runner targets.
func (r *Runner) Name() string { return r.name }

// IsRoot reports whether the target account is root.
func (r *Runner) IsRoot() bool { return r.uid == 0 }

// Home is the target account's home directory, or "" when it is unknown.
func (r *Runner) Home() string { return r.home }

// NeedsSwitch reports whether a command for this account must leave the
// agent's own credentials. A runner that does not need it can read and write
// the account's files in process, without a helper process.
func (r *Runner) NeedsSwitch() bool {
	return r != nil && (r.sudo || r.switchUser)
}

// Argv is the argv that actually runs: the prompt's own, prefixed with sudo
// when the agent has to borrow another account. A caller reports this, never
// the unprefixed form, so `commands` in a result is what really ran.
func (r *Runner) Argv(argv []string) []string {
	if r == nil || !r.sudo {
		return argv
	}
	prefix := []string{"sudo", "-n"}
	if name := r.Name(); name != "" {
		prefix = append(prefix, "-u", name)
	}
	return append(append(prefix, "--"), argv...)
}

// Run executes one argv as the target account.
//
// The error return is non-nil only when the process could not be started or the
// account cannot be reached; a non-zero exit is reported through ExitCode.
func (r *Runner) Run(ctx context.Context, argv []string) (ExecResult, error) {
	return r.RunInput(ctx, argv, "")
}

// RunInput is Run with text fed to the process on stdin.
func (r *Runner) RunInput(ctx context.Context, argv []string, input string) (ExecResult, error) {
	if len(argv) == 0 {
		return ExecResult{}, errors.New("empty argv")
	}
	if r != nil && r.sudo {
		if ok, err := r.canSudo(ctx); !ok {
			return ExecResult{}, err
		}
	}

	executable := r.Argv(argv)
	command := exec.CommandContext(ctx, executable[0], executable[1:]...)
	if r != nil && r.switchUser {
		// Root switching to another account: no sudo, no external helper.
		command.SysProcAttr = &syscall.SysProcAttr{
			Credential: &syscall.Credential{
				Uid:    uint32(r.uid),
				Gid:    uint32(r.gid),
				Groups: r.groups,
			},
		}
	}
	if r != nil && r.home != "" {
		command.Env = append(os.Environ(), "HOME="+r.home, "USER="+r.name, "LOGNAME="+r.name)
	}
	if input != "" {
		command.Stdin = strings.NewReader(input)
	}

	buffer := &boundedBuffer{limit: proto.MaxOutputBytes}
	command.Stdout = buffer
	command.Stderr = buffer

	runErr := command.Run()
	result := ExecResult{Output: buffer.String(), ExitCode: 0}
	if runErr == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		if result.ExitCode == 0 {
			result.ExitCode = 1
		}
		if r != nil && r.sudo && result.ExitCode == 1 && asksForPassword(result.Output) {
			return result, r.noPrivilege()
		}
		return result, nil
	}
	return result, runErr
}

// canSudo probes passwordless sudo once, so a node without it fails with a
// sentence an operator can act on instead of one failed dnf run.
func (r *Runner) canSudo(ctx context.Context) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.checked {
		if r.available {
			return true, nil
		}
		return false, r.noPrivilege()
	}
	r.checked = true

	probe := []string{"sudo", "-n"}
	if r.name != "" {
		probe = append(probe, "-u", r.name)
	}
	probe = append(probe, "--", "true")

	command := exec.CommandContext(ctx, probe[0], probe[1:]...)
	var out boundedBuffer
	out.limit = 4 << 10
	command.Stdout = &out
	command.Stderr = &out
	if err := command.Run(); err != nil {
		r.available = false
		return false, r.noPrivilege()
	}
	r.available = true
	return true, nil
}

// noPrivilege explains the two ways out, in the order an operator should try
// them.
func (r *Runner) noPrivilege() error {
	current := currentAccount()
	if current == "" {
		current = "this account"
	}
	return fmt.Errorf("%w: commands must run as %s, but %s cannot use sudo without a password; "+
		"run msm-node as root, or allow it with a sudoers rule such as "+
		"`%s ALL=(%s) NOPASSWD: ALL`",
		ErrNoPrivilege, r.name, current, current, r.name)
}

// asksForPassword reports a sudo refusal that was really a password prompt.
func asksForPassword(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "password is required") ||
		strings.Contains(lower, "a terminal is required") ||
		strings.Contains(lower, "no tty present")
}

// TailLine is the line of a command's output that explains a failure, trimmed
// and bounded.
//
// Package managers print their error and then a hint about a flag, so the last
// line is often the least useful one. A line that names a failure wins; the
// last non-empty line is the fallback for output that uses none of those words.
func TailLine(output string) string {
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	fallback := ""
	for index := len(lines) - 1; index >= 0; index-- {
		line := strings.TrimSpace(lines[index])
		if line == "" {
			continue
		}
		if fallback == "" {
			fallback = line
		}
		if namesAFailure(line) {
			return clip(line, 200)
		}
	}
	return clip(fallback, 200)
}

// namesAFailure reports whether a line is a reason rather than a hint.
func namesAFailure(line string) bool {
	lower := strings.ToLower(line)
	for _, marker := range []string{"error", "failed", "denied", "cannot", "not found", "requires", "no such"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func clip(line string, limit int) string {
	if len(line) <= limit {
		return line
	}
	return line[:limit]
}
