// Package sys is the operating-system side of a command: package managers,
// init systems and kernel counters.
//
// Nothing here ever invokes a shell. Every process starts from an argv slice
// whose elements were validated by the caller.
package sys

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"sync"

	"github.com/MSM/MSMNode/internal/proto"
)

// Manager is a detected package manager plus the argv it wants.
type Manager struct {
	Name string
}

// DetectManager returns the package manager present on this host.
//
// The order is deliberate: a host that somehow has several picks the one whose
// database is authoritative for it in practice.
func DetectManager() (Manager, bool) {
	for _, candidate := range []string{"dnf", "apt-get", "pacman", "apk"} {
		if _, err := exec.LookPath(candidate); err == nil {
			return Manager{Name: managerName(candidate)}, true
		}
	}
	return Manager{}, false
}

func managerName(binary string) string {
	switch binary {
	case "apt-get":
		return "apt"
	default:
		return binary
	}
}

// UpdateArgv is the sequence that upgrades every installed package.
func (m Manager) UpdateArgv() [][]string {
	switch m.Name {
	case "dnf":
		return [][]string{{"dnf", "-y", "upgrade"}}
	case "apt":
		return [][]string{{"apt-get", "update"}, {"apt-get", "-y", "upgrade"}}
	case "pacman":
		return [][]string{{"pacman", "-Syu", "--noconfirm"}}
	case "apk":
		return [][]string{{"apk", "-U", "upgrade"}}
	default:
		return nil
	}
}

// InstallArgv is the sequence that installs one already-validated package name.
func (m Manager) InstallArgv(name string) []string {
	switch m.Name {
	case "dnf":
		return []string{"dnf", "-y", "install", name}
	case "apt":
		return []string{"apt-get", "-y", "install", name}
	case "pacman":
		return []string{"pacman", "-S", "--noconfirm", name}
	case "apk":
		return []string{"apk", "add", "--no-cache", name}
	default:
		return nil
	}
}

// ExecResult is the outcome of one process.
type ExecResult struct {
	ExitCode int
	Output   string
}

// Run executes one argv, capturing a bounded tail of its combined output.
//
// The error return is non-nil only when the process could not be started; a
// non-zero exit is reported through ExitCode.
func Run(ctx context.Context, argv []string) (ExecResult, error) {
	if len(argv) == 0 {
		return ExecResult{}, errors.New("empty argv")
	}

	command := exec.CommandContext(ctx, argv[0], argv[1:]...)
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
		return result, nil
	}
	return result, runErr
}

// boundedBuffer keeps only the newest bytes, so a chatty command cannot make the
// agent hold unbounded output.
type boundedBuffer struct {
	mu      sync.Mutex
	data    []byte
	limit   int
	dropped int
}

func (b *boundedBuffer) Write(chunk []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.data = append(b.data, chunk...)
	if len(b.data) > b.limit {
		excess := len(b.data) - b.limit
		b.data = b.data[excess:]
		b.dropped += excess
	}
	return len(chunk), nil
}

func (b *boundedBuffer) String() string { return TrimOutput(string(b.data)) }

// TrimOutput keeps the last MaxOutputLines lines and at most MaxOutputBytes.
func TrimOutput(text string) string {
	text = strings.ToValidUTF8(text, "")
	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) > proto.MaxOutputLines {
		lines = lines[len(lines)-proto.MaxOutputLines:]
	}
	out := strings.Join(lines, "\n")
	if len(out) > proto.MaxOutputBytes {
		out = out[len(out)-proto.MaxOutputBytes:]
		out = strings.ToValidUTF8(out, "")
	}
	return out
}
