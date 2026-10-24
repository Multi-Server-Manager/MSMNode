package sys

import (
	"context"
	"os/user"
	"strings"
	"testing"
)

// Test_tail_line_prefers_the_reason proves a trailing hint does not replace the
// line that says what went wrong, which is what a refusal shows.
func Test_tail_line_prefers_the_reason(t *testing.T) {
	output := strings.Join([]string{
		"Updating and loading repositories:",
		"Error: Unable to find a match: no-such-package",
		"Use --skip-unavailable to skip unavailable packages",
	}, "\n")

	if got := TailLine(output); !strings.Contains(got, "Unable to find a match") {
		t.Fatalf("TailLine = %q, want the error line", got)
	}

	// No failure word: the last non-empty line is the best available answer.
	if got := TailLine("one\ntwo\n\n"); got != "two" {
		t.Fatalf("TailLine = %q, want two", got)
	}
	if got := TailLine("   \n"); got != "" {
		t.Fatalf("TailLine of blank output = %q", got)
	}
	// A very long line is bounded so it cannot flood a status row.
	if got := TailLine(strings.Repeat("x", 500)); len(got) != 200 {
		t.Fatalf("TailLine length = %d, want 200", len(got))
	}
}

// Test_runner_for_this_account proves a command for the agent's own account
// runs directly, with no helper process and the prompt's own argv.
func Test_runner_for_this_account(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatalf("user.Current: %v", err)
	}
	runner, err := RunnerFor(current.Username)
	if err != nil {
		t.Fatalf("RunnerFor: %v", err)
	}
	if runner.NeedsSwitch() {
		t.Fatalf("runner for %s wants a privilege switch", current.Username)
	}
	argv := []string{"true"}
	if got := runner.Argv(argv); len(got) != 1 || got[0] != "true" {
		t.Fatalf("Argv = %v", got)
	}

	result, err := runner.Run(context.Background(), argv)
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("true = %+v, %v", result, err)
	}

	// A failed command reports its exit code rather than an error.
	failed, err := runner.Run(context.Background(), []string{"false"})
	if err != nil {
		t.Fatalf("false: %v", err)
	}
	if failed.ExitCode != 1 {
		t.Fatalf("false exit = %d", failed.ExitCode)
	}
}

// Test_runner_refuses_an_unknown_account proves a typo is caught before any
// process starts.
func Test_runner_refuses_an_unknown_account(t *testing.T) {
	if _, err := RunnerFor("no-such-account-msm"); err == nil {
		t.Fatal("RunnerFor accepted an account this host does not have")
	}
}
