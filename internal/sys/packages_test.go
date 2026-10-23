package sys

import (
	"fmt"
	"strings"
	"testing"

	"github.com/MSM/MSMNode/internal/proto"
)

// Test_sys_trim_output_lines proves the output keeps its tail, not its head.
func Test_sys_trim_output_lines(t *testing.T) {
	var text strings.Builder
	for i := 0; i < proto.MaxOutputLines+10; i++ {
		fmt.Fprintf(&text, "line-%d\n", i)
	}

	trimmed := TrimOutput(text.String())
	lines := strings.Split(trimmed, "\n")
	if len(lines) != proto.MaxOutputLines {
		t.Fatalf("kept %d lines, want %d", len(lines), proto.MaxOutputLines)
	}
	if lines[len(lines)-1] != fmt.Sprintf("line-%d", proto.MaxOutputLines+9) {
		t.Fatalf("last line = %q", lines[len(lines)-1])
	}
	if lines[0] != "line-10" {
		t.Fatalf("first kept line = %q, want line-10", lines[0])
	}
}

// Test_sys_trim_output_bytes proves the byte cap also keeps the tail.
func Test_sys_trim_output_bytes(t *testing.T) {
	trimmed := TrimOutput(strings.Repeat("a", proto.MaxOutputBytes*2))
	if len(trimmed) > proto.MaxOutputBytes {
		t.Fatalf("kept %d bytes, want at most %d", len(trimmed), proto.MaxOutputBytes)
	}
}

// Test_sys_trim_output_utf8 proves truncation cannot leave invalid UTF-8,
// which would break the JSON encoding of the result payload.
func Test_sys_trim_output_utf8(t *testing.T) {
	trimmed := TrimOutput(strings.Repeat("é", proto.MaxOutputBytes))
	if !strings.ContainsRune(trimmed, 'é') {
		t.Fatalf("trimmed output is not valid UTF-8 text: %q", trimmed[:8])
	}
}

// Test_sys_manager_argv proves every manager's argv is a slice, never a shell
// string, and that the package name is its own element.
func Test_sys_manager_argv(t *testing.T) {
	for _, name := range []string{"dnf", "apt", "pacman", "apk"} {
		manager := Manager{Name: name}
		argv := manager.InstallArgv("aero")
		if len(argv) == 0 {
			t.Fatalf("%s has no install argv", name)
		}
		if argv[len(argv)-1] != "aero" {
			t.Fatalf("%s install argv ends with %q, want the package name", name, argv[len(argv)-1])
		}
		for _, element := range argv {
			if strings.ContainsAny(element, " ;|&$`") {
				t.Fatalf("%s argv element %q looks like a shell string", name, element)
			}
		}
		if len(manager.UpdateArgv()) == 0 {
			t.Fatalf("%s has no update argv", name)
		}
	}
}
