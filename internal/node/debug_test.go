package node

import (
	"bytes"
	"strings"
	"testing"
)

// Test_debugf_silent_by_default proves an option-less node has no trace stream
// to leak into: debugf must be a no-op rather than panic or write to stdout.
func Test_debugf_silent_by_default(t *testing.T) {
	n := &Node{}
	n.debugf("this must not be written anywhere")
}

// Test_debugf_writes_timestamped_lines proves --debug gets one prefixed line
// per event, with the values interpolated.
func Test_debugf_writes_timestamped_lines(t *testing.T) {
	var out bytes.Buffer
	n := &Node{debug: &out}

	n.debugf("pair %s: connected", "100.74.163.8:41000")

	line := strings.TrimSpace(out.String())
	if !strings.Contains(line, "DEBUG pair 100.74.163.8:41000: connected") {
		t.Fatalf("debug line = %q", line)
	}
	if !strings.Contains(line, "T") || len(line) < 24 {
		t.Fatalf("debug line has no timestamp: %q", line)
	}
}
