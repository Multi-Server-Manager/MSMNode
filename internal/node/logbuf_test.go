package node

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

// Test_log_ring proves the ring keeps only the newest lines.
func Test_log_ring(t *testing.T) {
	ring := newLogRing(3)
	for i := 0; i < 5; i++ {
		ring.add(fmt.Sprintf("line-%d", i))
	}

	lines, dropped := ring.tail(10)
	if dropped != 2 {
		t.Fatalf("dropped = %d, want 2", dropped)
	}
	want := []string{"line-2", "line-3", "line-4"}
	if strings.Join(lines, ",") != strings.Join(want, ",") {
		t.Fatalf("tail = %v, want %v", lines, want)
	}
}

// Test_log_ring_bounds proves n is clamped to what is stored.
func Test_log_ring_bounds(t *testing.T) {
	ring := newLogRing(10)
	ring.add("only")

	lines, dropped := ring.tail(500)
	if len(lines) != 1 || dropped != 0 {
		t.Fatalf("tail = %v, dropped = %d", lines, dropped)
	}
}

// Test_log_ring_truncates proves a single enormous line cannot grow the ring.
func Test_log_ring_truncates(t *testing.T) {
	ring := newLogRing(4)
	ring.add(strings.Repeat("x", 5000))

	lines, _ := ring.tail(1)
	if len(lines[0]) != 512 {
		t.Fatalf("line length = %d, want 512", len(lines[0]))
	}
}

// Test_log_ring_partial_writes proves a write is recorded line by line, so a
// partial write never produces half-lines in logs.tail.
func Test_log_ring_partial_writes(t *testing.T) {
	var out bytes.Buffer
	ring := newLogRing(10)
	writer := newLogWriter(&out, ring)

	_, _ = writer.Write([]byte("one\ntw"))
	_, _ = writer.Write([]byte("o\nthree\n"))

	lines, _ := ring.tail(10)
	if strings.Join(lines, ",") != "one,two,three" {
		t.Fatalf("ring = %v", lines)
	}
	if out.String() != "one\ntwo\nthree\n" {
		t.Fatalf("terminal output = %q", out.String())
	}
}
