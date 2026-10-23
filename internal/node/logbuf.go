package node

import (
	"bytes"
	"io"
	"strings"
	"sync"

	"github.com/MSM/MSMNode/internal/proto"
)

// logRing keeps the newest log lines for `logs.tail`.
type logRing struct {
	mu      sync.Mutex
	lines   []string
	limit   int
	dropped int
}

func newLogRing(limit int) *logRing {
	if limit < 1 {
		limit = 1
	}
	return &logRing{limit: limit}
}

// add records one line, evicting the oldest once the ring is full.
func (r *logRing) add(line string) {
	line = strings.ToValidUTF8(line, "")
	if len(line) > proto.MaxLogLineBytes {
		line = strings.ToValidUTF8(line[:proto.MaxLogLineBytes], "")
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.lines) == r.limit {
		r.lines = r.lines[1:]
		r.dropped++
	}
	r.lines = append(r.lines, line)
}

// tail returns up to n newest lines and how many were evicted in total.
func (r *logRing) tail(n int) ([]string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if n > len(r.lines) {
		n = len(r.lines)
	}
	lines := make([]string, n)
	copy(lines, r.lines[len(r.lines)-n:])
	return lines, r.dropped
}

// logWriter prints to the terminal and records every complete line, so the
// ring and the operator's terminal never disagree about what the node said.
type logWriter struct {
	mu      sync.Mutex
	out     io.Writer
	ring    *logRing
	partial []byte
}

func newLogWriter(out io.Writer, ring *logRing) *logWriter {
	return &logWriter{out: out, ring: ring}
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	// A failure to print must not stop the node from serving.
	_, _ = w.out.Write(p)

	w.partial = append(w.partial, p...)
	for {
		index := bytes.IndexByte(w.partial, '\n')
		if index < 0 {
			break
		}
		w.ring.add(string(w.partial[:index]))
		w.partial = w.partial[index+1:]
	}
	return len(p), nil
}
