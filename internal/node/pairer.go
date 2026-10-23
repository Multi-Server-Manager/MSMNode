package node

import (
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/MSM/MSMNode/internal/proto"
)

// pairer owns the lifetime of the one-time pairing code: generation, rotation
// on expiry, attempt accounting and the burn on success.
type pairer struct {
	mu        sync.Mutex
	code      string
	expires   time.Time
	trials    int
	maxTrials int
	ttl       time.Duration
	addresses []string
	out       io.Writer
}

func newPairer(ttl time.Duration, attempts int, addresses []string, out io.Writer) (*pairer, error) {
	if attempts < 1 {
		attempts = 1
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	p := &pairer{maxTrials: attempts, ttl: ttl, addresses: addresses, out: out}
	if err := p.rotateLocked(); err != nil {
		return nil, err
	}
	return p, nil
}

// rotateLocked replaces the code and resets its lifetime and attempts.
func (p *pairer) rotateLocked() error {
	code, err := proto.GenerateCode(rand.Reader)
	if err != nil {
		return fmt.Errorf("generate pairing code: %w", err)
	}
	p.code = code
	p.expires = time.Now().Add(p.ttl)
	p.trials = p.maxTrials
	return nil
}

func (p *pairer) announce(reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.printLocked(reason)
}

func (p *pairer) printLocked(reason string) {
	line := fmt.Sprintf("PAIR code=%s addr=%s", p.code, p.primary())
	if len(p.addresses) > 1 {
		line += " addrs=" + endpointsText(p.addresses)
	}
	line += fmt.Sprintf(" ttl=%s", p.ttl)
	if reason != "" {
		line += " rotated=" + reason
	}
	fmt.Fprintln(p.out, line)
}

// primary is the address an operator should try first: the Tailscale one when
// the host has it, since it is the only address a remote console can reach.
func (p *pairer) primary() string {
	if len(p.addresses) == 0 {
		return "127.0.0.1:0"
	}
	return p.addresses[0]
}

// begin hands out the current code for a new attempt, rotating an expired one.
func (p *pairer) begin() (code string, trials int, ttlLeft time.Duration, err *proto.ProtocolError) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if time.Now().After(p.expires) {
		if rotateErr := p.rotateLocked(); rotateErr != nil {
			return "", 0, 0, proto.Errorf(proto.CodeInternal, "cannot generate a pairing code")
		}
		p.printLocked("expired")
		return "", 0, 0, proto.Errorf(proto.CodeExpired, "the pairing code expired; a new one has been printed")
	}
	return p.code, p.trials, time.Until(p.expires), nil
}

// fail consumes one attempt and reports the code to send back.
func (p *pairer) fail(code string) string {
	p.mu.Lock()
	defer p.mu.Unlock()

	if code != p.code || p.code == "" {
		return proto.CodeExpired
	}
	p.trials--
	if p.trials > 0 {
		return proto.CodeBadProof
	}
	if err := p.rotateLocked(); err != nil {
		return proto.CodeInternal
	}
	p.printLocked("abuse")
	return proto.CodeAbuse
}

// succeed burns the code if it is still the current one.
func (p *pairer) succeed(code string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	if code == "" || code != p.code {
		return false
	}
	if time.Now().After(p.expires) {
		return false
	}
	p.code = ""
	p.expires = time.Time{}
	return true
}
