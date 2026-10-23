package node

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/MSM/MSMNode/internal/proto"
)

// Test_pairer_expiry proves an elapsed code is refused and replaced.
func Test_pairer_expiry(t *testing.T) {
	var out bytes.Buffer
	pair, err := newPairer(20*time.Millisecond, 3, []string{"127.0.0.1:1"}, &out)
	if err != nil {
		t.Fatalf("newPairer: %v", err)
	}
	first := pair.code

	time.Sleep(40 * time.Millisecond)

	_, _, _, perr := pair.begin()
	if perr == nil || perr.Code != proto.CodeExpired {
		t.Fatalf("begin after expiry = %v, want code %s", perr, proto.CodeExpired)
	}
	if pair.code == first {
		t.Fatal("expired code was reused instead of rotated")
	}
	if !strings.Contains(out.String(), "rotated=expired") {
		t.Fatalf("rotation was not reported: %q", out.String())
	}

	// The rotated code is usable again.
	code, trials, _, perr := pair.begin()
	if perr != nil || code != pair.code || trials != 3 {
		t.Fatalf("begin after rotation = %q, %d, %v", code, trials, perr)
	}
}

// Test_pairer_attempts proves the attempt budget and the rotation on abuse.
func Test_pairer_attempts(t *testing.T) {
	var out bytes.Buffer
	pair, err := newPairer(time.Minute, 3, []string{"127.0.0.1:1"}, &out)
	if err != nil {
		t.Fatalf("newPairer: %v", err)
	}

	code := pair.code
	if got := pair.fail(code); got != proto.CodeBadProof {
		t.Fatalf("first failure = %s, want %s", got, proto.CodeBadProof)
	}
	if got := pair.fail(code); got != proto.CodeBadProof {
		t.Fatalf("second failure = %s, want %s", got, proto.CodeBadProof)
	}
	if got := pair.fail(code); got != proto.CodeAbuse {
		t.Fatalf("third failure = %s, want %s", got, proto.CodeAbuse)
	}
	if pair.code == code {
		t.Fatal("code was not rotated after the attempt budget was exhausted")
	}
	if !strings.Contains(out.String(), "rotated=abuse") {
		t.Fatalf("abuse rotation was not reported: %q", out.String())
	}
	if pair.trials != 3 {
		t.Fatalf("trials = %d after rotation, want 3", pair.trials)
	}

	// A stale failure against the old code must not consume the new budget.
	if got := pair.fail(code); got != proto.CodeExpired {
		t.Fatalf("stale failure = %s, want %s", got, proto.CodeExpired)
	}
	if pair.trials != 3 {
		t.Fatalf("stale failure consumed an attempt: %d left", pair.trials)
	}
}

// Test_pairer_burn proves a successful pairing destroys the code exactly once.
func Test_pairer_burn(t *testing.T) {
	pair, err := newPairer(time.Minute, 3, []string{"127.0.0.1:1"}, io.Discard)
	if err != nil {
		t.Fatalf("newPairer: %v", err)
	}
	code := pair.code

	if !pair.succeed(code) {
		t.Fatal("succeed rejected the current code")
	}
	if pair.succeed(code) {
		t.Fatal("succeed accepted a burned code")
	}
	if got := pair.fail(code); got != proto.CodeExpired {
		t.Fatalf("fail after burn = %s, want %s", got, proto.CodeExpired)
	}
}

// Test_pairer_single_call_site proves the announce line is machine readable.
func Test_pairer_announce(t *testing.T) {
	var out bytes.Buffer
	pair, err := newPairer(time.Minute, 3, []string{"127.0.0.1:4040"}, &out)
	if err != nil {
		t.Fatalf("newPairer: %v", err)
	}
	pair.announce("")

	line := strings.TrimSpace(out.String())
	if !strings.HasPrefix(line, "PAIR code=") {
		t.Fatalf("announce line = %q", line)
	}
	if !strings.Contains(line, "addr=127.0.0.1:4040") {
		t.Fatalf("announce line is missing the address: %q", line)
	}
	if !strings.Contains(line, "ttl=") {
		t.Fatalf("announce line is missing the ttl: %q", line)
	}
}
