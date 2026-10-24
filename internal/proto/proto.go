// Package proto implements the MSM wire protocol, version 1.
//
// The authoritative description of every byte on the wire is
// MSM/docs/PROTOCOL.md. This package must not diverge from that document.
package proto

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

const (
	// Version is the protocol version this build speaks.
	Version = 1
	// MaxFrameLen is the largest payload a single frame may carry.
	MaxFrameLen = 1 << 20
	// separator prefixes every transcript hash.
	separator = "MSM-PAIR-V1"
)

// Message types (PROTOCOL.md §6, §8).
const (
	TypePairHello     = "pair.hello"
	TypePairChallenge = "pair.challenge"
	TypePairProof     = "pair.proof"
	TypePairOK        = "pair.ok"
	TypeInfo          = "info"
	TypeInfoOK        = "info.ok"
	TypeError         = "error"
)

// Error codes (PROTOCOL.md §9).
const (
	CodeBadFrame     = "bad_frame"
	CodeUnknownType  = "unknown_type"
	CodeBadVersion   = "bad_version"
	CodeBadProof     = "bad_proof"
	CodeExpired      = "expired"
	CodeAbuse        = "abuse"
	CodeUnauthorized = "unauthorized"
	CodeInternal     = "internal"
)

// ProtocolError is an error that can be reported to the peer as an `error`
// message. Detail is shown to a human and must never contain secrets.
type ProtocolError struct {
	Code   string
	Detail string
}

func (e *ProtocolError) Error() string { return e.Code + ": " + e.Detail }

// Errorf builds a ProtocolError with a formatted detail string.
func Errorf(code, format string, args ...any) *ProtocolError {
	return &ProtocolError{Code: code, Detail: fmt.Sprintf(format, args...)}
}

// Message is implemented by every concrete wire message.
type Message interface {
	// Type returns the value of the "t" member.
	Type() string
}

// EncodeB64 renders a binary field the way PROTOCOL.md §3 requires.
func EncodeB64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// DecodeB64N decodes a binary field and enforces its exact length.
func DecodeB64N(field string, n int) ([]byte, error) {
	b, err := base64.StdEncoding.Strict().DecodeString(field)
	if err != nil {
		return nil, Errorf(CodeBadFrame, "field is not canonical base64")
	}
	if len(b) != n {
		return nil, Errorf(CodeBadFrame, "field is %d bytes, want %d", len(b), n)
	}
	return b, nil
}

// Decode parses a frame payload into a concrete Message.
//
// The order of checks matches PROTOCOL.md §2: version first, then the presence
// and type of "t", then the message body. Both implementations report the same
// code for the same malformed input.
func Decode(payload []byte) (Message, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(payload, &members); err != nil {
		return nil, Errorf(CodeBadFrame, "payload is not a JSON object")
	}

	rawVersion, ok := members["v"]
	if !ok {
		return nil, Errorf(CodeBadVersion, "missing v")
	}
	var version int
	if err := json.Unmarshal(rawVersion, &version); err != nil {
		return nil, Errorf(CodeBadVersion, "v is not an integer")
	}
	if version != Version {
		return nil, Errorf(CodeBadVersion, "protocol version %d, want %d", version, Version)
	}

	rawType, ok := members["t"]
	if !ok {
		return nil, Errorf(CodeBadFrame, "missing t")
	}
	var kind string
	if err := json.Unmarshal(rawType, &kind); err != nil {
		return nil, Errorf(CodeBadFrame, "t is not a string")
	}

	var msg Message
	switch kind {
	case TypePairHello:
		msg = &PairHello{}
	case TypePairChallenge:
		msg = &PairChallenge{}
	case TypePairProof:
		msg = &PairProof{}
	case TypePairOK:
		msg = &PairOK{}
	case TypeInfo:
		msg = &Info{}
	case TypeInfoOK:
		msg = &InfoOK{}
	case TypeError:
		msg = &Error{}
	case TypePkgUpdate:
		msg = &PkgUpdate{}
	case TypePkgInstall:
		msg = &PkgInstall{}
	case TypeSvcRestart:
		msg = &SvcRestart{}
	case TypeHostReboot:
		msg = &HostReboot{}
	case TypeMetricsSample:
		msg = &MetricsSample{}
	case TypeLogsTail:
		msg = &LogsTail{}
	case TypeSSHAuthorize:
		msg = &SSHAuthorize{}
	case TypeNodeSetup:
		msg = &NodeSetup{}
	case TypeResult:
		msg = &Result{}
	default:
		return nil, Errorf(CodeUnknownType, "unknown message type %q", kind)
	}

	if err := json.Unmarshal(payload, msg); err != nil {
		return nil, Errorf(CodeBadFrame, "malformed %q payload", kind)
	}
	return msg, nil
}
