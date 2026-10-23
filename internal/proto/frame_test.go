package proto

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// Test_frame_roundtrip covers PROTOCOL.md §10 "frame round-trip".
func Test_frame_roundtrip(t *testing.T) {
	var buffer bytes.Buffer
	want := `{"t":"info","v":1}`
	if err := WriteFrame(&buffer, []byte(want)); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	got, err := ReadFrame(&buffer)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if string(got) != want {
		t.Fatalf("payload = %q, want %q", got, want)
	}

	// A frame of exactly the cap is legal.
	exact := bytes.Repeat([]byte("a"), MaxFrameLen)
	buffer.Reset()
	if err := WriteFrame(&buffer, exact); err != nil {
		t.Fatalf("WriteFrame at cap: %v", err)
	}
	if _, err := ReadFrame(&buffer); err != nil {
		t.Fatalf("ReadFrame at cap: %v", err)
	}
}

// Test_frame_zero_length covers PROTOCOL.md §10 "zero-length frame rejected".
func Test_frame_zero_length(t *testing.T) {
	header := make([]byte, 4)
	if _, err := ReadFrame(bytes.NewReader(header)); !errors.Is(err, ErrFrameEmpty) {
		t.Fatalf("ReadFrame = %v, want ErrFrameEmpty", err)
	}
	if err := WriteFrame(&bytes.Buffer{}, nil); !errors.Is(err, ErrFrameEmpty) {
		t.Fatalf("WriteFrame(nil) = %v, want ErrFrameEmpty", err)
	}
}

// Test_frame_cap covers PROTOCOL.md §10 "frame over 1 MiB rejected".
func Test_frame_cap(t *testing.T) {
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, MaxFrameLen+1)

	// The rejection must happen from the header alone: no payload follows, so a
	// reader that tried to allocate and read would block or fail differently.
	_, err := ReadFrame(bytes.NewReader(header))
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("ReadFrame = %v, want ErrFrameTooLarge", err)
	}

	var perr *ProtocolError
	if !errors.As(err, &perr) || perr.Code != CodeBadFrame {
		t.Fatalf("error code = %v, want %s", perr, CodeBadFrame)
	}
}

// Test_frame_unknown_type covers PROTOCOL.md §10 "unknown type rejected".
func Test_frame_unknown_type(t *testing.T) {
	_, err := Decode([]byte(`{"t":"pair.renegotiate","v":1}`))
	var perr *ProtocolError
	if !errors.As(err, &perr) || perr.Code != CodeUnknownType {
		t.Fatalf("Decode = %v, want code %s", err, CodeUnknownType)
	}
}

// Test_frame_bad_version covers PROTOCOL.md §10 "v != 1 rejected".
func Test_frame_bad_version(t *testing.T) {
	for _, payload := range []string{
		`{"t":"info","v":2}`,
		`{"t":"info","v":0}`,
		`{"t":"info"}`,
	} {
		_, err := Decode([]byte(payload))
		var perr *ProtocolError
		if !errors.As(err, &perr) || perr.Code != CodeBadVersion {
			t.Fatalf("Decode(%s) = %v, want code %s", payload, err, CodeBadVersion)
		}
	}
}

// Test_frame_malformed covers the remaining §2 rules.
func Test_frame_malformed(t *testing.T) {
	cases := map[string]string{
		"array":      `[1,2,3]`,
		"scalar":     `"pair.hello"`,
		"truncated":  `{"t":"info","v":`,
		"empty body": ``,
	}
	for name, payload := range cases {
		_, err := Decode([]byte(payload))
		var perr *ProtocolError
		if !errors.As(err, &perr) || perr.Code != CodeBadFrame {
			t.Fatalf("%s: Decode = %v, want code %s", name, err, CodeBadFrame)
		}
	}

	// Unknown members are ignored, not fatal.
	msg, err := Decode([]byte(`{"t":"info","v":1,"extra":"ignored"}`))
	if err != nil {
		t.Fatalf("Decode with extra member: %v", err)
	}
	if _, ok := msg.(*Info); !ok {
		t.Fatalf("Decode = %T, want *Info", msg)
	}
	if !strings.HasPrefix(msg.Type(), "info") {
		t.Fatalf("Type() = %q", msg.Type())
	}
}

// Test_frame_truncated_body proves a short payload is an error, not a hang.
func Test_frame_truncated_body(t *testing.T) {
	payload := []byte(`{"t":"info","v":1}`)
	var buffer bytes.Buffer
	if err := WriteFrame(&buffer, payload); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}
	truncated := buffer.Bytes()[:buffer.Len()-3]
	if _, err := ReadFrame(bytes.NewReader(truncated)); err == nil {
		t.Fatal("ReadFrame accepted a truncated payload")
	}
}
