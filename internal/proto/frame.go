package proto

import (
	"encoding/binary"
	"io"
)

// ErrFrameTooLarge is returned when a peer announces a payload over MaxFrameLen.
var ErrFrameTooLarge = Errorf(CodeBadFrame, "frame exceeds %d bytes", MaxFrameLen)

// ErrFrameEmpty is returned when a peer announces a zero-length payload.
var ErrFrameEmpty = Errorf(CodeBadFrame, "zero-length frame")

// WriteFrame writes one length-prefixed payload (PROTOCOL.md §2).
func WriteFrame(w io.Writer, payload []byte) error {
	if len(payload) == 0 {
		return ErrFrameEmpty
	}
	if len(payload) > MaxFrameLen {
		return ErrFrameTooLarge
	}
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(payload)))
	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads one length-prefixed payload.
//
// The length is validated before any buffer is allocated, so a peer cannot make
// this process reserve more than MaxFrameLen bytes for a single frame.
func ReadFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 {
		return nil, ErrFrameEmpty
	}
	if length > MaxFrameLen {
		return nil, ErrFrameTooLarge
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// WriteMessage encodes and frames a message.
func WriteMessage(w io.Writer, msg Message) error {
	payload, err := marshal(msg)
	if err != nil {
		return err
	}
	return WriteFrame(w, payload)
}

// ReadMessage reads one frame and decodes it.
func ReadMessage(r io.Reader) (Message, error) {
	payload, err := ReadFrame(r)
	if err != nil {
		return nil, err
	}
	return Decode(payload)
}
