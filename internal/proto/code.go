package proto

import (
	"errors"
	"io"
	"strings"
	"unicode"
)

// Alphabet is Crockford Base32: no I, L, O or U (PROTOCOL.md §4).
const Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// CodeLen is the number of characters in a pairing code.
const CodeLen = 8

// ErrCodeFormat reports input that is not a usable pairing code.
var ErrCodeFormat = errors.New("pairing code must be 8 characters from the Crockford base32 alphabet")

// GenerateCode reads 5 random bytes (40 bits) and renders them as 8 characters,
// most significant bits first.
func GenerateCode(r io.Reader) (string, error) {
	var raw [5]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return "", err
	}
	value := uint64(0)
	for _, b := range raw {
		value = value<<8 | uint64(b)
	}
	out := make([]byte, CodeLen)
	for i := CodeLen - 1; i >= 0; i-- {
		out[i] = Alphabet[value&0x1f]
		value >>= 5
	}
	return string(out), nil
}

// NormalizeCode accepts what a human types and returns the canonical code.
//
// Separators are dropped, letters are uppercased, and the Crockford
// confusables I/L and O are folded to 1 and 0.
func NormalizeCode(input string) (string, error) {
	var b strings.Builder
	b.Grow(CodeLen)
	for _, r := range input {
		switch r {
		case '-', ' ', '\t', '\r', '\n':
			continue
		}
		r = unicode.ToUpper(r)
		switch r {
		case 'I', 'L':
			r = '1'
		case 'O':
			r = '0'
		}
		if !strings.ContainsRune(Alphabet, r) {
			return "", ErrCodeFormat
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) != CodeLen {
		return "", ErrCodeFormat
	}
	return out, nil
}
