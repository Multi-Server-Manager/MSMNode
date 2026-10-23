package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
)

// errHKDFLength reports an output length outside the RFC 5869 range.
var errHKDFLength = errors.New("hkdf: output length must be between 1 and 255*32 bytes")

// hkdfExtract is HKDF-Extract (RFC 5869 §2.2): HMAC-SHA256(salt, ikm).
func hkdfExtract(salt, ikm []byte) []byte {
	mac := hmac.New(sha256.New, salt)
	mac.Write(ikm)
	return mac.Sum(nil)
}

// hkdfExpand is HKDF-Expand (RFC 5869 §2.3) with SHA-256.
func hkdfExpand(prk, info []byte, length int) ([]byte, error) {
	if length <= 0 || length > 255*sha256.Size {
		return nil, errHKDFLength
	}
	out := make([]byte, 0, length+sha256.Size)
	var block []byte
	for counter := byte(1); len(out) < length; counter++ {
		mac := hmac.New(sha256.New, prk)
		mac.Write(block)
		mac.Write(info)
		mac.Write([]byte{counter})
		block = mac.Sum(nil)
		out = append(out, block...)
	}
	return out[:length], nil
}
