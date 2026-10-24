// Package sshkey installs a console's public key into the node account's
// authorized_keys (PROTOCOL.md §8.11).
//
// The line is validated before any file is touched: it must be a well-formed
// ssh-ed25519 key, so a console cannot inject options, a second key or a command
// into the file.
package sshkey

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
)

const (
	// KeyType is the only type accepted.
	KeyType = "ssh-ed25519"
	// blobLen is 4 + len("ssh-ed25519") + 4 + 32.
	blobLen = 4 + 11 + 4 + 32
)

// ErrInvalid reports a line that is not an acceptable public key.
var ErrInvalid = errors.New("not an ssh-ed25519 authorized_keys line")

// Valid reports whether line is exactly one acceptable public key.
func Valid(line string) bool {
	fields := strings.Split(line, " ")
	if len(fields) < 2 || len(fields) > 3 {
		return false
	}
	if fields[0] != KeyType {
		return false
	}
	if len(fields) == 3 && !validComment(fields[2]) {
		return false
	}

	blob, err := base64.StdEncoding.Strict().DecodeString(fields[1])
	if err != nil || len(blob) != blobLen {
		return false
	}
	if !bytes.HasPrefix(blob, []byte("\x00\x00\x00\x0b"+KeyType+"\x00\x00\x00\x20")) {
		return false
	}
	return true
}

func validComment(comment string) bool {
	if len(comment) > 64 {
		return false
	}
	for _, r := range comment {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '@', r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// Authorize appends line to the current user's authorized_keys.
//
// The directory is created 0700 and the file 0600. Pairing twice adds the key
// once: the second call reports added=false and leaves the file untouched.
func Authorize(line string) (path string, added bool, err error) {
	return AuthorizeFor("", line)
}

// containsKey reports whether an authorized_keys body already trusts line's
// key, whatever its comment or position in the file.
func containsKey(body, line string) bool {
	want := keyBlob(line)
	if want == "" {
		return false
	}
	for _, candidate := range strings.Split(body, "\n") {
		if keyBlob(candidate) == want {
			return true
		}
	}
	return false
}

// keyBlob returns the base64 key field of a line, or "" when it has none.
func keyBlob(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != KeyType {
		return ""
	}
	return fields[1]
}
