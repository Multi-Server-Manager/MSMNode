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
	"fmt"
	"os"
	"path/filepath"
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
	if !Valid(line) {
		return "", false, ErrInvalid
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", false, fmt.Errorf("cannot locate the home directory: %w", err)
	}
	dir := filepath.Join(home, ".ssh")
	path = filepath.Join(dir, "authorized_keys")

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return path, false, fmt.Errorf("cannot create %s: %w", dir, err)
	}

	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return path, false, fmt.Errorf("cannot read %s: %w", path, err)
	}

	blob := keyBlob(line)
	for _, candidate := range strings.Split(string(existing), "\n") {
		if keyBlob(candidate) == blob {
			// The key is already trusted; still make sure the mode is ours.
			_ = os.Chmod(path, 0o600)
			return path, false, nil
		}
	}

	var content bytes.Buffer
	content.Write(bytes.TrimRight(existing, "\n"))
	if content.Len() > 0 {
		content.WriteByte('\n')
	}
	content.WriteString(line)
	content.WriteByte('\n')

	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return path, false, fmt.Errorf("cannot write %s: %w", path, err)
	}
	if _, err := file.Write(content.Bytes()); err != nil {
		file.Close()
		return path, false, fmt.Errorf("cannot write %s: %w", path, err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return path, false, fmt.Errorf("cannot flush %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return path, false, fmt.Errorf("cannot close %s: %w", path, err)
	}
	// Enforce the mode even when the file already existed with another one.
	if err := os.Chmod(path, 0o600); err != nil {
		return path, false, fmt.Errorf("cannot chmod %s: %w", path, err)
	}
	return path, true, nil
}

// keyBlob returns the base64 key field of a line, or "" when it has none.
func keyBlob(line string) string {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != KeyType {
		return ""
	}
	return fields[1]
}
