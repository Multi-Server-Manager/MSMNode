package sshkey

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MSM/MSMNode/internal/sys"
)

// PrivateKeyName is the file holding the node's own SSH key.
const PrivateKeyName = "id_ed25519"

// Identity is the node's SSH keypair, in the forms the agent needs.
type Identity struct {
	// Private is the raw Ed25519 key.
	Private ed25519.PrivateKey
	// PublicLine is one authorized_keys line for the public half.
	PublicLine string
}

// LoadOrCreateIdentity reads the node's SSH key, generating one on first use.
//
// The key is what makes the node able to log in to a console that has trusted
// it: both sides now hold an MSM-managed pair, not a shared password.
func LoadOrCreateIdentity(dir string) (*Identity, error) {
	path := filepath.Join(dir, PrivateKeyName)
	raw, err := os.ReadFile(path)
	if err == nil {
		key, parseErr := parseOpenSSH(string(raw))
		if parseErr != nil {
			return nil, fmt.Errorf("%s: %w", path, parseErr)
		}
		return newIdentity(key)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("cannot read %s: %w", path, err)
	}

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("cannot generate an SSH key: %w", err)
	}
	identity, err := newIdentity(key)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("cannot create %s: %w", dir, err)
	}
	if err := os.WriteFile(path, []byte(marshalOpenSSH(key, "msm-node")), 0o600); err != nil {
		return nil, fmt.Errorf("cannot write %s: %w", path, err)
	}

	public := path + ".pub"
	if err := os.WriteFile(public, []byte(identity.PublicLine+"\n"), 0o600); err != nil {
		return nil, fmt.Errorf("cannot write %s: %w", public, err)
	}
	return identity, nil
}

func newIdentity(key ed25519.PrivateKey) (*Identity, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("the SSH key is %d bytes, want %d", len(key), ed25519.PrivateKeySize)
	}
	public := key.Public().(ed25519.PublicKey)
	return &Identity{Private: key, PublicLine: PublicLine(public)}, nil
}

// PublicLine renders one authorized_keys line for a raw Ed25519 public key.
func PublicLine(public ed25519.PublicKey) string {
	return KeyType + " " + base64.StdEncoding.EncodeToString(blobFor(public)) + " msm-node"
}

func pushU32(out *bytes.Buffer, value uint32) {
	out.Write([]byte{byte(value >> 24), byte(value >> 16), byte(value >> 8), byte(value)})
}

func pushString(out *bytes.Buffer, value []byte) {
	pushU32(out, uint32(len(value)))
	out.Write(value)
}

func blobFor(public ed25519.PublicKey) []byte {
	blob := make([]byte, 0, blobLen)
	blob = append(blob, 0, 0, 0, 11)
	blob = append(blob, KeyType...)
	blob = append(blob, 0, 0, 0, 32)
	return append(blob, public...)
}

// AuthorizeFor installs line in an account's authorized_keys.
//
// The account is the one the console will log in as, which is not necessarily
// the account the agent runs as: a node started by a normal user and configured
// to command as root still has to write /root/.ssh/authorized_keys, through
// exactly the privilege path the commands use.
func AuthorizeFor(account, line string) (path string, added bool, err error) {
	if !Valid(line) {
		return "", false, ErrInvalid
	}

	runner, err := sys.RunnerFor(account)
	if err != nil {
		return "", false, err
	}
	if runner.Home() == "" {
		return "", false, fmt.Errorf("account %q has no home directory to hold an authorized_keys file", runner.Name())
	}

	dir := filepath.Join(runner.Home(), ".ssh")
	path = filepath.Join(dir, "authorized_keys")

	if !runner.NeedsSwitch() {
		return authorizeLocal(dir, path, line)
	}
	return authorizeRemote(runner, dir, path, line)
}

// authorizeLocal is the unprivileged path: read, dedupe, append in place.
func authorizeLocal(dir, path, line string) (string, bool, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return path, false, fmt.Errorf("cannot create %s: %w", dir, err)
	}

	existing, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return path, false, fmt.Errorf("cannot read %s: %w", path, err)
	}

	if containsKey(string(existing), line) {
		_ = os.Chmod(path, 0o600)
		return path, false, nil
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
	if err := os.Chmod(path, 0o600); err != nil {
		return path, false, fmt.Errorf("cannot chmod %s: %w", path, err)
	}
	return path, true, nil
}

// authorizeRemote is the privileged path: every file operation runs as the
// target account, so the agent never needs to chown another user's home.
func authorizeRemote(runner *sys.Runner, dir, path, line string) (string, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	if result, err := runner.Run(ctx, []string{"install", "-d", "-m", "0700", dir}); err != nil {
		return path, false, err
	} else if result.ExitCode != 0 {
		return path, false, fmt.Errorf("cannot create %s: %s", dir, sys.TailLine(result.Output))
	}

	existing, err := runner.Run(ctx, []string{"cat", path})
	if err != nil {
		return path, false, err
	}
	if existing.ExitCode != 0 && !missingFile(existing.Output) {
		return path, false, fmt.Errorf("cannot read %s: %s", path, sys.TailLine(existing.Output))
	}
	if containsKey(existing.Output, line) {
		_, _ = runner.Run(ctx, []string{"chmod", "0600", path})
		return path, false, nil
	}

	var content bytes.Buffer
	content.WriteString(strings.TrimRight(existing.Output, "\n"))
	if content.Len() > 0 {
		content.WriteByte('\n')
	}
	content.WriteString(line)
	content.WriteByte('\n')

	written, err := runner.RunInput(ctx, []string{"tee", path}, content.String())
	if err != nil {
		return path, false, err
	}
	if written.ExitCode != 0 {
		return path, false, fmt.Errorf("cannot write %s: %s", path, sys.TailLine(written.Output))
	}
	chmod, err := runner.Run(ctx, []string{"chmod", "0600", path})
	if err != nil {
		return path, false, err
	}
	if chmod.ExitCode != 0 {
		return path, false, fmt.Errorf("cannot chmod %s: %s", path, sys.TailLine(chmod.Output))
	}
	return path, true, nil
}

// missingFile reports the cat failure that means "no authorized_keys yet".
func missingFile(output string) bool {
	lower := strings.ToLower(output)
	return strings.Contains(lower, "no such file")
}

// parseOpenSSH reads back the unencrypted openssh-key-v1 file this package
// writes. It is not a general key parser: anything else is reported, never
// guessed at.
func parseOpenSSH(text string) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("not a PEM file")
	}
	if block.Type != "OPENSSH PRIVATE KEY" {
		return nil, fmt.Errorf("PEM type %q, want OPENSSH PRIVATE KEY", block.Type)
	}

	blob := block.Bytes
	magic := []byte("openssh-key-v1\x00")
	if !bytes.HasPrefix(blob, magic) {
		return nil, errors.New("not an openssh-key-v1 file")
	}
	cursor := len(magic)
	for range 3 {
		_, next, err := readString(blob, cursor)
		if err != nil {
			return nil, err
		}
		cursor = next
	}
	if count, next, err := readU32(blob, cursor); err != nil {
		return nil, err
	} else if count != 1 {
		return nil, errors.New("the file holds more than one key")
	} else {
		cursor = next
	}
	if _, next, err := readString(blob, cursor); err != nil {
		return nil, err
	} else {
		cursor = next
	}

	private, _, err := readString(blob, cursor)
	if err != nil {
		return nil, err
	}
	privateCursor := 8 // two check words
	if kind, next, err := readString(private, privateCursor); err != nil {
		return nil, err
	} else if string(kind) != KeyType {
		return nil, fmt.Errorf("key type %q, want %s", kind, KeyType)
	} else {
		privateCursor = next
	}
	if public, next, err := readString(private, privateCursor); err != nil {
		return nil, err
	} else if len(public) != ed25519.PublicKeySize {
		return nil, errors.New("the public half has the wrong length")
	} else {
		privateCursor = next
	}
	secret, _, err := readString(private, privateCursor)
	if err != nil {
		return nil, err
	}
	if len(secret) != ed25519.PrivateKeySize {
		return nil, errors.New("the private half has the wrong length")
	}
	return ed25519.PrivateKey(secret), nil
}

func readU32(data []byte, at int) (uint32, int, error) {
	if at+4 > len(data) {
		return 0, 0, errors.New("the key file is truncated")
	}
	value := uint32(data[at])<<24 | uint32(data[at+1])<<16 | uint32(data[at+2])<<8 | uint32(data[at+3])
	return value, at + 4, nil
}

func readString(data []byte, at int) ([]byte, int, error) {
	length, start, err := readU32(data, at)
	if err != nil {
		return nil, 0, err
	}
	end := start + int(length)
	if end > len(data) || end < start {
		return nil, 0, errors.New("the key file is truncated")
	}
	return data[start:end], end, nil
}

// marshalOpenSSH builds the unencrypted openssh-key-v1 container that
// `ssh-keygen` writes for a key without a passphrase.
func marshalOpenSSH(key ed25519.PrivateKey, comment string) string {
	public := key.Public().(ed25519.PublicKey)
	blob := blobFor(public)

	var private bytes.Buffer
	pushU32(&private, 0x5eed5eed)
	pushU32(&private, 0x5eed5eed)
	pushString(&private, []byte(KeyType))
	pushString(&private, public)
	pushString(&private, key)
	pushString(&private, []byte(comment))
	for pad := byte(1); private.Len()%8 != 0; pad++ {
		private.WriteByte(pad)
	}

	var out bytes.Buffer
	out.WriteString("openssh-key-v1\x00")
	pushString(&out, []byte("none"))
	pushString(&out, []byte("none"))
	pushString(&out, nil)
	pushU32(&out, 1)
	pushString(&out, blob)
	pushString(&out, private.Bytes())

	return string(pem.EncodeToMemory(&pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: out.Bytes()}))
}
