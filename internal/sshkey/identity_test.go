package sshkey

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Test_identity_roundtrip proves the node key is generated once, written 0600
// and readable back as the same key, which is what lets it survive an upgrade.
func Test_identity_roundtrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ssh")

	first, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}
	if !Valid(first.PublicLine) {
		t.Fatalf("public line is not acceptable to a console: %q", first.PublicLine)
	}
	if !strings.HasSuffix(first.PublicLine, " msm-node") {
		t.Fatalf("public line = %q", first.PublicLine)
	}

	path := filepath.Join(dir, PrivateKeyName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("key mode = %o, want 600", mode)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if !strings.HasPrefix(string(raw), "-----BEGIN OPENSSH PRIVATE KEY-----") {
		t.Fatalf("key is not in OpenSSH form: %q", string(raw[:40]))
	}

	second, err := LoadOrCreateIdentity(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreateIdentity: %v", err)
	}
	if second.PublicLine != first.PublicLine {
		t.Fatal("the key changed across a reload")
	}
}

// Test_identity_rejects_garbage proves a damaged key is reported, not replaced:
// silently minting a new identity would lock every console out.
func Test_identity_rejects_garbage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, PrivateKeyName), []byte("not a key"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadOrCreateIdentity(dir); err == nil {
		t.Fatal("a damaged key was accepted")
	}
}

// Test_public_line_matches_blob proves the line is one strict authorized_keys
// entry, so the console can install it without a second parser.
func Test_public_line_matches_blob(t *testing.T) {
	identity, err := LoadOrCreateIdentity(t.TempDir())
	if err != nil {
		t.Fatalf("LoadOrCreateIdentity: %v", err)
	}
	fields := strings.Fields(identity.PublicLine)
	if len(fields) != 3 || fields[0] != KeyType {
		t.Fatalf("line = %q", identity.PublicLine)
	}
}
