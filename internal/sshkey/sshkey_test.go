package sshkey

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// line builds a syntactically valid ssh-ed25519 authorized_keys line.
func line(key byte, comment string) string {
	blob := []byte("\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20")
	blob = append(blob, bytesOf(key)...)
	if comment == "" {
		return KeyType + " " + base64.StdEncoding.EncodeToString(blob)
	}
	return KeyType + " " + base64.StdEncoding.EncodeToString(blob) + " " + comment
}

func bytesOf(key byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = key
	}
	return out
}

// Test_sshkey_valid proves the only accepted shape is one plain ed25519 key.
func Test_sshkey_valid(t *testing.T) {
	accepted := []string{line(1, "msm-console"), line(2, ""), line(3, "a@b-c_d.e")}
	refused := []string{
		"",
		KeyType,
		"ssh-rsa " + strings.Repeat("A", 68) + " msm-console",
		`command="/bin/sh" ` + line(4, "msm-console"),
		line(5, "msm-console") + " " + line(6, "second"),
		line(7, "bad comment!"),
		KeyType + " " + base64.StdEncoding.EncodeToString(bytesOf(8)),
		KeyType + " not-base64 msm-console",
		line(9, strings.Repeat("c", 65)),
	}

	for _, candidate := range accepted {
		if !Valid(candidate) {
			t.Fatalf("Valid refused %q", candidate)
		}
	}
	for _, candidate := range refused {
		if Valid(candidate) {
			t.Fatalf("Valid accepted %q", candidate)
		}
	}
}

// Test_sshkey_install proves the key is written once, with tight modes.
func Test_sshkey_install(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	key := line(10, "msm-console")
	path, added, err := Authorize(key)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if !added {
		t.Fatal("first install reported added=false")
	}
	want := filepath.Join(home, ".ssh", "authorized_keys")
	if path != want {
		t.Fatalf("path = %s, want %s", path, want)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %O, want 600", info.Mode().Perm())
	}
	dir, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if dir.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %O, want 700", dir.Mode().Perm())
	}

	// A second pairing must not duplicate the line.
	_, added, err = Authorize(key)
	if err != nil {
		t.Fatalf("second Authorize: %v", err)
	}
	if added {
		t.Fatal("second install reported added=true")
	}

	// A different key is appended, keeping the first.
	if _, added, err = Authorize(line(11, "second")); err != nil || !added {
		t.Fatalf("second key: added=%v err=%v", added, err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(content), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("authorized_keys has %d lines, want 2: %q", len(lines), content)
	}
	if lines[0] != key {
		t.Fatalf("first line = %q", lines[0])
	}
}

// Test_sshkey_refuses_invalid proves nothing is written for a bad line.
func Test_sshkey_refuses_invalid(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if _, _, err := Authorize("ssh-rsa AAAA msm-console"); err == nil {
		t.Fatal("Authorize accepted a non-ed25519 key")
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh")); !os.IsNotExist(err) {
		t.Fatalf("a refused key created state: %v", err)
	}
}
