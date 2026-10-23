package state

import (
	"os"
	"path/filepath"
	"testing"
)

// Test_load_or_create proves a first run mints an identity and persists it.
func Test_load_or_create(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "msm-node")

	cfg, id, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if len(cfg.Clients) != 0 {
		t.Fatalf("fresh config has %d clients, want 0", len(cfg.Clients))
	}
	if cfg.NodeID != id.EncodedID() {
		t.Fatal("config node id does not match the identity")
	}

	path := filepath.Join(dir, "config.json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat config: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("config mode = %o, want 600", mode)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if mode := dirInfo.Mode().Perm(); mode != 0o700 {
		t.Fatalf("state dir mode = %o, want 700", mode)
	}

	// A second load reads the same identity back.
	again, againID, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if again.NodeID != cfg.NodeID {
		t.Fatal("node id changed across restarts")
	}
	if againID.EncodedSPKI() != id.EncodedSPKI() {
		t.Fatal("identity pin changed across restarts")
	}
}

// Test_save_clients proves pinned consoles survive a restart.
func Test_save_clients(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "msm-node")
	cfg, _, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	cfg.Clients = append(cfg.Clients, Client{ID: "abc", SPKI: "def"})
	if err := Save(dir, cfg); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reloaded, _, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate after save: %v", err)
	}
	if len(reloaded.Clients) != 1 || reloaded.Clients[0].ID != "abc" {
		t.Fatalf("clients = %+v", reloaded.Clients)
	}
}

// Test_rejects_bad_schema proves an unknown config version is not guessed at.
func Test_rejects_bad_schema(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"version":9}`), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, _, err := LoadOrCreate(dir); err == nil {
		t.Fatal("LoadOrCreate accepted an unknown schema version")
	}
}
