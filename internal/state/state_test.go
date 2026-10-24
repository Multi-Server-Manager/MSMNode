package state

import (
	"encoding/json"
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

// Test_migrating_a_version_1_config_never_asks_again proves an upgrade from the
// pre-setup schema is not a first run: the identity, the pins and the answers
// survive, and the questions stay answered, so restarting the node on the
// terminal of the upgrade never asks for them again.
func Test_migrating_a_version_1_config_never_asks_again(t *testing.T) {
	dir := t.TempDir()
	cfg, id, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	// The shape 1.0.x wrote: schema 1, no setup block, pins present.
	v1 := struct {
		Version     int      `json:"version"`
		NodeID      string   `json:"node_id"`
		IdentityKey string   `json:"identity_key"`
		Clients     []Client `json:"clients"`
	}{
		Version:     1,
		NodeID:      cfg.NodeID,
		IdentityKey: cfg.IdentityKey,
		Clients:     []Client{{ID: "abc", SPKI: "def"}},
	}
	payload, err := json.MarshalIndent(v1, "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.json"), payload, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	migrated, migratedID, err := LoadOrCreate(dir)
	if err != nil {
		t.Fatalf("migrating LoadOrCreate: %v", err)
	}
	if migrated.Version != ConfigVersion {
		t.Fatalf("schema = %d, want %d", migrated.Version, ConfigVersion)
	}
	if !migrated.Setup.Configured {
		t.Fatal("a migrated node is unconfigured: the upgrade would ask the questions again")
	}
	if migrated.Setup.RunAs == "" || migrated.Setup.SSHUser == "" || migrated.Setup.SSHPort != DefaultSSHPort {
		t.Fatalf("migrated setup = %+v, want the install defaults", migrated.Setup)
	}
	if migrated.NodeID != cfg.NodeID || migratedID.EncodedSPKI() != id.EncodedSPKI() {
		t.Fatal("the upgrade changed the node identity")
	}
	if len(migrated.Clients) != 1 || migrated.Clients[0].ID != "abc" {
		t.Fatalf("the upgrade lost a pin: %+v", migrated.Clients)
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
