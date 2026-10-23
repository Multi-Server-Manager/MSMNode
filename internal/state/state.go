// Package state persists the node identity and the consoles it trusts.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/MSM/MSMNode/internal/identity"
)

// ConfigVersion is the on-disk schema version.
const ConfigVersion = 1

// Client is one console that paired with this node.
type Client struct {
	ID       string    `json:"id"`
	SPKI     string    `json:"spki"`
	PairedAt time.Time `json:"paired_at"`
}

// Config is the contents of config.json.
type Config struct {
	Version     int      `json:"version"`
	NodeID      string   `json:"node_id"`
	IdentityKey string   `json:"identity_key"`
	Clients     []Client `json:"clients"`
}

// Dir returns the directory holding the config file.
func Dir(base string) string { return base }

// LoadOrCreate reads the config, generating an identity the first time.
func LoadOrCreate(base string) (*Config, *identity.Identity, error) {
	path := filepath.Join(base, "config.json")

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		id, newErr := identity.New()
		if newErr != nil {
			return nil, nil, newErr
		}
		key, newErr := id.EncodedKey()
		if newErr != nil {
			return nil, nil, newErr
		}
		cfg := &Config{Version: ConfigVersion, NodeID: id.EncodedID(), IdentityKey: key}
		if saveErr := Save(base, cfg); saveErr != nil {
			return nil, nil, saveErr
		}
		return cfg, id, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", path, err)
	}

	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if cfg.Version != ConfigVersion {
		return nil, nil, fmt.Errorf("%s has schema %d, want %d", path, cfg.Version, ConfigVersion)
	}
	id, err := identity.FromStored(cfg.NodeID, cfg.IdentityKey)
	if err != nil {
		return nil, nil, err
	}
	return &cfg, id, nil
}

// Save writes the config atomically with owner-only permissions.
func Save(base string, cfg *Config) error {
	if err := os.MkdirAll(base, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", base, err)
	}
	payload, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')

	path := filepath.Join(base, "config.json")
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return fmt.Errorf("write %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("rename %s: %w", tmp, err)
	}
	return nil
}
