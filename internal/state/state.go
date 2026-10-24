// Package state persists the node identity, its setup answers and the consoles
// it trusts.
package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/MSM/MSMNode/internal/identity"
)

// ConfigVersion is the on-disk schema version.
//
// Version 2 added the setup block: which account commands run as, where SSH
// logins land and on which port. A version 1 file is migrated in place, so an
// upgrade never asks for the pairing code again.
const ConfigVersion = 2

// DefaultSSHPort is offered when nothing else is known.
const DefaultSSHPort = 22

// Setup is what the first pairing asked, and what `node.setup` may change.
type Setup struct {
	// Configured is true once an operator answered the questions, so starting
	// the agent again never asks twice.
	Configured bool `json:"configured"`
	// RunAs is the account package and service commands run as.
	RunAs string `json:"run_as"`
	// SSHUser is the account the console's key is installed for.
	SSHUser string `json:"ssh_user"`
	// SSHPort is the port the console dials for SSH.
	SSHPort int `json:"ssh_port"`
}

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
	Setup       Setup    `json:"setup"`
	Clients     []Client `json:"clients"`
}

// Dir returns the directory holding the config file.
func Dir(base string) string { return base }

// DefaultSetup is the answer set offered on a fresh install: the account the
// agent runs as, the same account for SSH, and the standard SSH port.
func DefaultSetup() Setup {
	name := "root"
	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}
	return Setup{RunAs: name, SSHUser: name, SSHPort: DefaultSSHPort}
}

// normalize fills the gaps a migrated or hand-written config may have, so the
// rest of the agent never has to guess.
func (c *Config) normalize() {
	defaults := DefaultSetup()
	if c.Setup.RunAs == "" {
		c.Setup.RunAs = defaults.RunAs
	}
	if c.Setup.SSHUser == "" {
		c.Setup.SSHUser = c.Setup.RunAs
	}
	if c.Setup.SSHPort <= 0 || c.Setup.SSHPort > 65535 {
		c.Setup.SSHPort = DefaultSSHPort
	}
}

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
		cfg := &Config{Version: ConfigVersion, NodeID: id.EncodedID(), IdentityKey: key, Setup: DefaultSetup()}
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
	switch cfg.Version {
	case 1:
		// The setup block did not exist; keep the pins and fill in defaults.
		cfg.Version = ConfigVersion
		cfg.Setup = DefaultSetup()
		if err := Save(base, &cfg); err != nil {
			return nil, nil, err
		}
	case ConfigVersion:
	default:
		return nil, nil, fmt.Errorf("%s has schema %d, want %d", path, cfg.Version, ConfigVersion)
	}
	cfg.normalize()

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
	cfg.Version = ConfigVersion
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
