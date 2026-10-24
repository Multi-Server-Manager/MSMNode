package node

import (
	"context"
	"io"
	"path/filepath"
	"strings"

	"github.com/MSM/MSMNode/internal/sshkey"
	"github.com/MSM/MSMNode/internal/state"
	"github.com/MSM/MSMNode/internal/sys"
)

// Check validates everything a start needs before it binds a port: the state
// file, the SSH identity, the command runner and the setup answers.
//
// `--check` runs it, and an upgrade runs it through the new binary before
// committing to it. A binary that cannot start is then refused while the old
// image is still serving, so a bad upgrade cannot take a node offline.
func Check(opts Options) error {
	cfg, _, err := state.LoadOrCreate(opts.StateDir)
	if err != nil {
		return err
	}
	if _, err := sshkey.LoadOrCreateIdentity(filepath.Join(opts.StateDir, "ssh")); err != nil {
		return err
	}

	n := &Node{opts: opts, cfg: cfg, out: io.Discard, ctx: context.Background()}
	n.setup = cfg.Setup
	n.runner, err = sys.RunnerFor(cfg.Setup.RunAs)
	if err != nil {
		return err
	}

	// A check has no terminal, and must take exactly the path a service start
	// takes: the answers stand, and stdin is never read.
	return n.configureSetup(strings.NewReader(""), io.Discard, opts.Setup, false)
}
