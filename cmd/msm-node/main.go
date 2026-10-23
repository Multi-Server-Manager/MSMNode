// Command msm-node is the MSM node agent.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/MSM/MSMNode/internal/node"
)

// version is overridden at build time with -ldflags "-X main.version=...".
var version = "0.1.0-dev"

func main() {
	service := flag.String("service", serviceUser, "where to keep state when --state-dir is unset: user (home) or system (/var/lib/msm-node)")
	stateDir := flag.String("state-dir", "", "directory holding config.json; default depends on --service")
	opListen := flag.String("op-listen", "0.0.0.0:7333", "operational listener address")
	pairListen := flag.String("pair-listen", "0.0.0.0:7334", "pairing listener address; a fixed port is what lets a console find an unpaired node over Tailscale (port 0 picks a free one, but only mDNS discovery works then)")
	advertise := flag.String("advertise-host", "", "comma-separated hosts printed in the pairing address; default is every local address, Tailscale first")
	pairingTTL := flag.Duration("pairing-ttl", 5*time.Minute, "lifetime of a pairing code")
	pairingAttempts := flag.Int("pairing-attempts", 3, "failed proofs allowed per code")
	showVersion := flag.Bool("version", false, "print the version and exit")
	debug := flag.Bool("debug", false, "trace TLS handshakes, pairing steps and commands to stderr; stays in the foreground")
	detach := flag.Bool("detach", false, "return the shell prompt and keep serving in the background (default on a terminal)")
	foreground := flag.Bool("foreground", false, "never detach; the systemd units pass this")
	flag.Parse()

	if *showVersion {
		fmt.Println(version)
		return
	}

	dir, err := stateDirFor(*service, *stateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "msm-node: %v\n", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	err = node.Run(ctx, node.Options{
		StateDir:        dir,
		OpListen:        *opListen,
		PairListen:      *pairListen,
		AdvertiseHosts:  advertiseHosts(*advertise),
		PairingTTL:      *pairingTTL,
		PairingAttempts: *pairingAttempts,
		Version:         version,
		Out:             os.Stdout,
		Debug:           debugOut(*debug),
		Detach:          detachMode(*foreground, *detach, *debug),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "msm-node: %v\n", err)
		os.Exit(1)
	}
}

// debugOut returns the trace sink for --debug, or nil for no trace. The trace
// goes to stderr so the machine-readable stdout lines stay unchanged.
func debugOut(on bool) io.Writer {
	if on {
		return os.Stderr
	}
	return nil
}

// detachMode decides whether this run hands itself to the background.
//
// A terminal gets the shell prompt back once the node is serving; a pipe, a log
// redirect or a systemd service keeps the process in the foreground, where its
// output is being collected. `--debug` always stays: the point is to watch the
// trace, and a background node never detaches twice.
func detachMode(foreground, detach, debug bool) bool {
	if foreground || debug {
		return false
	}
	if detach {
		return true
	}
	info, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// advertiseHosts resolves --advertise-host: empty means every local address,
// which is what lets a console on another network pick the Tailscale one.
func advertiseHosts(flagValue string) []string {
	if flagValue == "" {
		return node.LocalAddresses()
	}
	var hosts []string
	for _, host := range strings.Split(flagValue, ",") {
		if trimmed := strings.TrimSpace(host); trimmed != "" {
			hosts = append(hosts, trimmed)
		}
	}
	return hosts
}

// The two modes a packaged systemd unit can start the agent in.
const (
	serviceUser   = "user"
	serviceSystem = "system"
)

// serviceSystemStateDir is where the system unit keeps config.json; the unit
// declares it as StateDirectory so systemd creates it with the right owner.
const serviceSystemStateDir = "/var/lib/msm-node"

// stateDirFor resolves the state directory from --service and --state-dir.
// An explicit --state-dir always wins, so an operator can point either mode
// anywhere without the flag combination being rejected.
func stateDirFor(service, explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	switch service {
	case serviceUser:
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot find a home directory for --service user: %w", err)
		}
		return filepath.Join(home, ".msm-node"), nil
	case serviceSystem:
		return serviceSystemStateDir, nil
	default:
		return "", fmt.Errorf("unknown --service %q (want %q or %q)", service, serviceUser, serviceSystem)
	}
}
