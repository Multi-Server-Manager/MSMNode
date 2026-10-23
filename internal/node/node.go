// Package node runs the msm-node agent: an operational listener for pinned
// consoles and, until the first console pairs, a one-time pairing listener.
package node

import (
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/MSM/MSMNode/internal/identity"
	"github.com/MSM/MSMNode/internal/mdns"
	"github.com/MSM/MSMNode/internal/proto"
	"github.com/MSM/MSMNode/internal/state"
)

const (
	// pairingDeadline bounds a single pairing connection.
	pairingDeadline = 30 * time.Second
	// operationalDeadline bounds a single operational request.
	operationalDeadline = 15 * time.Second
)

// Options configures one node run.
type Options struct {
	StateDir   string
	OpListen   string
	PairListen string
	// AdvertiseHosts are the hosts printed in the pairing announcement, best
	// first. Empty means every local address, Tailscale before LAN.
	AdvertiseHosts  []string
	PairingTTL      time.Duration
	PairingAttempts int
	Version         string
	Out             io.Writer
	// Debug is the verbose trace behind `--debug`; nil keeps it silent. It
	// never contains a pairing code or a private key.
	Debug io.Writer
	// Detach re-execs the node in the background once it is serving, so the
	// terminal that started it gets its prompt back. `--debug` runs never
	// detach.
	Detach bool
}

// Node is a running agent.
type Node struct {
	opts Options
	out  io.Writer
	// debug is opts.Debug, copied out so a nil writer means "no trace".
	debug io.Writer
	// lock keeps one node per state directory; nil once it has been given to
	// a background child.
	lock *instanceLock

	mu     sync.RWMutex
	cfg    *state.Config
	id     *identity.Identity
	opPort int

	// cmdMu serialises operational commands: one at a time, `busy` otherwise.
	cmdMu sync.Mutex
	// logs is the bounded ring served by logs.tail.
	logs *logRing
}

// Run starts the agent and blocks until the context is cancelled.
func Run(ctx context.Context, opts Options) error {
	if opts.Out == nil {
		opts.Out = io.Discard
	}
	ring := newLogRing(proto.MaxLogBufferLines)
	n := &Node{opts: opts, out: newLogWriter(opts.Out, ring), logs: ring, debug: opts.Debug}

	cfg, id, err := state.LoadOrCreate(opts.StateDir)
	if err != nil {
		return err
	}
	n.cfg, n.id = cfg, id
	if len(opts.AdvertiseHosts) == 0 {
		opts.AdvertiseHosts = LocalAddresses()
	}
	n.opts = opts

	lock, err := acquireInstanceLock(opts.StateDir)
	if err != nil {
		return err
	}
	n.lock = lock
	defer n.releaseLock()

	fmt.Fprintf(n.out, "MSM-NODE id=%s version=%s state=%s\n", id.EncodedID(), opts.Version, opts.StateDir)
	n.debugf("start version=%s state=%s paired=%d advertise=%s",
		opts.Version, opts.StateDir, len(cfg.Clients), strings.Join(opts.AdvertiseHosts, ","))

	operational, err := tls.Listen("tcp", opts.OpListen, n.serverTLS())
	if err != nil {
		return fmt.Errorf("listen %s: %w", opts.OpListen, err)
	}
	defer operational.Close()
	n.opPort = operational.Addr().(*net.TCPAddr).Port
	go n.acceptOperational(operational)
	fmt.Fprintf(n.out, "LISTEN addr=%s\n", operational.Addr().String())
	n.debugf("operational listener on %s (port %d)", operational.Addr(), n.opPort)

	if len(cfg.Clients) > 0 {
		fmt.Fprintf(n.out, "PAIRING skipped=already-paired\n")
	} else {
		if err := n.pairingPhase(ctx); err != nil {
			return err
		}
		if ctx.Err() != nil {
			return nil
		}
	}

	// Detach only once the node is serving: the terminal keeps the pairing
	// code and PAIRED line, then the shell prompt comes back.
	if opts.Detach {
		return n.detach(operational)
	}

	go n.watchExecutable(ctx)
	stop := n.startDiscovery(ctx, n.opPort)
	defer stop()
	<-ctx.Done()
	return nil
}

// releaseLock drops the instance lock, if this process still holds it.
func (n *Node) releaseLock() {
	if n.lock != nil {
		n.lock.release()
		n.lock = nil
	}
}

// startDiscovery advertises the port that accepts new consoles right now: the
// pairing port while unpaired, the operational port afterwards. Discovery is a
// convenience, so a host without multicast keeps serving and only says so.
func (n *Node) startDiscovery(ctx context.Context, port int) func() {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "msm-node"
	}
	lan := lanAddress(n.opts.AdvertiseHosts)
	n.debugf("mDNS advertises %s:%d as %s", lan, port, hostname)
	advertiser, err := mdns.NewAt(hostname, port, lan, n.id.EncodedID(), n.id.EncodedSPKI())
	if err != nil {
		n.logf("MDNS disabled=%s", err)
		return func() {}
	}

	discoveryCtx, cancel := context.WithCancel(ctx)
	go func() {
		if err := advertiser.Run(discoveryCtx); err != nil {
			n.logf("MDNS stopped=%s", err)
		}
	}()
	n.logf("MDNS service=%s instance=%s port=%d", mdns.Service, hostname, port)
	return cancel
}

// serverTLS is the TLS profile from PROTOCOL.md §1. Client certificates are
// requested but not validated against a CA: the pin is checked by the caller.
func (n *Node) serverTLS() *tls.Config {
	certificate, err := n.id.Certificate("msm-node")
	if err != nil {
		return &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	}
	return &tls.Config{
		Certificates: []tls.Certificate{certificate},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	}
}

// pairingPhase advertises a one-time code and accepts pairing attempts until
// one succeeds or the context is cancelled.
func (n *Node) pairingPhase(ctx context.Context) error {
	listener, err := tls.Listen("tcp", n.opts.PairListen, n.serverTLS())
	if err != nil {
		return fmt.Errorf("listen %s: %w", n.opts.PairListen, err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	n.debugf("pairing listener on %s (port %d)", listener.Addr(), port)
	n.debugf("a console must reach TCP %d (pairing) and %d (commands); if firewalld is running, allow the service: firewall-cmd --permanent --add-service=msm-node && firewall-cmd --reload", port, n.opPort)
	stopDiscovery := n.startDiscovery(ctx, port)
	defer stopDiscovery()
	addresses := endpoints(n.opts.AdvertiseHosts, port)

	pair, err := newPairer(n.opts.PairingTTL, n.opts.PairingAttempts, addresses, n.out)
	if err != nil {
		return err
	}
	pair.announce("")

	var once sync.Once
	paired := make(chan struct{})
	signal := func() { once.Do(func() { close(paired) }) }

	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go n.handlePair(conn, pair, signal)
		}
	}()

	select {
	case <-paired:
		// Burn the code and stop accepting pairing connections. Run takes over
		// from here: it either serves on the operational port or detaches, and
		// re-announces that port in both cases.
		listener.Close()
		stopDiscovery()
		fmt.Fprintf(n.out, "PAIRING closed\n")
		return nil
	case <-ctx.Done():
		return nil
	}
}

// handlePair runs one pairing attempt (PROTOCOL.md §6).
func (n *Node) handlePair(conn net.Conn, pair *pairer, signal func()) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(pairingDeadline))
	remote := conn.RemoteAddr().String()

	n.debugf("pair %s: connected", remote)
	if !n.clientHandshake(conn, "pair", remote) {
		return
	}

	message, err := proto.ReadMessage(conn)
	if err != nil {
		n.debugf("pair %s: no pair.hello: %v", remote, err)
		replyError(conn, err)
		return
	}
	hello, ok := message.(*proto.PairHello)
	if !ok {
		n.debugf("pair %s: first message is %s, want pair.hello", remote, message.Type())
		replyError(conn, proto.Errorf(proto.CodeUnknownType, "expected pair.hello, got %q", message.Type()))
		return
	}
	n.debugf("pair %s: pair.hello", remote)

	clientEphRaw, err := proto.DecodeB64N(hello.Eph, 32)
	if err != nil {
		n.debugf("pair %s: bad ephemeral key: %v", remote, err)
		replyError(conn, err)
		return
	}
	clientNonce, err := proto.DecodeB64N(hello.Nonce, 16)
	if err != nil {
		n.debugf("pair %s: bad nonce: %v", remote, err)
		replyError(conn, err)
		return
	}
	clientEph, err := ecdh.X25519().NewPublicKey(clientEphRaw)
	if err != nil {
		n.debugf("pair %s: eph is not a valid X25519 key", remote)
		replyError(conn, proto.Errorf(proto.CodeBadFrame, "eph is not a valid X25519 key"))
		return
	}

	// The proof is bound to the certificate the client presented, so a recorded
	// proof cannot be replayed from a different TLS identity.
	clientSPKI, err := identity.PeerSPKI(conn)
	if err != nil {
		n.debugf("pair %s: no client certificate", remote)
		replyError(conn, proto.Errorf(proto.CodeUnauthorized, "a client certificate is required"))
		return
	}
	n.debugf("pair %s: client spki=%s", remote, proto.EncodeB64(clientSPKI))

	code, trials, ttlLeft, perr := pair.begin()
	if perr != nil {
		n.logf("PAIRING failed from %s: %s", remote, perr.Detail)
		replyError(conn, perr)
		return
	}

	nodeEph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		replyError(conn, proto.Errorf(proto.CodeInternal, "cannot generate an ephemeral key"))
		return
	}
	nodeNonce := make([]byte, 16)
	if _, err := rand.Read(nodeNonce); err != nil {
		replyError(conn, proto.Errorf(proto.CodeInternal, "cannot generate a nonce"))
		return
	}

	challenge := &proto.PairChallenge{
		T:          proto.TypePairChallenge,
		V:          proto.Version,
		Eph:        proto.EncodeB64(nodeEph.PublicKey().Bytes()),
		Nonce:      proto.EncodeB64(nodeNonce),
		NodeID:     n.id.EncodedID(),
		NodeSPKI:   n.id.EncodedSPKI(),
		OpPort:     n.opPort,
		TTLLeft:    int(ttlLeft.Seconds()),
		TrialsLeft: trials,
	}
	if err := proto.WriteMessage(conn, challenge); err != nil {
		n.debugf("pair %s: challenge not sent: %v", remote, err)
		return
	}
	n.debugf("pair %s: challenge sent (trials=%d ttl=%ds)", remote, trials, int(ttlLeft.Seconds()))

	message, err = proto.ReadMessage(conn)
	if err != nil {
		n.debugf("pair %s: no pair.proof: %v", remote, err)
		replyError(conn, err)
		return
	}
	proof, ok := message.(*proto.PairProof)
	if !ok {
		n.debugf("pair %s: got %s, want pair.proof", remote, message.Type())
		replyError(conn, proto.Errorf(proto.CodeUnknownType, "expected pair.proof, got %q", message.Type()))
		return
	}

	clientID, err := proto.DecodeB64N(proof.ClientID, identity.IDLen)
	if err != nil {
		replyError(conn, err)
		return
	}
	claimedSPKI, err := proto.DecodeB64N(proof.ClientSPKI, identity.SPKILen)
	if err != nil {
		replyError(conn, err)
		return
	}
	clientMAC, err := proto.DecodeB64N(proof.MAC, 32)
	if err != nil {
		replyError(conn, err)
		return
	}

	if !hmac.Equal(claimedSPKI, clientSPKI) {
		code := pair.fail(code)
		n.logf("PAIRING failed from %s: the client certificate does not match the claimed identity", remote)
		replyError(conn, proto.Errorf(code, "client certificate does not match the claimed identity"))
		return
	}

	shared, err := nodeEph.ECDH(clientEph)
	if err != nil {
		code := pair.fail(code)
		n.logf("PAIRING failed from %s: ephemeral key exchange failed", remote)
		replyError(conn, proto.Errorf(code, "ephemeral key exchange failed"))
		return
	}

	transcript := proto.Transcript{
		ClientEph:   clientEphRaw,
		NodeEph:     nodeEph.PublicKey().Bytes(),
		ClientNonce: clientNonce,
		NodeNonce:   nodeNonce,
		NodeID:      n.id.ID,
		NodeSPKI:    n.id.SPKI,
		ClientID:    clientID,
		ClientSPKI:  clientSPKI,
	}.Hash()

	clientKey, nodeKey, err := proto.PairKeys(code, shared)
	if err != nil {
		replyError(conn, proto.Errorf(proto.CodeInternal, "cannot derive pairing keys"))
		return
	}
	if !proto.EqualMAC(proto.ClientProof(clientKey, transcript), clientMAC) {
		code := pair.fail(code)
		n.logf("PAIRING failed from %s: the code did not verify (wrong code, or a code that was replaced)", remote)
		replyError(conn, proto.Errorf(code, "pairing proof did not verify"))
		return
	}

	if !pair.succeed(code) {
		replyError(conn, proto.Errorf(proto.CodeExpired, "the pairing code is no longer valid"))
		return
	}

	// Commit the pin before acknowledging, so a lost acknowledgement can never
	// leave the node trusting a console that believes it failed.
	if err := n.pin(clientID, clientSPKI); err != nil {
		replyError(conn, proto.Errorf(proto.CodeInternal, "cannot persist the pairing"))
		return
	}

	if err := proto.WriteMessage(conn, &proto.PairOK{
		T:        proto.TypePairOK,
		V:        proto.Version,
		MAC:      proto.EncodeB64(proto.NodeProof(nodeKey, transcript)),
		NodeID:   n.id.EncodedID(),
		NodeSPKI: n.id.EncodedSPKI(),
		OpPort:   n.opPort,
	}); err != nil {
		return
	}

	fmt.Fprintf(n.out, "PAIRED client=%s spki=%s\n", proto.EncodeB64(clientID), proto.EncodeB64(clientSPKI))
	n.debugf("pair %s: client %s pinned and acknowledged", remote, proto.EncodeB64(clientID))
	signal()
}

// pin records a console identity and persists it.
func (n *Node) pin(clientID, spki []byte) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	id := proto.EncodeB64(clientID)
	pin := proto.EncodeB64(spki)
	for i := range n.cfg.Clients {
		if n.cfg.Clients[i].ID == id {
			n.cfg.Clients[i].SPKI = pin
			n.cfg.Clients[i].PairedAt = time.Now().UTC()
			return state.Save(n.opts.StateDir, n.cfg)
		}
	}
	n.cfg.Clients = append(n.cfg.Clients, state.Client{
		ID:       id,
		SPKI:     pin,
		PairedAt: time.Now().UTC(),
	})
	return state.Save(n.opts.StateDir, n.cfg)
}

// isPinned reports whether a certificate belongs to a paired console.
func (n *Node) isPinned(spki []byte) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()

	pin := proto.EncodeB64(spki)
	for _, client := range n.cfg.Clients {
		if client.SPKI == pin {
			return true
		}
	}
	return false
}

func (n *Node) acceptOperational(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go n.handleOperational(conn)
	}
}

// handleOperational answers requests from a pinned console (PROTOCOL.md §8).
func (n *Node) handleOperational(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(operationalDeadline))
	remote := conn.RemoteAddr().String()

	n.debugf("command %s: connected", remote)
	if !n.clientHandshake(conn, "command", remote) {
		return
	}

	spki, err := identity.PeerSPKI(conn)
	if err != nil {
		n.debugf("command %s: no client certificate", remote)
		replyError(conn, proto.Errorf(proto.CodeUnauthorized, "a client certificate is required"))
		return
	}
	if !n.isPinned(spki) {
		n.debugf("command %s: client %s is not pinned", remote, proto.EncodeB64(spki))
		replyError(conn, proto.Errorf(proto.CodeUnauthorized, "this console is not paired with this node"))
		return
	}

	message, err := proto.ReadMessage(conn)
	if err != nil {
		n.debugf("command %s: no request: %v", remote, err)
		replyError(conn, err)
		return
	}
	n.debugf("command %s: %s", remote, message.Type())
	n.dispatch(conn, message)
}

// clientHandshake completes the TLS handshake explicitly, so `--debug` can say
// why a connection died. Without it the failure only shows up at the first
// read, where a wrong port, a plain TCP probe and a TLS mismatch all look the
// same.
func (n *Node) clientHandshake(conn net.Conn, kind, remote string) bool {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return true
	}
	if err := tlsConn.Handshake(); err != nil {
		n.debugf("%s %s: TLS handshake failed: %v", kind, remote, err)
		return false
	}
	state := tlsConn.ConnectionState()
	certificate := "none"
	if len(state.PeerCertificates) > 0 {
		certificate = "presented"
	}
	n.debugf("%s %s: %s, cipher %s, client certificate %s",
		kind, remote, tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite), certificate)
	return true
}

// debugf writes one timestamped line to the `--debug` stream when it is on.
func (n *Node) debugf(format string, args ...any) {
	if n.debug == nil {
		return
	}
	stamp := time.Now().Format("2006-01-02T15:04:05.000Z07:00")
	fmt.Fprintf(n.debug, "%s DEBUG %s\n", stamp, fmt.Sprintf(format, args...))
}

// handleInfo answers the identity query from a pinned console.
func (n *Node) handleInfo(conn net.Conn) {
	hostname, _ := os.Hostname()
	n.mu.RLock()
	pinned := len(n.cfg.Clients)
	n.mu.RUnlock()

	_ = proto.WriteMessage(conn, &proto.InfoOK{
		T:             proto.TypeInfoOK,
		V:             proto.Version,
		NodeID:        n.id.EncodedID(),
		Hostname:      hostname,
		OS:            runtime.GOOS + "/" + runtime.GOARCH,
		Version:       n.opts.Version,
		PinnedClients: pinned,
	})
}

// replyError sends an `error` message and gives the peer a moment to read it.
func replyError(w io.Writer, err error) {
	perr := &proto.ProtocolError{Code: proto.CodeInternal, Detail: "internal error"}
	var target *proto.ProtocolError
	if errors.As(err, &target) {
		perr = target
	}
	_ = proto.WriteMessage(w, proto.NewError(perr))
}
