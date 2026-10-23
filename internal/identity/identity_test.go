package identity

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
)

// Test_spki_ed25519 covers PROTOCOL.md §10 "Ed25519 SPKI is the fixed 44-byte form".
func Test_spki_ed25519(t *testing.T) {
	id, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(id.ID) != IDLen {
		t.Fatalf("id is %d bytes, want %d", len(id.ID), IDLen)
	}
	if len(id.SPKI) != SPKILen {
		t.Fatalf("spki is %d bytes, want %d", len(id.SPKI), SPKILen)
	}

	prefix := []byte{0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00}
	if !bytes.HasPrefix(id.SPKI, prefix) {
		t.Fatalf("spki does not start with the Ed25519 prefix: %x", id.SPKI[:12])
	}

	// The certificate must carry exactly that SPKI.
	certificate, err := id.Certificate("msm-node")
	if err != nil {
		t.Fatalf("Certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if !bytes.Equal(parsed.RawSubjectPublicKeyInfo, id.SPKI) {
		t.Fatal("certificate SPKI does not match the identity pin")
	}
	if got, err := SPKIPin(certificate.Certificate[0]); err != nil || !bytes.Equal(got, id.SPKI) {
		t.Fatalf("SPKIPin = %x, %v", got, err)
	}

	// The certificate must negotiate TLS 1.3 only.
	if certificate.Leaf != nil {
		t.Fatal("certificate should not carry a cached leaf")
	}
}

// Test_identity_roundtrip proves the stored key rebuilds the same pin.
func Test_identity_roundtrip(t *testing.T) {
	id, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	encoded, err := id.EncodedKey()
	if err != nil {
		t.Fatalf("EncodedKey: %v", err)
	}
	restored, err := FromStored(id.EncodedID(), encoded)
	if err != nil {
		t.Fatalf("FromStored: %v", err)
	}
	if !bytes.Equal(restored.ID, id.ID) {
		t.Fatal("identity id changed across a save/load cycle")
	}
	if !bytes.Equal(restored.SPKI, id.SPKI) {
		t.Fatal("identity pin changed across a save/load cycle")
	}

	if _, err := FromStored("not-base64", encoded); err == nil {
		t.Fatal("FromStored accepted a non-base64 id")
	}
}

// Test_peer_spki_rejects_non_ed25519 proves the pin is only the fixed form.
func Test_peer_spki_rejects_non_ed25519(t *testing.T) {
	// A certificate whose SPKI is not 44 bytes must not be pinnable.
	cert := &x509.Certificate{RawSubjectPublicKeyInfo: []byte{0x30, 0x00}}
	if _, err := SPKIFromCertificate(cert); err != ErrNotEd25519 {
		t.Fatalf("SPKIFromCertificate = %v, want ErrNotEd25519", err)
	}
}

// Test_peer_spki_over_tls proves the pin survives a real handshake.
func Test_peer_spki_over_tls(t *testing.T) {
	node, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	client, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	nodeCert, err := node.Certificate("msm-node")
	if err != nil {
		t.Fatalf("Certificate: %v", err)
	}
	clientCert, err := client.Certificate("msm-client")
	if err != nil {
		t.Fatalf("Certificate: %v", err)
	}

	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{nodeCert},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	type result struct {
		spki []byte
		err  error
	}
	server := make(chan result, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			server <- result{err: acceptErr}
			return
		}
		defer conn.Close()
		spki, pinErr := PeerSPKI(conn)
		server <- result{spki: spki, err: pinErr}
	}()

	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		Certificates:       []tls.Certificate{clientCert},
		InsecureSkipVerify: true, // pinning replaces chain validation
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	got := <-server
	if got.err != nil {
		t.Fatalf("server PeerSPKI: %v", got.err)
	}
	if !bytes.Equal(got.spki, client.SPKI) {
		t.Fatal("server observed a different pin than the client published")
	}
	if !bytes.Equal(conn.ConnectionState().PeerCertificates[0].RawSubjectPublicKeyInfo, node.SPKI) {
		t.Fatal("client observed a different pin than the node published")
	}

	// A connection that is not TLS must not be pinnable.
	plain, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer plain.Close()
	go func() {
		c, acceptErr := plain.Accept()
		if acceptErr == nil {
			c.Close()
		}
	}()
	raw, err := net.Dial("tcp", plain.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer raw.Close()
	if _, err := PeerSPKI(raw); err == nil {
		t.Fatal("PeerSPKI accepted a plaintext connection")
	}
}
