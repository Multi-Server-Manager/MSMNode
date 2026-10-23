// Package identity owns the node's long-term Ed25519 key and the self-signed
// certificate built from it.
//
// The identity is the certificate's SubjectPublicKeyInfo, not a hostname or a
// CA chain; see MSM/docs/PROTOCOL.md §1 and §5.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// IDLen is the length of a node or client identifier.
const IDLen = 16

// SPKILen is the DER length of an Ed25519 SubjectPublicKeyInfo.
const SPKILen = 44

// ErrNoPeerCert reports a TLS peer that presented no certificate.
var ErrNoPeerCert = errors.New("peer presented no certificate")

// ErrNotEd25519 reports a peer whose identity key is not Ed25519.
var ErrNotEd25519 = errors.New("peer identity is not an Ed25519 key")

// Identity is a node or client long-term key plus its identifier.
type Identity struct {
	ID   []byte
	SPKI []byte
	key  ed25519.PrivateKey
}

// New generates a fresh identity.
func New() (*Identity, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, IDLen)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	spki, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return nil, err
	}
	return &Identity{ID: id, SPKI: spki, key: private}, nil
}

// FromStored rebuilds an identity from its base64 fields.
func FromStored(idField, keyField string) (*Identity, error) {
	id, err := base64.StdEncoding.Strict().DecodeString(idField)
	if err != nil {
		return nil, fmt.Errorf("identity id is not base64: %w", err)
	}
	if len(id) != IDLen {
		return nil, fmt.Errorf("identity id is %d bytes, want %d", len(id), IDLen)
	}
	der, err := base64.StdEncoding.Strict().DecodeString(keyField)
	if err != nil {
		return nil, fmt.Errorf("identity key is not base64: %w", err)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("identity key is not PKCS#8: %w", err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("identity key is not Ed25519")
	}
	spki, err := x509.MarshalPKIXPublicKey(private.Public())
	if err != nil {
		return nil, err
	}
	return &Identity{ID: id, SPKI: spki, key: private}, nil
}

// EncodedKey returns the PKCS#8 private key as base64.
func (i *Identity) EncodedKey() (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(i.key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

// EncodedID returns the identifier as base64.
func (i *Identity) EncodedID() string { return base64.StdEncoding.EncodeToString(i.ID) }

// EncodedSPKI returns the pinned value as base64.
func (i *Identity) EncodedSPKI() string { return base64.StdEncoding.EncodeToString(i.SPKI) }

// Certificate builds the self-signed certificate served during TLS (PROTOCOL.md §1).
func (i *Identity) Certificate(role string) (tls.Certificate, error) {
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: role},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{role},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, i.key.Public(), i.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: i.key}, nil
}

// SPKIPin extracts the identity pin from a DER certificate.
//
// Only the fixed 44-byte Ed25519 SubjectPublicKeyInfo is accepted, so a peer
// offering a different key type cannot be pinned by accident.
func SPKIPin(certDER []byte) ([]byte, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("peer certificate is not parseable: %w", err)
	}
	return SPKIFromCertificate(cert)
}

// SPKIFromCertificate returns the pin for an already parsed certificate.
func SPKIFromCertificate(cert *x509.Certificate) ([]byte, error) {
	spki := cert.RawSubjectPublicKeyInfo
	if len(spki) != SPKILen {
		return nil, ErrNotEd25519
	}
	return spki, nil
}

// PeerSPKI returns the pin of the peer on a TLS connection.
//
// The handshake is completed first when it has not run yet: a caller that wants
// to inspect the peer identity before reading a frame must not observe an empty
// connection state. The caller is responsible for setting a deadline.
func PeerSPKI(conn net.Conn) ([]byte, error) {
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, errors.New("connection is not TLS")
	}
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, ErrNoPeerCert
	}
	return SPKIFromCertificate(state.PeerCertificates[0])
}
