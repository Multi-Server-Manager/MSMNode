package proto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// Transcript holds every value bound into a pairing session (PROTOCOL.md §7.2).
type Transcript struct {
	ClientEph   []byte
	NodeEph     []byte
	ClientNonce []byte
	NodeNonce   []byte
	NodeID      []byte
	NodeSPKI    []byte
	ClientID    []byte
	ClientSPKI  []byte
}

// Hash returns SHA-256 over the domain separator and the length-prefixed fields.
//
// Field order is fixed by the protocol document. Changing it is a protocol
// version bump.
func (t Transcript) Hash() [sha256.Size]byte {
	digest := sha256.New()
	digest.Write([]byte(separator))
	fields := [...][]byte{
		t.ClientEph,
		t.NodeEph,
		t.ClientNonce,
		t.NodeNonce,
		t.NodeID,
		t.NodeSPKI,
		t.ClientID,
		t.ClientSPKI,
	}
	for _, field := range fields {
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(len(field)))
		digest.Write(length[:])
		digest.Write(field)
	}
	var out [sha256.Size]byte
	copy(out[:], digest.Sum(nil))
	return out
}

// PairKeys derives the client and node proof keys (PROTOCOL.md §7.3).
//
// prk1 binds the one-time code, prk2 binds the shared X25519 secret, so neither
// the code alone nor the secret alone yields a usable key.
func PairKeys(code string, shared []byte) (clientKey, nodeKey []byte, err error) {
	prk1 := hkdfExtract([]byte("msm-pair-v1 code seal"), []byte(code))
	prk2 := hkdfExtract(prk1, shared)

	clientKey, err = hkdfExpand(prk2, []byte("msm-pair-v1 client proof"), sha256.Size)
	if err != nil {
		return nil, nil, err
	}
	nodeKey, err = hkdfExpand(prk2, []byte("msm-pair-v1 node proof"), sha256.Size)
	if err != nil {
		return nil, nil, err
	}
	return clientKey, nodeKey, nil
}

// ClientProof is HMAC-SHA256(c2n, "MSM-PAIR-V1 client" || th).
func ClientProof(clientKey []byte, transcript [sha256.Size]byte) []byte {
	return proof(clientKey, "MSM-PAIR-V1 client", transcript)
}

// NodeProof is HMAC-SHA256(n2c, "MSM-PAIR-V1 node" || th).
func NodeProof(nodeKey []byte, transcript [sha256.Size]byte) []byte {
	return proof(nodeKey, "MSM-PAIR-V1 node", transcript)
}

func proof(key []byte, label string, transcript [sha256.Size]byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(label))
	mac.Write(transcript[:])
	return mac.Sum(nil)
}

// EqualMAC compares two MACs in constant time.
func EqualMAC(a, b []byte) bool { return hmac.Equal(a, b) }
