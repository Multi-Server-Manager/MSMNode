package proto

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test_hkdf_rfc5869 covers PROTOCOL.md §10 "HKDF matches RFC 5869 test case 1".
func Test_hkdf_rfc5869(t *testing.T) {
	ikm := bytes.Repeat([]byte{0x0b}, 22)
	salt := mustHex(t, "000102030405060708090a0b0c")
	info := mustHex(t, "f0f1f2f3f4f5f6f7f8f9")

	prk := hkdfExtract(salt, ikm)
	if got, want := hex.EncodeToString(prk), "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"; got != want {
		t.Fatalf("PRK = %s, want %s", got, want)
	}

	okm, err := hkdfExpand(prk, info, 42)
	if err != nil {
		t.Fatalf("hkdfExpand: %v", err)
	}
	if got, want := hex.EncodeToString(okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"; got != want {
		t.Fatalf("OKM = %s, want %s", got, want)
	}

	if _, err := hkdfExpand(prk, info, 0); err == nil {
		t.Fatal("hkdfExpand accepted a zero length")
	}
	if _, err := hkdfExpand(prk, info, 255*32+1); err == nil {
		t.Fatal("hkdfExpand accepted an oversized length")
	}
}

// Test_derive_vectors covers PROTOCOL.md §10 "transcript and proofs are
// deterministic and code-sensitive". The expected values were produced by an
// independent implementation (Python hmac/hashlib), not by this package.
func Test_derive_vectors(t *testing.T) {
	transcript := Transcript{
		ClientEph:   bytes.Repeat([]byte{0x11}, 32),
		NodeEph:     bytes.Repeat([]byte{0x22}, 32),
		ClientNonce: bytes.Repeat([]byte{0x33}, 16),
		NodeNonce:   bytes.Repeat([]byte{0x44}, 16),
		NodeID:      bytes.Repeat([]byte{0x55}, 16),
		NodeSPKI:    append(mustHex(t, "302a300506032b6570032100"), bytes.Repeat([]byte{0x77}, 32)...),
		ClientID:    bytes.Repeat([]byte{0x66}, 16),
		ClientSPKI:  append(mustHex(t, "302a300506032b6570032100"), bytes.Repeat([]byte{0x88}, 32)...),
	}
	shared := make([]byte, 32)
	for i := range shared {
		shared[i] = byte(i)
	}

	th := transcript.Hash()
	checkHex(t, "th", th[:], "bd32dac41b5f3c00a69923cb5dd91234aa846136283eed72fd84223e811ccf7a")

	clientKey, nodeKey, err := PairKeys("7K3M9QXA", shared)
	if err != nil {
		t.Fatalf("PairKeys: %v", err)
	}
	checkHex(t, "c2n", clientKey, "0cbf791edfaddf0d68a5f054890406e4036be9f1736b788ba1d6c276231d67f0")
	checkHex(t, "n2c", nodeKey, "8380e037d87ff7081d4185b6be150dcd07e5fcb4dbf44d3ec1b2fe137581bc64")

	checkHex(t, "client_mac", ClientProof(clientKey, th),
		"dd2ec1d589496749a721d62584f9d7b115c65d35d4005028192cb74a9858bc5c")
	checkHex(t, "node_mac", NodeProof(nodeKey, th),
		"bda7348ebf2ae7b6276f5502a664519b74bf2567d92afa3bdd69ddc44106ec66")

	// A single wrong character in the code must change the client proof.
	wrongKey, _, err := PairKeys("7K3M9QXB", shared)
	if err != nil {
		t.Fatalf("PairKeys: %v", err)
	}
	checkHex(t, "wrong_code_client_mac", ClientProof(wrongKey, th),
		"7a449a29cbb7b56047aef45f42d617e3af40e7884760cf7e9107dbe678e6b4f3")

	// Reordering transcript fields must change the hash.
	swapped := transcript
	swapped.ClientEph, swapped.NodeEph = transcript.NodeEph, transcript.ClientEph
	if swapped.Hash() == th {
		t.Fatal("transcript hash ignores field order")
	}

	// A changed nonce must change the hash.
	mutated := transcript
	mutated.NodeNonce = bytes.Repeat([]byte{0x45}, 16)
	if mutated.Hash() == th {
		t.Fatal("transcript hash ignores the node nonce")
	}
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("bad hex in test: %v", err)
	}
	return b
}

func checkHex(t *testing.T, label string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Fatalf("%s = %s, want %s", label, hex.EncodeToString(got), want)
	}
}
