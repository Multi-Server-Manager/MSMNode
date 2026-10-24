package proto

import (
	"encoding/json"
	"strings"
	"testing"
)

// Test_setup_travels_only_when_answered proves a console that skipped the
// questions sends exactly the old wire shape (PROTOCOL.md §6.3).
func Test_setup_travels_only_when_answered(t *testing.T) {
	proof := &PairProof{T: TypePairProof, V: Version, MAC: "m", ClientID: "c", ClientSPKI: "s"}
	encoded, err := json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), "setup") {
		t.Fatalf("unanswered proof carries setup: %s", encoded)
	}

	proof.Setup = &Setup{RunAs: "root", SSHUser: "admin", SSHPort: 2222}
	encoded, err = json.Marshal(proof)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	want := `{"t":"pair.proof","v":1,"mac":"m","client_id":"c","client_spki":"s","setup":{"run_as":"root","ssh_user":"admin","ssh_port":2222}}`
	if string(encoded) != want {
		t.Fatalf("encoded as %s, want %s", encoded, want)
	}

	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	arrived, ok := decoded.(*PairProof)
	if !ok {
		t.Fatalf("decoded %T", decoded)
	}
	if arrived.Setup == nil || arrived.Setup.SSHPort != 2222 {
		t.Fatalf("setup did not survive the roundtrip: %+v", arrived.Setup)
	}
}
