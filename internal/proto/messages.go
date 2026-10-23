package proto

import "encoding/json"

// marshal renders a message exactly as it goes on the wire.
func marshal(msg Message) ([]byte, error) {
	return json.Marshal(msg)
}

// PairHello opens a pairing session (PROTOCOL.md §6.1).
type PairHello struct {
	T     string `json:"t"`
	V     int    `json:"v"`
	Eph   string `json:"eph"`
	Nonce string `json:"nonce"`
}

// Type implements Message.
func (m *PairHello) Type() string { return TypePairHello }

// NewPairHello builds a hello from raw binary fields.
func NewPairHello(eph, nonce []byte) *PairHello {
	return &PairHello{T: TypePairHello, V: Version, Eph: EncodeB64(eph), Nonce: EncodeB64(nonce)}
}

// PairChallenge is the node's answer to a hello (PROTOCOL.md §6.2).
type PairChallenge struct {
	T          string `json:"t"`
	V          int    `json:"v"`
	Eph        string `json:"eph"`
	Nonce      string `json:"nonce"`
	NodeID     string `json:"node_id"`
	NodeSPKI   string `json:"node_spki"`
	OpPort     int    `json:"op_port"`
	TTLLeft    int    `json:"ttl_left"`
	TrialsLeft int    `json:"trials_left"`
}

// Type implements Message.
func (m *PairChallenge) Type() string { return TypePairChallenge }

// PairProof carries the client's transcript proof (PROTOCOL.md §6.3).
type PairProof struct {
	T          string `json:"t"`
	V          int    `json:"v"`
	MAC        string `json:"mac"`
	ClientID   string `json:"client_id"`
	ClientSPKI string `json:"client_spki"`
}

// Type implements Message.
func (m *PairProof) Type() string { return TypePairProof }

// PairOK is the node's confirmation and proof (PROTOCOL.md §6.4).
type PairOK struct {
	T        string `json:"t"`
	V        int    `json:"v"`
	MAC      string `json:"mac"`
	NodeID   string `json:"node_id"`
	NodeSPKI string `json:"node_spki"`
	OpPort   int    `json:"op_port"`
}

// Type implements Message.
func (m *PairOK) Type() string { return TypePairOK }

// Info asks a pinned node for its identity (PROTOCOL.md §8.1).
type Info struct {
	T string `json:"t"`
	V int    `json:"v"`
}

// Type implements Message.
func (m *Info) Type() string { return TypeInfo }

// InfoOK is the node's answer to Info (PROTOCOL.md §8.2).
type InfoOK struct {
	T             string `json:"t"`
	V             int    `json:"v"`
	NodeID        string `json:"node_id"`
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Version       string `json:"version"`
	PinnedClients int    `json:"pinned_clients"`
}

// Type implements Message.
func (m *InfoOK) Type() string { return TypeInfoOK }

// Error reports a protocol failure (PROTOCOL.md §9).
type Error struct {
	T      string `json:"t"`
	V      int    `json:"v"`
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Type implements Message.
func (m *Error) Type() string { return TypeError }

// NewError builds an error message from a ProtocolError.
func NewError(e *ProtocolError) *Error {
	return &Error{T: TypeError, V: Version, Code: e.Code, Detail: e.Detail}
}
