package mdns

import (
	"encoding/binary"
	"strings"
	"testing"
)

func testAdvertiser(t *testing.T) *Advertiser {
	t.Helper()
	return &Advertiser{
		instance: "node-one",
		port:     7333,
		address:  []byte{192, 0, 2, 10},
		records:  []string{"id=abc", "spki=def", "v=1"},
	}
}

// Test_mdns_response proves the answer set carries all four record types with
// the port and address a console needs.
func Test_mdns_response(t *testing.T) {
	packet := testAdvertiser(t).response()

	if flags := binary.BigEndian.Uint16(packet[2:]); flags&0x8000 == 0 {
		t.Fatalf("flags %#x are not a response", flags)
	}
	if answers := binary.BigEndian.Uint16(packet[6:]); answers != 4 {
		t.Fatalf("ancount = %d, want 4", answers)
	}

	types := make(map[uint16]int)
	offset := 12
	for offset < len(packet) {
		name, next, ok := readName(packet, offset)
		if !ok {
			t.Fatalf("cannot parse a name at %d", offset)
		}
		offset = next + 8 // type, class, ttl
		kind := binary.BigEndian.Uint16(packet[next:])
		length := int(binary.BigEndian.Uint16(packet[offset:]))
		offset += 2
		types[kind]++

		if kind == typeSRV {
			port := binary.BigEndian.Uint16(packet[offset+4:])
			if port != 7333 {
				t.Fatalf("SRV port = %d, want 7333", port)
			}
			target, _, ok := readName(packet, offset+6)
			if !ok || target != "node-one.local." {
				t.Fatalf("SRV target = %q", target)
			}
		}
		if kind == typePTR {
			instance, _, ok := readName(packet, offset)
			if !ok || instance != "node-one."+Service {
				t.Fatalf("PTR target = %q", instance)
			}
		}
		if kind == typeTXT {
			if !strings.Contains(string(packet[offset:offset+length]), "id=abc") {
				t.Fatalf("TXT = %q", packet[offset:offset+length])
			}
		}
		_ = name
		offset += length
	}

	for _, want := range []uint16{typePTR, typeSRV, typeTXT, typeA} {
		if types[want] != 1 {
			t.Fatalf("record type %d appears %d times, want 1", want, types[want])
		}
	}
}

// Test_mdns_queries proves a service query is recognised and a response is not.
func Test_mdns_queries(t *testing.T) {
	query := queryPacket()
	if !queriesForService(query) {
		t.Fatal("the service query was not recognised")
	}
	if queriesForService(testAdvertiser(t).response()) {
		t.Fatal("a response was treated as a query")
	}

	other := make([]byte, 12)
	binary.BigEndian.PutUint16(other[4:], 1)
	other = appendName(other, "_http._tcp.local.")
	other = binary.BigEndian.AppendUint16(other, typePTR)
	other = binary.BigEndian.AppendUint16(other, classIN)
	if queriesForService(other) {
		t.Fatal("an unrelated service query was answered")
	}
}

// Test_mdns_names proves compression pointers are followed.
func Test_mdns_names(t *testing.T) {
	var packet []byte
	packet = appendName(packet, Service)
	pointer := len(packet)
	packet = append(packet, 0xC0, 0x00) // back to offset 0

	name, next, ok := readName(packet, pointer)
	if !ok || name != Service || next != pointer+2 {
		t.Fatalf("readName = %q, %d, %v", name, next, ok)
	}
}

// Test_mdns_sanitize keeps instance labels legal.
func Test_mdns_sanitize(t *testing.T) {
	cases := map[string]string{
		"node-one":     "node-one",
		"node one":     "node-one",
		"a.b":          "a-b",
		"ünïcödé":      "ncd",
		"--x--":        "x",
		"MSM_Node_001": "MSM-Node-001",
	}
	for input, want := range cases {
		if got := sanitize(input); got != want {
			t.Fatalf("sanitize(%q) = %q, want %q", input, got, want)
		}
	}
}
