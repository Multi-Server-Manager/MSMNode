package node

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// Test_addresses_tailscale_first proves the ordering rule: a Tailscale address
// is the one a console on another network can reach, so it is offered first.
func Test_addresses_tailscale_first(t *testing.T) {
	if !isTailscale(net.ParseIP("100.89.238.21")) {
		t.Fatal("100.89.238.21 is not recognised as Tailscale")
	}
	for _, not := range []string{"10.134.179.6", "192.168.1.2", "172.17.0.1", "100.63.0.1", "100.128.0.1"} {
		if isTailscale(net.ParseIP(not)) {
			t.Fatalf("%s was mistaken for a Tailscale address", not)
		}
	}
}

// Test_local_addresses_are_usable proves the list never contains loopback
// before a real address, and always has something to print.
func Test_local_addresses_are_usable(t *testing.T) {
	hosts := LocalAddresses()
	if len(hosts) == 0 {
		t.Fatal("no addresses at all")
	}
	if hosts[0] == "127.0.0.1" && len(hosts) > 1 {
		t.Fatalf("loopback was preferred over %v", hosts[1:])
	}
	firstTailscale, firstOther := -1, -1
	for index, host := range hosts {
		if isTailscale(net.ParseIP(host)) {
			if firstTailscale < 0 {
				firstTailscale = index
			}
			continue
		}
		if host != "127.0.0.1" && firstOther < 0 {
			firstOther = index
		}
	}
	if firstTailscale >= 0 && firstOther >= 0 && firstTailscale > firstOther {
		t.Fatalf("a Tailscale address came after a LAN one: %v", hosts)
	}
}

// Test_lan_address_skips_tailscale proves mDNS never advertises a tailnet
// address when the host has a LAN one.
func Test_lan_address_skips_tailscale(t *testing.T) {
	got := lanAddress([]string{"100.89.238.21", "10.134.179.6"}).String()
	if got != "10.134.179.6" {
		t.Fatalf("lanAddress = %s, want the LAN address", got)
	}
	only := lanAddress([]string{"100.89.238.21"}).String()
	if only != "100.89.238.21" {
		t.Fatalf("lanAddress with no LAN address = %s, want the Tailscale fallback", only)
	}
}

// Test_endpoints proves every host gets the same port, and that a second
// address is reported separately from the primary one.
func Test_endpoints(t *testing.T) {
	got := endpoints([]string{"100.89.238.21", "10.134.179.6"}, 7334)
	want := []string{"100.89.238.21:7334", "10.134.179.6:7334"}
	if len(got) != len(want) {
		t.Fatalf("endpoints = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("endpoints[%d] = %s, want %s", i, got[i], want[i])
		}
	}
	if text := endpointsText(got); text != "100.89.238.21:7334,10.134.179.6:7334" {
		t.Fatalf("endpointsText = %q", text)
	}
}

// Test_pairer_announces_every_address proves the announcement carries the
// primary address in `addr=` and the rest in `addrs=`, so an operator on the
// LAN and a console on the tailnet can both find their way in.
func Test_pairer_announces_every_address(t *testing.T) {
	var out bytes.Buffer
	pair, err := newPairer(time.Minute, 3, []string{"100.89.238.21:7334", "10.134.179.6:7334"}, &out)
	if err != nil {
		t.Fatalf("newPairer: %v", err)
	}
	pair.announce("")

	line := out.String()
	for _, want := range []string{
		"addr=100.89.238.21:7334",
		"addrs=100.89.238.21:7334,10.134.179.6:7334",
		"ttl=",
	} {
		if !bytes.Contains([]byte(line), []byte(want)) {
			t.Fatalf("announce line %q is missing %q", line, want)
		}
	}
}

// Test_pairer_single_address_stays_short proves a one-address host keeps the
// line free of a redundant field.
func Test_pairer_single_address_stays_short(t *testing.T) {
	var out bytes.Buffer
	pair, err := newPairer(time.Minute, 3, []string{"127.0.0.1:4040"}, &out)
	if err != nil {
		t.Fatalf("newPairer: %v", err)
	}
	pair.announce("")
	if bytes.Contains(out.Bytes(), []byte("addrs=")) {
		t.Fatalf("a single address was repeated: %q", out.String())
	}
}
