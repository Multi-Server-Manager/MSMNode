// Package mdns advertises the node over multicast DNS (PROTOCOL.md §9).
//
// It is deliberately small: one service type, one instance, and only the record
// types a console needs to reach the node (PTR, SRV, TXT, A). It answers
// queries and announces itself once at startup.
package mdns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

const (
	// Service is the DNS-SD service type a console browses for.
	Service = "_msm-node._tcp.local."
	// TTL is the record lifetime, in seconds.
	TTL = 120

	groupAddress = "224.0.0.251:5353"
	typeA        = 1
	typePTR      = 12
	typeTXT      = 16
	typeSRV      = 33
	classIN      = 1
	classFlush   = 0x8000
)

// Advertiser answers mDNS queries for one node.
type Advertiser struct {
	instance string
	port     int
	address  net.IP
	iface    *net.Interface
	records  []string
}

// New builds an advertiser, choosing the address a local network can reach.
//
// A host with Tailscale has a 100.64/10 address as well; that one is useless to
// a multicast peer, so it is skipped when anything else is available.
func New(instance string, port int, nodeID, spki string) (*Advertiser, error) {
	address, err := localIPv4()
	if err != nil {
		return nil, err
	}
	return NewAt(instance, port, address, nodeID, spki)
}

// NewAt builds an advertiser that answers with a specific address.
//
// The address's own interface is joined, so a machine whose default route is a
// Tailscale tunnel still hears the multicast queries arriving on its LAN.
func NewAt(instance string, port int, address net.IP, nodeID, spki string) (*Advertiser, error) {
	label := sanitize(instance)
	if label == "" {
		return nil, errors.New("mdns: the instance name is empty")
	}
	if v4 := address.To4(); v4 != nil {
		address = v4
	} else {
		return nil, errors.New("mdns: the advertised address is not IPv4")
	}
	return &Advertiser{
		instance: label,
		port:     port,
		address:  address,
		iface:    interfaceFor(address),
		records:  []string{"id=" + nodeID, "spki=" + spki, "v=1"},
	}, nil
}

// Run answers queries until the context is cancelled.
func (a *Advertiser) Run(ctx context.Context) error {
	group, err := net.ResolveUDPAddr("udp4", groupAddress)
	if err != nil {
		return err
	}
	conn, err := net.ListenMulticastUDP("udp4", a.iface, group)
	if err != nil {
		return fmt.Errorf("mdns: cannot join %s: %w", groupAddress, err)
	}
	defer conn.Close()

	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()

	a.announce()

	packet := make([]byte, 1500)
	for {
		count, source, readErr := conn.ReadFromUDP(packet)
		if readErr != nil {
			if ctx.Err() != nil {
				return nil
			}
			return readErr
		}
		if count < 12 || !queriesForService(packet[:count]) {
			continue
		}
		a.reply(conn, source)
	}
}

// announce sends one unsolicited response to the group.
func (a *Advertiser) announce() {
	group, err := net.ResolveUDPAddr("udp4", groupAddress)
	if err != nil {
		return
	}
	conn, err := net.DialUDP("udp4", nil, group)
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write(a.response())
}

// reply answers one query, unicast when the querier used an ephemeral port and
// multicast when it queried from 5353 (RFC 6762 §6.7).
func (a *Advertiser) reply(conn *net.UDPConn, source *net.UDPAddr) {
	target := source
	if source.Port == 5353 {
		group, err := net.ResolveUDPAddr("udp4", groupAddress)
		if err != nil {
			return
		}
		target = group
	}
	_, _ = conn.WriteToUDP(a.response(), target)
}

// response builds a PTR/SRV/TXT/A answer set for this node.
func (a *Advertiser) response() []byte {
	instance := a.instance + "." + Service
	host := a.instance + ".local."

	answers := [][]byte{
		a.record(Service, typePTR, classIN, nameData(instance)),
		a.record(instance, typeSRV, classIN|classFlush, srvData(0, 0, uint16(a.port), host)),
		a.record(instance, typeTXT, classIN|classFlush, txtData(a.records)),
		a.record(host, typeA, classIN|classFlush, a.address.To4()),
	}

	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[2:], 0x8400) // response, authoritative
	binary.BigEndian.PutUint16(packet[6:], uint16(len(answers)))
	for _, answer := range answers {
		packet = append(packet, answer...)
	}
	return packet
}

// record renders one resource record.
func (a *Advertiser) record(name string, kind uint16, class uint16, data []byte) []byte {
	out := appendName(nil, name)
	out = binary.BigEndian.AppendUint16(out, kind)
	out = binary.BigEndian.AppendUint16(out, class)
	out = binary.BigEndian.AppendUint32(out, TTL)
	out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
	return append(out, data...)
}

func nameData(name string) []byte { return appendName(nil, name) }

func srvData(priority, weight, port uint16, target string) []byte {
	out := binary.BigEndian.AppendUint16(nil, priority)
	out = binary.BigEndian.AppendUint16(out, weight)
	out = binary.BigEndian.AppendUint16(out, port)
	return appendName(out, target)
}

func txtData(records []string) []byte {
	var out []byte
	for _, record := range records {
		out = append(out, byte(len(record)))
		out = append(out, record...)
	}
	return out
}

// appendName writes a dotted name as length-prefixed labels.
func appendName(out []byte, name string) []byte {
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if label == "" {
			continue
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	return append(out, 0)
}

// queriesForService reports whether a packet asks for our service type.
func queriesForService(packet []byte) bool {
	flags := binary.BigEndian.Uint16(packet[2:])
	if flags&0x8000 != 0 {
		return false // a response, not a query
	}
	if binary.BigEndian.Uint16(packet[4:]) == 0 {
		return false
	}

	name, _, ok := readName(packet, 12)
	if !ok {
		return false
	}
	// A console browses the service type; a resolver refreshing a known host
	// asks for the instance name directly.
	return strings.EqualFold(name, Service) ||
		strings.HasSuffix(strings.ToLower(name), strings.ToLower(Service))
}

// readName decodes a possibly compressed DNS name.
func readName(packet []byte, start int) (string, int, bool) {
	var labels []string
	offset := start
	next := start
	jumps := 0

	for {
		if offset >= len(packet) {
			return "", 0, false
		}
		length := int(packet[offset])
		switch {
		case length == 0:
			if jumps == 0 {
				next = offset + 1
			}
			return strings.Join(labels, ".") + ".", next, true
		case length&0xC0 == 0xC0:
			if offset+1 >= len(packet) || jumps > 8 {
				return "", 0, false
			}
			pointer := int(binary.BigEndian.Uint16(packet[offset:]) & 0x3FFF)
			if jumps == 0 {
				next = offset + 2
			}
			jumps++
			offset = pointer
		default:
			if offset+1+length > len(packet) {
				return "", 0, false
			}
			labels = append(labels, string(packet[offset+1:offset+1+length]))
			offset += 1 + length
		}
	}
}

// sanitize keeps an instance label inside what DNS allows.
func sanitize(instance string) string {
	var out strings.Builder
	for _, r := range instance {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-':
			out.WriteRune(r)
		case r == '.' || r == '_' || r == ' ':
			out.WriteRune('-')
		}
	}
	return strings.Trim(out.String(), "-")
}

// localIPv4 returns the first non-loopback IPv4 address on this host,
// preferring one a local network can reach over a Tailscale one.
func localIPv4() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var fallback net.IP
	for _, addr := range addrs {
		network, ok := addr.(*net.IPNet)
		if !ok || network.IP.IsLoopback() || network.IP.IsLinkLocalUnicast() {
			continue
		}
		ip := network.IP.To4()
		if ip == nil {
			continue
		}
		if isTailscale(ip) {
			if fallback == nil {
				fallback = ip
			}
			continue
		}
		return ip, nil
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, errors.New("mdns: no non-loopback IPv4 address")
}

// tailscaleRange is the address block Tailscale uses (100.64.0.0/10).
var tailscaleRange = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

func isTailscale(ip net.IP) bool { return tailscaleRange.Contains(ip) }

// interfaceFor finds the interface that owns an address, or nil for the
// kernel's default multicast interface.
func interfaceFor(address net.IP) *net.Interface {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addresses {
			network, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			if network.IP.Equal(address) {
				candidate := iface
				return &candidate
			}
		}
	}
	return nil
}

// Probe asks the network once and returns how many answers arrived, which is
// what the end-to-end suite uses to check the advertiser is alive.
func Probe(timeout time.Duration) int {
	conn, err := net.Dial("udp4", groupAddress)
	if err != nil {
		return 0
	}
	defer conn.Close()
	_, _ = conn.Write(queryPacket())
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	count := 0
	buffer := make([]byte, 1500)
	for {
		n, err := conn.Read(buffer)
		if err != nil {
			return count
		}
		if n > 12 && binary.BigEndian.Uint16(buffer[6:]) > 0 {
			count++
		}
	}
}

// queryPacket is a PTR question for the service type.
func queryPacket() []byte {
	packet := make([]byte, 12)
	binary.BigEndian.PutUint16(packet[4:], 1) // one question
	packet = appendName(packet, Service)
	packet = binary.BigEndian.AppendUint16(packet, typePTR)
	return binary.BigEndian.AppendUint16(packet, classIN)
}
