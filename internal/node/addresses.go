package node

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

// tailscaleRange is the CGNAT block Tailscale hands out (100.64.0.0/10).
var tailscaleRange = &net.IPNet{IP: net.IPv4(100, 64, 0, 0), Mask: net.CIDRMask(10, 32)}

// isTailscale reports whether an address is a Tailscale one.
func isTailscale(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && tailscaleRange.Contains(v4)
}

// localAddresses lists the addresses a console can dial, best first.
//
// Tailscale addresses come first: they stay the same when the machine moves
// between networks and are reachable from every device on the tailnet, so a
// console anywhere can pair without an operator copying a LAN address that will
// be stale by the next coffee. LAN addresses follow, and loopback is the
// fallback for a host with nothing else (a container, or a laptop offline).
func LocalAddresses() []string {
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return []string{"127.0.0.1"}
	}

	type candidate struct {
		text      string
		tailscale bool
	}
	var found []candidate
	seen := make(map[string]bool)
	for _, address := range addresses {
		network, ok := address.(*net.IPNet)
		if !ok {
			continue
		}
		ip := network.IP.To4()
		if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
			continue
		}
		text := ip.String()
		if seen[text] {
			continue
		}
		seen[text] = true
		found = append(found, candidate{text: text, tailscale: isTailscale(ip)})
	}

	// InterfaceAddrs is already ordered by interface index, and the sort is
	// stable, so Tailscale first while everything else keeps kernel order.
	sort.SliceStable(found, func(i, j int) bool {
		return found[i].tailscale && !found[j].tailscale
	})

	out := make([]string, 0, len(found)+1)
	for _, item := range found {
		out = append(out, item.text)
	}
	if len(out) == 0 {
		out = append(out, "127.0.0.1")
	}
	return out
}

// lanAddress picks the address a local network can reach, which is the one an
// mDNS answer must carry. A tailnet address is useless to a multicast peer, so
// it is only used when the host has nothing else.
func lanAddress(hosts []string) net.IP {
	for _, host := range hosts {
		if ip := net.ParseIP(host); ip != nil && !isTailscale(ip) {
			return ip
		}
	}
	if len(hosts) > 0 {
		return net.ParseIP(hosts[0])
	}
	return net.IPv4(127, 0, 0, 1)
}

// endpoints appends the port to every host, for the pairing announcement.
func endpoints(hosts []string, port int) []string {
	portText := strconv.Itoa(port)
	out := make([]string, 0, len(hosts))
	for _, host := range hosts {
		out = append(out, net.JoinHostPort(host, portText))
	}
	return out
}

// endpointsText is the `addrs=` field: every address, comma separated.
func endpointsText(addrs []string) string {
	return strings.Join(addrs, ",")
}
