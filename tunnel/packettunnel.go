package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"universal-bypass-tool/utils"
)

const (
	dnsTypeAAAA  uint16 = 28
	dnsTypeSVCB  uint16 = 64
	dnsTypeHTTPS uint16 = 65
)

// TCPDialer originates a TCP connection to address ("host:port") through some
// upstream (here: the OpenFlux transport tunnel to the exit node).
type TCPDialer interface {
	DialTCP(address string) (net.Conn, error)
}

// PacketTunnel is a userspace TCP/IP stack for Android/iOS TUN packets. It
// terminates device TCP flows locally and forwards each flow through OpenFlux.
//
// OpenFlux is currently IPv4/TCP-only. DNS is accepted over UDP/53 from the
// device and resolved over the tunnel. IPv6-oriented DNS records are answered
// locally with NODATA so Android apps do not waste seconds trying IPv6 paths
// that this MVP deliberately black-holes. This is especially important for
// browsers and apps that use Happy Eyeballs and HTTPS/SVCB records.
type PacketTunnel struct {
	stack  *stack.Stack
	ep     *channel.Endpoint
	dialer TCPDialer
	nicID  tcpip.NICID
}

// NewPacketTunnel builds the stack and installs TCP + DNS forwarders.
func NewPacketTunnel(dialer TCPDialer, mtu uint32) *PacketTunnel {
	s := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol},
	})

	SetTCPBuffers(s)

	ep := channel.New(256, mtu, "")
	nicID := tcpip.NICID(1)
	if err := s.CreateNIC(nicID, ep); err != nil {
		utils.Debugf("[PKT] CreateNIC: %v", err)
	}
	// Accept packets addressed to any destination and let the stack answer
	// with any source address (we are terminating arbitrary device traffic).
	s.SetPromiscuousMode(nicID, true)
	s.SetSpoofing(nicID, true)
	s.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})

	pt := &PacketTunnel{stack: s, ep: ep, dialer: dialer, nicID: nicID}

	tcpFwd := tcp.NewForwarder(s, 0, 2048, pt.handleTCP)
	s.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)

	udpFwd := udp.NewForwarder(s, pt.handleUDP)
	s.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	return pt
}

func (pt *PacketTunnel) handleTCP(r *tcp.ForwarderRequest) {
	id := r.ID()
	dest := fmt.Sprintf("%s:%d", id.LocalAddress.String(), id.LocalPort)

	var wq waiter.Queue
	ep, tErr := r.CreateEndpoint(&wq)
	if tErr != nil {
		utils.Debugf("[PKT] CreateEndpoint %s: %v", dest, tErr)
		r.Complete(true)
		return
	}
	r.Complete(false)
	local := gonet.NewTCPConn(&wq, ep)

	utils.SafeGo("pkt.flow", func() {
		remote, err := pt.dialer.DialTCP(dest)
		if err != nil {
			utils.Debugf("[PKT] dial %s failed: %v", dest, err)
			local.Close()
			return
		}
		// Splice both directions; close when either side ends.
		go func() {
			_, _ = io.Copy(remote, local)
			_ = remote.Close()
			_ = local.Close()
		}()
		_, _ = io.Copy(local, remote)
		_ = local.Close()
		_ = remote.Close()
	})
}

// handleUDP serves DNS only. Other UDP is intentionally not carried by the
// current OpenFlux protocol; apps should fall back to TCP when UDP/QUIC fails.
func (pt *PacketTunnel) handleUDP(r *udp.ForwarderRequest) bool {
	id := r.ID()
	if id.LocalPort != 53 {
		return false
	}

	var wq waiter.Queue
	ep, err := r.CreateEndpoint(&wq)
	if err != nil {
		utils.Debugf("[PKT] UDP CreateEndpoint: %v", err)
		return true
	}
	conn := gonet.NewUDPConn(&wq, ep)
	dest := fmt.Sprintf("%s:53", id.LocalAddress.String())

	utils.SafeGo("pkt.dns", func() {
		defer conn.Close()
		buf := make([]byte, 4096)
		for {
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			n, err := conn.Read(buf)
			if err != nil || n == 0 {
				return
			}

			query := append([]byte(nil), buf[:n]...)
			if shouldSuppressDNSQuery(query) {
				if resp, ok := makeDNSNoDataResponse(query); ok {
					utils.Debugf("[PKT] DNS compatibility NODATA qtype=%d", firstDNSQType(query))
					_, _ = conn.Write(resp)
					continue
				}
			}

			resp, err := pt.resolveDNS(dest, query)
			if err != nil {
				utils.Debugf("[PKT] DNS resolution failed: %v", err)
				return
			}
			if _, err := conn.Write(resp); err != nil {
				return
			}
		}
	})
	return true
}

// resolveDNS prefers normal DNS-over-TCP to the DNS address Android selected,
// then falls back to Google DNS-over-TCP and finally Cloudflare DoH over 443.
// All three paths still go through OpenFlux/the exit node.
func (pt *PacketTunnel) resolveDNS(dest string, query []byte) ([]byte, error) {
	tried := make([]string, 0, 3)

	if dest != "" {
		tried = append(tried, dest)
		if resp, err := pt.dnsOverTCPOnce(dest, query, 2500*time.Millisecond); err == nil {
			return resp, nil
		} else {
			utils.Debugf("[PKT] DNS/TCP %s failed: %v", dest, err)
		}
	}

	if dest != "8.8.8.8:53" {
		tried = append(tried, "8.8.8.8:53")
		if resp, err := pt.dnsOverTCPOnce("8.8.8.8:53", query, 2500*time.Millisecond); err == nil {
			return resp, nil
		} else {
			utils.Debugf("[PKT] DNS/TCP 8.8.8.8:53 failed: %v", err)
		}
	}

	tried = append(tried, "Cloudflare DoH 1.1.1.1:443")
	if resp, err := pt.dnsOverHTTPS(query); err == nil {
		return resp, nil
	} else {
		return nil, fmt.Errorf("all DNS paths failed (%v): %w", tried, err)
	}
}

// dnsOverTCP sends a DNS query to dest over TCP using RFC 7766 framing.
func (pt *PacketTunnel) dnsOverTCP(dest string, query []byte) ([]byte, error) {
	return pt.dnsOverTCPOnce(dest, query, 4*time.Second)
}

func (pt *PacketTunnel) dnsOverTCPOnce(dest string, query []byte, timeout time.Duration) ([]byte, error) {
	c, err := pt.dialer.DialTCP(dest)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(timeout))

	var lp [2]byte
	binary.BigEndian.PutUint16(lp[:], uint16(len(query)))
	if _, err := c.Write(lp[:]); err != nil {
		return nil, err
	}
	if _, err := c.Write(query); err != nil {
		return nil, err
	}

	hdr := make([]byte, 2)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, err
	}
	respLen := int(binary.BigEndian.Uint16(hdr))
	if respLen == 0 || respLen > 65535 {
		return nil, fmt.Errorf("invalid DNS response length: %d", respLen)
	}
	resp := make([]byte, respLen)
	if _, err := io.ReadFull(c, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// dnsOverHTTPS is a bootstrap-safe DoH fallback: the HTTP connection is dialed
// directly to Cloudflare's 1.1.1.1 IP through OpenFlux, while TLS validates the
// cloudflare-dns.com hostname. No local/mobile DNS lookup is needed.
func (pt *PacketTunnel) dnsOverHTTPS(query []byte) ([]byte, error) {
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return pt.dialer.DialTCP("1.1.1.1:443")
		},
		TLSClientConfig: &tls.Config{
			ServerName: "cloudflare-dns.com",
			MinVersion: tls.VersionTLS12,
		},
		ForceAttemptHTTP2: false,
		DisableKeepAlives: true,
	}
	defer tr.CloseIdleConnections()

	client := &http.Client{Transport: tr, Timeout: 6 * time.Second}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://cloudflare-dns.com/dns-query", bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, err
	}
	if len(data) < 12 {
		return nil, fmt.Errorf("short DoH response: %d bytes", len(data))
	}
	return data, nil
}

// IPv4/TCP compatibility: do not hand apps AAAA or SVCB/HTTPS answers while the
// tunnel cannot carry IPv6 or QUIC. NODATA makes browsers/apps use A + TCP now
// instead of waiting through long IPv6/HTTP3 fallback timers.
func shouldSuppressDNSQuery(query []byte) bool {
	qtype := firstDNSQType(query)
	return qtype == dnsTypeAAAA || qtype == dnsTypeSVCB || qtype == dnsTypeHTTPS
}

func firstDNSQType(query []byte) uint16 {
	_, qtype, ok := firstDNSQuestion(query)
	if !ok {
		return 0
	}
	return qtype
}

func firstDNSQuestion(query []byte) (end int, qtype uint16, ok bool) {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return 0, 0, false
	}

	i := 12
	for {
		if i >= len(query) {
			return 0, 0, false
		}
		labelLen := int(query[i])
		i++
		if labelLen == 0 {
			break
		}
		if labelLen&0xc0 == 0xc0 {
			if i >= len(query) {
				return 0, 0, false
			}
			i++
			break
		}
		if labelLen&0xc0 != 0 || i+labelLen > len(query) {
			return 0, 0, false
		}
		i += labelLen
	}

	if i+4 > len(query) {
		return 0, 0, false
	}
	qtype = binary.BigEndian.Uint16(query[i : i+2])
	return i + 4, qtype, true
}

func makeDNSNoDataResponse(query []byte) ([]byte, bool) {
	end, _, ok := firstDNSQuestion(query)
	if !ok {
		return nil, false
	}

	resp := append([]byte(nil), query[:end]...)
	reqFlags := binary.BigEndian.Uint16(resp[2:4])
	// QR=1, RA=1, preserve opcode and RD. RCODE=NOERROR with ANCOUNT=0.
	flags := uint16(0x8000 | 0x0080)
	flags |= reqFlags & 0x7900
	binary.BigEndian.PutUint16(resp[2:4], flags)
	binary.BigEndian.PutUint16(resp[6:8], 0)  // ANCOUNT
	binary.BigEndian.PutUint16(resp[8:10], 0) // NSCOUNT
	binary.BigEndian.PutUint16(resp[10:12], 0) // ARCOUNT
	return resp, true
}

// WriteInbound injects one IPv4 packet coming from the device into the stack.
func (pt *PacketTunnel) WriteInbound(ipPacket []byte) {
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{
		Payload: buffer.MakeWithData(append([]byte{}, ipPacket...)),
	})
	pt.ep.InjectInbound(ipv4.ProtocolNumber, pkt)
	pkt.DecRef()
}

// ReadOutbound blocks until the stack has a packet to deliver to the device,
// returning its bytes, or nil if ctx is cancelled / the tunnel is closed.
func (pt *PacketTunnel) ReadOutbound(ctx context.Context) []byte {
	p := pt.ep.ReadContext(ctx)
	if p == nil {
		return nil
	}
	data := p.ToView().ToSlice()
	p.DecRef()
	return data
}

func (pt *PacketTunnel) Close() {
	pt.ep.Close()
	pt.stack.Close()
}
