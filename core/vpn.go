package core

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/tunnel"
)

const defaultVPNMTU uint32 = 1500

// VPNClient connects Android's TUN packet stream to the existing OpenFlux TCP
// tunnel. PacketTunnel terminates device TCP flows in userspace and dials them
// through TCPTunnel. DNS/UDP 53 is converted to DNS-over-TCP through OpenFlux;
// other UDP is intentionally unsupported by the current TCP-only protocol.
type VPNClient struct {
	mu sync.RWMutex

	config Config
	mtu    uint32

	transport       transport.Transport
	transportTunnel *tunnel.TCPTunnel
	packetTunnel    *tunnel.PacketTunnel
	ctx             context.Context
	cancel          context.CancelFunc

	running   bool
	startedAt time.Time
	lastError string
}

func NewVPNClient(config Config, mtu uint32) (*VPNClient, error) {
	config = normalizeConfig(config)
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	if mtu == 0 {
		mtu = defaultVPNMTU
	}
	if mtu < 576 || mtu > 9000 {
		return nil, fmt.Errorf("invalid MTU: %d", mtu)
	}
	return &VPNClient{config: config, mtu: mtu}, nil
}

func (c *VPNClient) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return errors.New("OpenFlux VPN client is already running")
	}

	trans, err := buildTransport(c.config)
	if err != nil {
		c.lastError = err.Error()
		return err
	}
	if err := trans.Start(); err != nil {
		c.lastError = err.Error()
		return fmt.Errorf("start transport: %w", err)
	}

	transportTunnel := tunnel.NewTCPTunnel(trans, false)
	packetTunnel := tunnel.NewPacketTunnel(transportTunnel, c.mtu)
	ctx, cancel := context.WithCancel(context.Background())

	c.transport = trans
	c.transportTunnel = transportTunnel
	c.packetTunnel = packetTunnel
	c.ctx = ctx
	c.cancel = cancel
	c.running = true
	c.startedAt = time.Now()
	c.lastError = ""
	return nil
}

func (c *VPNClient) WritePacket(packet []byte) error {
	if len(packet) == 0 {
		return nil
	}
	if packet[0]>>4 != 4 {
		// IPv6 is deliberately black-holed by the Android MVP to prevent leaks
		// until OpenFlux gains IPv6 support.
		return nil
	}

	c.mu.RLock()
	pt := c.packetTunnel
	running := c.running
	c.mu.RUnlock()
	if !running || pt == nil {
		return errors.New("OpenFlux VPN client is not running")
	}

	pt.WriteInbound(packet)
	return nil
}

// ReadPacket blocks until the userspace stack has a packet for Android's TUN,
// or returns nil when Stop cancels the VPN.
func (c *VPNClient) ReadPacket() []byte {
	c.mu.RLock()
	pt := c.packetTunnel
	ctx := c.ctx
	running := c.running
	c.mu.RUnlock()
	if !running || pt == nil || ctx == nil {
		return nil
	}
	return pt.ReadOutbound(ctx)
}

func (c *VPNClient) Stop() error {
	c.mu.Lock()
	if !c.running && c.transport == nil {
		c.mu.Unlock()
		return nil
	}

	cancel := c.cancel
	packetTunnel := c.packetTunnel
	transportTunnel := c.transportTunnel
	trans := c.transport

	c.running = false
	c.cancel = nil
	c.ctx = nil
	c.packetTunnel = nil
	c.transportTunnel = nil
	c.transport = nil
	c.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	if packetTunnel != nil {
		packetTunnel.Close()
	}
	if transportTunnel != nil {
		transportTunnel.Close()
	}
	if trans != nil {
		if err := trans.Stop(); err != nil {
			c.mu.Lock()
			c.lastError = err.Error()
			c.mu.Unlock()
			return fmt.Errorf("stop transport: %w", err)
		}
	}
	return nil
}

func (c *VPNClient) Status() Status {
	c.mu.RLock()
	defer c.mu.RUnlock()

	status := Status{
		Running:   c.running,
		Transport: c.config.Transport,
		LastError: c.lastError,
	}
	if c.running && !c.startedAt.IsZero() {
		status.UptimeSeconds = int64(time.Since(c.startedAt).Seconds())
	}
	if c.transport != nil {
		stats := c.transport.Stats()
		status.Connected = stats.Connected
		status.BytesSent = stats.BytesSent
		status.BytesReceived = stats.BytesReceived
		status.PacketsSent = stats.PacketsSent
		status.PacketsRecv = stats.PacketsRecv
		status.Reconnects = stats.Reconnects
	}
	return status
}
