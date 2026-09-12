package core

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"universal-bypass-tool/socks5"
	"universal-bypass-tool/transport"
	"universal-bypass-tool/transport/oneme"
	"universal-bypass-tool/transport/yandex"
	"universal-bypass-tool/tunnel"
	"universal-bypass-tool/utils"
)

const defaultSocksAddress = "127.0.0.1:1080"

type Config struct {
	Transport    string `json:"transport"`
	YandexURL    string `json:"yandexUrl"`
	MaxToken     string `json:"maxToken"`
	MaxUID       string `json:"maxUid"`
	SocksAddress string `json:"socksAddress"`
	Debug        bool   `json:"debug"`
}

type Status struct {
	Running       bool   `json:"running"`
	Transport     string `json:"transport"`
	Connected     bool   `json:"connected"`
	BytesSent     uint64 `json:"bytesSent"`
	BytesReceived uint64 `json:"bytesReceived"`
	PacketsSent   uint64 `json:"packetsSent"`
	PacketsRecv   uint64 `json:"packetsReceived"`
	Reconnects    uint64 `json:"reconnects"`
	UptimeSeconds int64  `json:"uptimeSeconds"`
	LastError     string `json:"lastError,omitempty"`
}

type Client struct {
	mu sync.RWMutex

	config Config

	transport transport.Transport
	tunnel    *tunnel.TCPTunnel
	socks     *socks5.SOCKS5Server

	running   bool
	startedAt time.Time
	lastError string
}

func NewClient(config Config) (*Client, error) {
	config = normalizeConfig(config)
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	return &Client{config: config}, nil
}

func normalizeConfig(config Config) Config {
	config.Transport = strings.ToLower(strings.TrimSpace(config.Transport))
	if config.Transport == "" {
		config.Transport = "yandex"
	}
	if strings.TrimSpace(config.SocksAddress) == "" {
		config.SocksAddress = defaultSocksAddress
	}
	config.YandexURL = strings.TrimSpace(config.YandexURL)
	config.MaxToken = strings.TrimSpace(config.MaxToken)
	config.MaxUID = strings.TrimSpace(config.MaxUID)
	return config
}

func validateConfig(config Config) error {
	switch config.Transport {
	case "yandex":
		if config.YandexURL == "" {
			return errors.New("yandex transport requires yandexUrl")
		}
		u, err := url.Parse(config.YandexURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("invalid yandexUrl: %q", config.YandexURL)
		}
	case "oneme", "max":
		if config.MaxToken == "" {
			return errors.New("MAX transport requires maxToken")
		}
		if _, err := strconv.ParseInt(config.MaxUID, 10, 64); err != nil {
			return fmt.Errorf("MAX transport requires numeric maxUid: %w", err)
		}
	default:
		return fmt.Errorf("unsupported transport %q", config.Transport)
	}
	return nil
}

func (c *Client) Start() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return errors.New("OpenFlux client is already running")
	}

	if c.config.Debug {
		utils.EnableDebug()
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

	tun := tunnel.NewTCPTunnel(trans, false)
	socksServer := socks5.NewSOCKS5Server(c.config.SocksAddress, tun)
	if err := socksServer.Bind(); err != nil {
		tun.Close()
		_ = trans.Stop()
		c.lastError = err.Error()
		return fmt.Errorf("bind SOCKS5: %w", err)
	}

	c.transport = trans
	c.tunnel = tun
	c.socks = socksServer
	c.running = true
	c.startedAt = time.Now()
	c.lastError = ""

	go func() {
		err := socksServer.Start()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			c.mu.Lock()
			c.lastError = fmt.Sprintf("SOCKS5 stopped: %v", err)
			c.running = false
			c.mu.Unlock()
		}
	}()

	return nil
}

func (c *Client) Stop() error {
	c.mu.Lock()
	if !c.running && c.socks == nil && c.transport == nil {
		c.mu.Unlock()
		return nil
	}

	socksServer := c.socks
	tun := c.tunnel
	trans := c.transport

	c.running = false
	c.socks = nil
	c.tunnel = nil
	c.transport = nil
	c.mu.Unlock()

	var errs []error
	if socksServer != nil {
		if err := socksServer.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			errs = append(errs, fmt.Errorf("stop SOCKS5: %w", err))
		}
	}
	if tun != nil {
		tun.Close()
	}
	if trans != nil {
		if err := trans.Stop(); err != nil {
			errs = append(errs, fmt.Errorf("stop transport: %w", err))
		}
	}

	if len(errs) > 0 {
		err := errors.Join(errs...)
		c.mu.Lock()
		c.lastError = err.Error()
		c.mu.Unlock()
		return err
	}
	return nil
}

func (c *Client) Status() Status {
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

func buildTransport(config Config) (transport.Transport, error) {
	transportConfig := transport.DefaultConfig()

	switch config.Transport {
	case "yandex":
		return transport.NewCompressedTransport(
			yandex.NewYandexDocsTransport(config.YandexURL, transportConfig),
		), nil
	case "oneme", "max":
		uid, err := strconv.ParseInt(config.MaxUID, 10, 64)
		if err != nil {
			return nil, err
		}
		return transport.NewCompressedTransport(
			oneme.NewOneMeTransport(false, config.MaxToken, uid, transportConfig),
		), nil
	default:
		return nil, fmt.Errorf("unsupported transport %q", config.Transport)
	}
}
