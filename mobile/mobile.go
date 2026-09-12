package mobile

import (
	"encoding/json"
	"errors"
	"sync"

	"universal-bypass-tool/core"
)

var (
	mu        sync.Mutex
	client    *core.Client
	vpnClient *core.VPNClient
)

func Start(configJSON string) error {
	mu.Lock()
	defer mu.Unlock()

	if client != nil || vpnClient != nil {
		return errors.New("OpenFlux is already running")
	}

	var config core.Config
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return err
	}

	c, err := core.NewClient(config)
	if err != nil {
		return err
	}
	if err := c.Start(); err != nil {
		return err
	}

	client = c
	return nil
}

func Stop() error {
	mu.Lock()
	c := client
	client = nil
	mu.Unlock()

	if c == nil {
		return nil
	}
	return c.Stop()
}

func StatusJSON() string {
	mu.Lock()
	c := client
	mu.Unlock()

	status := core.Status{}
	if c != nil {
		status = c.Status()
	}

	data, err := json.Marshal(status)
	if err != nil {
		return `{"running":false,"lastError":"failed to encode status"}`
	}
	return string(data)
}

// StartVPN starts the direct Android TUN packet bridge. It does not expose a
// local proxy: Android feeds raw IPv4 packets via WriteVPNPacket and receives
// packets for the TUN via ReadVPNPacket.
func StartVPN(configJSON string, mtu int) error {
	mu.Lock()
	defer mu.Unlock()

	if client != nil || vpnClient != nil {
		return errors.New("OpenFlux is already running")
	}

	var config core.Config
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return err
	}

	c, err := core.NewVPNClient(config, uint32(mtu))
	if err != nil {
		return err
	}
	if err := c.Start(); err != nil {
		return err
	}

	vpnClient = c
	return nil
}

func StopVPN() error {
	mu.Lock()
	c := vpnClient
	vpnClient = nil
	mu.Unlock()

	if c == nil {
		return nil
	}
	return c.Stop()
}

func WriteVPNPacket(packet []byte) error {
	mu.Lock()
	c := vpnClient
	mu.Unlock()
	if c == nil {
		return errors.New("OpenFlux VPN is not running")
	}
	return c.WritePacket(packet)
}

// ReadVPNPacket intentionally does not hold the package mutex while blocking;
// StopVPN must be able to acquire the lock and cancel the pending read.
func ReadVPNPacket() []byte {
	mu.Lock()
	c := vpnClient
	mu.Unlock()
	if c == nil {
		return nil
	}
	return c.ReadPacket()
}

func StatusVPNJSON() string {
	mu.Lock()
	c := vpnClient
	mu.Unlock()

	status := core.Status{}
	if c != nil {
		status = c.Status()
	}
	data, err := json.Marshal(status)
	if err != nil {
		return `{"running":false,"lastError":"failed to encode status"}`
	}
	return string(data)
}
