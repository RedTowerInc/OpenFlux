package mobile

import (
	"encoding/json"
	"errors"
	"sync"

	"universal-bypass-tool/core"
)

var (
	mu     sync.Mutex
	client *core.Client
)

func Start(configJSON string) error {
	mu.Lock()
	defer mu.Unlock()

	if client != nil {
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
	defer mu.Unlock()

	if client == nil {
		return nil
	}

	err := client.Stop()
	client = nil
	return err
}

func StatusJSON() string {
	mu.Lock()
	defer mu.Unlock()

	status := core.Status{}
	if client != nil {
		status = client.Status()
	}

	data, err := json.Marshal(status)
	if err != nil {
		return `{"running":false,"lastError":"failed to encode status"}`
	}
	return string(data)
}
