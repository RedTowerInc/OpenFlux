package yandex

// Stop closes the active WebSocket explicitly. BaseTransport.Stop only changes
// state; without closing the socket, ReadMessage can remain blocked after an
// Android VPN disconnect and keep the old session alive.
func (t *YandexDocsTransport) Stop() error {
	if err := t.BaseTransport.Stop(); err != nil {
		return err
	}

	t.Mu.Lock()
	session := t.session
	t.session = nil
	t.Mu.Unlock()

	if session != nil && session.Conn != nil {
		return session.Conn.Close()
	}
	return nil
}
