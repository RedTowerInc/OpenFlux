package socks5

import (
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	"universal-bypass-tool/utils"
)

type Dialer interface {
	DialTCP(address string) (net.Conn, error)
}

type Stats struct {
	Accepted        uint64
	ConnectRequests uint64
	DialSuccess     uint64
	DialFailures    uint64
	HandshakeErrors uint64
	Active          int64
	BytesUp         uint64
	BytesDown       uint64
	LastTarget      string
	LastError       string
}

type SOCKS5Server struct {
	listenAddr string
	dialer     Dialer

	mu       sync.Mutex
	listener net.Listener
	closed   bool

	accepted        atomic.Uint64
	connectRequests atomic.Uint64
	dialSuccess     atomic.Uint64
	dialFailures    atomic.Uint64
	handshakeErrors atomic.Uint64
	active          atomic.Int64
	bytesUp         atomic.Uint64
	bytesDown       atomic.Uint64
	statsMu         sync.RWMutex
	lastTarget      string
	lastError       string
}

func NewSOCKS5Server(addr string, dialer Dialer) *SOCKS5Server {
	return &SOCKS5Server{listenAddr: addr, dialer: dialer}
}

func (s *SOCKS5Server) Bind() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if s.listener != nil {
		return nil
	}
	listener, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	s.listener = listener
	return nil
}

func (s *SOCKS5Server) Start() error {
	if err := s.Bind(); err != nil {
		return err
	}

	s.mu.Lock()
	listener := s.listener
	s.mu.Unlock()
	defer listener.Close()

	utils.Debugf("[SOCKS5] Listening on %s", s.listenAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				utils.Debugf("[SOCKS5] Listener closed, stopping")
				return net.ErrClosed
			}
			utils.Debugf("[SOCKS5] Accept error: %v", err)
			continue
		}
		s.accepted.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *SOCKS5Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *SOCKS5Server) Stats() Stats {
	s.statsMu.RLock()
	lastTarget := s.lastTarget
	lastError := s.lastError
	s.statsMu.RUnlock()
	return Stats{
		Accepted:        s.accepted.Load(),
		ConnectRequests: s.connectRequests.Load(),
		DialSuccess:     s.dialSuccess.Load(),
		DialFailures:    s.dialFailures.Load(),
		HandshakeErrors: s.handshakeErrors.Load(),
		Active:          s.active.Load(),
		BytesUp:         s.bytesUp.Load(),
		BytesDown:       s.bytesDown.Load(),
		LastTarget:      lastTarget,
		LastError:       lastError,
	}
}

func (s *SOCKS5Server) setLast(target, errText string) {
	s.statsMu.Lock()
	if target != "" {
		s.lastTarget = target
	}
	if errText != "" {
		s.lastError = errText
	}
	s.statsMu.Unlock()
}

func (s *SOCKS5Server) handshakeError(stage string, err error) {
	s.handshakeErrors.Add(1)
	text := stage
	if err != nil {
		text += ": " + err.Error()
	}
	s.setLast("", text)
	utils.Debugf("[SOCKS5] Handshake error: %s", text)
}

func (s *SOCKS5Server) handleConnection(clientConn net.Conn) {
	s.active.Add(1)
	defer s.active.Add(-1)

	defer func() {
		if r := recover(); r != nil {
			s.handshakeErrors.Add(1)
			s.setLast("", fmt.Sprintf("panic: %v", r))
			utils.Debugf("[SOCKS5] Recovered from panic in handler: %v", r)
		}
	}()
	defer clientConn.Close()

	buf := make([]byte, 256)
	n, err := clientConn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		s.handshakeError(fmt.Sprintf("greeting n=%d", n), err)
		return
	}

	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		s.handshakeError("greeting reply", err)
		return
	}

	n, err = clientConn.Read(buf)
	if err != nil || n < 10 || buf[0] != 0x05 || buf[1] != 0x01 {
		s.handshakeError(fmt.Sprintf("request n=%d", n), err)
		return
	}

	var targetAddr string
	switch buf[3] {
	case 0x01:
		targetAddr = fmt.Sprintf("%d.%d.%d.%d:%d",
			buf[4], buf[5], buf[6], buf[7],
			uint16(buf[8])<<8|uint16(buf[9]))
	case 0x03:
		domainLen := int(buf[4])
		if domainLen == 0 || 5+domainLen+2 > n {
			s.handshakeError(fmt.Sprintf("bad domain request len=%d n=%d", domainLen, n), nil)
			return
		}
		targetAddr = fmt.Sprintf("%s:%d",
			string(buf[5:5+domainLen]),
			uint16(buf[5+domainLen])<<8|uint16(buf[6+domainLen]))
	default:
		s.handshakeError(fmt.Sprintf("unsupported ATYP=%d", buf[3]), nil)
		return
	}

	s.connectRequests.Add(1)
	s.setLast(targetAddr, "")
	utils.Debugf("[SOCKS5] CONNECT %s", targetAddr)

	targetConn, err := s.dialer.DialTCP(targetAddr)
	if err != nil {
		s.dialFailures.Add(1)
		s.setLast(targetAddr, "dial: "+err.Error())
		utils.Debugf("[SOCKS5] Dial failed: %v", err)
		_, _ = clientConn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	s.dialSuccess.Add(1)
	defer targetConn.Close()

	if _, err := clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		s.setLast(targetAddr, "connect reply: "+err.Error())
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		defer targetConn.Close()
		n, copyErr := io.Copy(targetConn, clientConn)
		if n > 0 {
			s.bytesUp.Add(uint64(n))
		}
		if copyErr != nil {
			s.setLast(targetAddr, "upload copy: "+copyErr.Error())
		}
	}()

	go func() {
		defer wg.Done()
		defer clientConn.Close()
		n, copyErr := io.Copy(clientConn, targetConn)
		if n > 0 {
			s.bytesDown.Add(uint64(n))
		}
		if copyErr != nil {
			s.setLast(targetAddr, "download copy: "+copyErr.Error())
		}
	}()

	wg.Wait()
}
