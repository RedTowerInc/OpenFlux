package socks5

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"universal-bypass-tool/utils"
)

const (
	// Browsers and mobile apps can leave many pooled SOCKS connections open.
	// A global (both-directions) idle timeout keeps dead flows from accumulating
	// without killing a one-way active video/download stream.
	proxyIdleTimeout = 60 * time.Second

	// Preserve a real TCP half-close briefly so a final HTTP/TLS response can
	// drain, but never wait forever for the opposite direction to close.
	halfCloseGrace = 5 * time.Second
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
		// A successful new CONNECT must clear a stale error from an older
		// connection, otherwise the Android status screen keeps reporting a
		// harmless historical error forever.
		s.lastError = errText
	} else if errText != "" {
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

type copyResult struct {
	direction string
	dst       net.Conn
	err       error
}

type activityWriter struct {
	dst          net.Conn
	counter      *atomic.Uint64
	lastActivity *atomic.Int64
}

func (w *activityWriter) Write(p []byte) (int, error) {
	n, err := w.dst.Write(p)
	if n > 0 {
		w.counter.Add(uint64(n))
		w.lastActivity.Store(time.Now().UnixNano())
	}
	return n, err
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
	setNoDelay(clientConn)

	// SOCKS5 is a byte stream; a single Read is not guaranteed to contain a
	// complete greeting or CONNECT request. Parse each field with ReadFull so
	// packetization by tun2socks cannot create intermittent handshake failures.
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, greeting); err != nil {
		s.handshakeError("greeting header", err)
		return
	}
	if greeting[0] != 0x05 || greeting[1] == 0 {
		s.handshakeError(fmt.Sprintf("bad greeting ver=%d methods=%d", greeting[0], greeting[1]), nil)
		return
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(clientConn, methods); err != nil {
		s.handshakeError("greeting methods", err)
		return
	}
	noAuth := false
	for _, method := range methods {
		if method == 0x00 {
			noAuth = true
			break
		}
	}
	if !noAuth {
		_, _ = clientConn.Write([]byte{0x05, 0xff})
		s.handshakeError("no supported auth method", nil)
		return
	}
	if _, err := clientConn.Write([]byte{0x05, 0x00}); err != nil {
		s.handshakeError("greeting reply", err)
		return
	}

	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(clientConn, reqHeader); err != nil {
		s.handshakeError("request header", err)
		return
	}
	if reqHeader[0] != 0x05 || reqHeader[1] != 0x01 || reqHeader[2] != 0x00 {
		s.handshakeError(fmt.Sprintf("bad request ver=%d cmd=%d rsv=%d", reqHeader[0], reqHeader[1], reqHeader[2]), nil)
		return
	}

	var host string
	switch reqHeader[3] {
	case 0x01: // IPv4
		addr := make([]byte, 4)
		if _, err := io.ReadFull(clientConn, addr); err != nil {
			s.handshakeError("ipv4 address", err)
			return
		}
		host = net.IP(addr).String()
	case 0x03: // DOMAIN
		var lenBuf [1]byte
		if _, err := io.ReadFull(clientConn, lenBuf[:]); err != nil {
			s.handshakeError("domain length", err)
			return
		}
		domainLen := int(lenBuf[0])
		if domainLen == 0 {
			s.handshakeError("empty domain", nil)
			return
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(clientConn, domain); err != nil {
			s.handshakeError("domain", err)
			return
		}
		host = string(domain)
	case 0x04: // IPv6 is not carried by the current OpenFlux dataplane.
		addr := make([]byte, 16)
		port := make([]byte, 2)
		_, _ = io.ReadFull(clientConn, addr)
		_, _ = io.ReadFull(clientConn, port)
		_, _ = clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		s.handshakeError("IPv6 SOCKS target unsupported", nil)
		return
	default:
		s.handshakeError(fmt.Sprintf("unsupported ATYP=%d", reqHeader[3]), nil)
		return
	}

	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(clientConn, portBytes); err != nil {
		s.handshakeError("target port", err)
		return
	}
	port := uint16(portBytes[0])<<8 | uint16(portBytes[1])
	targetAddr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

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
	setNoDelay(targetConn)

	if _, err := clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}); err != nil {
		s.setLast(targetAddr, "connect reply: "+err.Error())
		return
	}

	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())
	results := make(chan copyResult, 2)

	go func() {
		_, copyErr := io.Copy(&activityWriter{dst: targetConn, counter: &s.bytesUp, lastActivity: &lastActivity}, clientConn)
		results <- copyResult{direction: "upload", dst: targetConn, err: copyErr}
	}()

	go func() {
		_, copyErr := io.Copy(&activityWriter{dst: clientConn, counter: &s.bytesDown, lastActivity: &lastActivity}, targetConn)
		results <- copyResult{direction: "download", dst: clientConn, err: copyErr}
	}()

	idleTicker := time.NewTicker(5 * time.Second)
	defer idleTicker.Stop()

	var first copyResult
	for {
		select {
		case first = <-results:
			goto firstFinished
		case <-idleTicker.C:
			last := time.Unix(0, lastActivity.Load())
			if time.Since(last) >= proxyIdleTimeout {
				// Both directions have been quiet for a full minute. Close both
				// sockets so pooled/dead app connections cannot grow without bound.
				_ = clientConn.Close()
				_ = targetConn.Close()
				return
			}
		}
	}

firstFinished:
	if !isExpectedClose(first.err) {
		s.setLast(targetAddr, first.direction+" copy: "+first.err.Error())
		_ = clientConn.Close()
		_ = targetConn.Close()
		select {
		case <-results:
		case <-time.After(time.Second):
		}
		return
	}

	// Let the opposite half drain a final response, but cap the grace period.
	// The previous unlimited half-close was directly observable as hundreds of
	// active SOCKS flows accumulating on Android.
	closeWrite(first.dst)
	select {
	case second := <-results:
		if !isExpectedClose(second.err) {
			s.setLast(targetAddr, second.direction+" copy: "+second.err.Error())
		}
	case <-time.After(halfCloseGrace):
		_ = clientConn.Close()
		_ = targetConn.Close()
		select {
		case <-results:
		case <-time.After(time.Second):
		}
	}
}

func setNoDelay(conn net.Conn) {
	if c, ok := conn.(interface{ SetNoDelay(bool) error }); ok {
		_ = c.SetNoDelay(true)
	}
}

func closeWrite(conn net.Conn) {
	if c, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = c.CloseWrite()
	}
}

func isExpectedClose(err error) bool {
	return err == nil || errors.Is(err, net.ErrClosed)
}
