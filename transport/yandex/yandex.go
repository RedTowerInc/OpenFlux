package yandex

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"

	"universal-bypass-tool/transport"
	"universal-bypass-tool/utils"
)

const (
	yandexBatchMaxPackets = 8
	yandexWriteTimeout     = 10 * time.Second
)

var yandexBatchMagic = [5]byte{0xf7, 'O', 'F', 'B', 0x01}

const yandexBatchCapability = "---OFB1---"

type YandexDocsInfo struct {
	CookieStr   string
	Token       string
	DocID       string
	CallbackURL string
	UserID      string
	Origin      string
	Host        string
	WsURL       string
	Permissions map[string]interface{}
	OpenCmd     map[string]interface{}
}

type DocSession struct {
	Info          YandexDocsInfo
	Conn          *websocket.Conn
	WriteQueue    chan []byte
	PriorityQueue chan []byte
	UserID        string
	writeMu       sync.Mutex
}

func (s *DocSession) safeWrite(messageType int, data []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.Conn == nil {
		return fmt.Errorf("nil websocket")
	}
	_ = s.Conn.SetWriteDeadline(time.Now().Add(yandexWriteTimeout))
	err := s.Conn.WriteMessage(messageType, data)
	_ = s.Conn.SetWriteDeadline(time.Time{})
	return err
}

type YandexDocsTransport struct {
	*transport.BaseTransport

	url     string
	session *DocSession

	userCounter atomic.Int32
	baseUserID  string
	peerBatch   atomic.Int32
}

func NewYandexDocsTransport(url string, config transport.TransportConfig) *YandexDocsTransport {
	t := &YandexDocsTransport{
		BaseTransport: transport.NewBaseTransport(config),
		url:           url,
	}
	t.baseUserID = randUserID()
	return t
}

func (t *YandexDocsTransport) Start() error {
	if err := t.BaseTransport.Start(); err != nil {
		return err
	}

	t.baseUserID = randUserID()
	t.peerBatch.Store(0)
	utils.SafeGo("yandex.keepAlive", t.keepAliveLoop)
	t.connectToDoc(0)

	return nil
}

func (t *YandexDocsTransport) Send(data []byte) error {
	return t.SendPriority(data, false)
}

// SendPriority is used by CompressedTransport when the original IP packet is
// latency-sensitive. Small TCP control/request packets bypass queued bulk data,
// which prevents one large transfer from stalling DNS/TLS/HTTP setup flows.
func (t *YandexDocsTransport) SendPriority(data []byte, priority bool) error {
	if !t.IsConnected() {
		return fmt.Errorf("transport not connected")
	}

	t.Mu.RLock()
	session := t.session
	t.Mu.RUnlock()

	if session == nil {
		return fmt.Errorf("no active session")
	}

	if priority && session.PriorityQueue != nil {
		select {
		case session.PriorityQueue <- data:
			t.RecordSend(len(data))
			return nil
		default:
			// If the priority queue bursts, spill into the normal queue instead
			// of dropping a SYN/ACK/DNS/TLS packet immediately.
			select {
			case session.WriteQueue <- data:
				t.RecordSend(len(data))
				return nil
			default:
				return fmt.Errorf("yandex write queues full")
			}
		}
	}

	select {
	case session.WriteQueue <- data:
		t.RecordSend(len(data))
		return nil
	default:
		return fmt.Errorf("write queue full")
	}
}

func (t *YandexDocsTransport) connectToDoc(attempt int) {
	if !t.IsRunning() {
		return
	}

	utils.Debugf("[YDOCS] connectToDoc attempt ...")

	go func() {
		defer func() {
			if r := recover(); r != nil {
				utils.Debugf("[PANIC] recovered in yandex.connect: %v", r)
			}
		}()
		t.Mu.Lock()
		existingSession := t.session
		t.Mu.Unlock()

		var userID string
		if existingSession != nil {
			userID = existingSession.UserID
		} else {
			suffix := fmt.Sprintf("%03d", t.userCounter.Add(1)%1000)
			userID = t.baseUserID + suffix
		}

		info, err := t.fetchDocInfo(t.url, userID)
		if err != nil {
			utils.Debugf("[YDOCS] fetchDocInfo failed: %v", err)
			t.scheduleReconnect(attempt)
			return
		}

		// Hard TCP dial timeout so a stuck connect/DNS to the balancer host
		// can't hang the whole transport (HandshakeTimeout alone proved
		// insufficient on iOS).
		dialer := websocket.Dialer{
			HandshakeTimeout: 15 * time.Second,
			NetDialContext: (&net.Dialer{
				Timeout:   10 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext,
		}
		headers := http.Header{}
		headers.Set("User-Agent", "Mozilla/5.0")
		headers.Set("Origin", info.Origin)
		headers.Set("Cookie", info.CookieStr)
		headers.Set("Host", info.Host)

		utils.Debugf("[YDOCS] WebSocket dial %s", info.WsURL)
		conn, resp, err := dialer.Dial(info.WsURL, headers)
		if err != nil {
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			utils.Debugf("[YDOCS] WebSocket dial failed (http %d): %v", status, err)
			t.scheduleReconnect(attempt)
			return
		}
		utils.Debugf("[YDOCS] WebSocket connected to %s", info.Host)

		writeQueue := make(chan []byte, t.GetConfig().MaxQueueSize)
		priorityQueueSize := t.GetConfig().MaxQueueSize / 4
		if priorityQueueSize < 64 {
			priorityQueueSize = 64
		}
		priorityQueue := make(chan []byte, priorityQueueSize)
		if existingSession != nil {
			writeQueue = existingSession.WriteQueue
			if existingSession.PriorityQueue != nil {
				priorityQueue = existingSession.PriorityQueue
			}
		}

		session := &DocSession{
			Info:          info,
			Conn:          conn,
			WriteQueue:    writeQueue,
			PriorityQueue: priorityQueue,
			UserID:        userID,
		}

		t.Mu.Lock()
		t.session = session
		t.peerBatch.Store(0)
		t.SetConnected(true)
		t.Mu.Unlock()

		if existingSession == nil {
			utils.SafeGo("yandex.writer", t.writerLoop)
		}

		// Auth - use safeWrite
		auth1 := fmt.Sprintf(`40{"token":"%s"}`, info.Token)
		_ = session.safeWrite(websocket.TextMessage, []byte(auth1))

		authData := map[string]interface{}{
			"type": "auth", "docid": info.DocID, "token": "fghhfgsjdgfjs",
			"user": map[string]interface{}{"id": userID}, "editorType": 0,
			"lastOtherSaveTime": -1, "permissions": info.Permissions,
			"openCmd": info.OpenCmd, "coEditingMode": "fast", "jwtOpen": info.Token,
		}
		messagePart, _ := json.Marshal([]interface{}{"message", authData})
		_ = session.safeWrite(websocket.TextMessage, []byte(fmt.Sprintf("42%s", string(messagePart))))

		// Backward-compatible capability probe. Old peers ignore this invalid
		// base64 cursor payload; new peers answer by sending the same probe from
		// their own session. Batching is enabled only after a peer probe is seen.
		capabilityMsg := fmt.Sprintf(`42["message",{"type":"cursor","cursor":"18;%s"}]`, yandexBatchCapability)
		_ = session.safeWrite(websocket.TextMessage, []byte(capabilityMsg))

		connectedAt := time.Now()
		for t.IsRunning() {
			_, message, err := conn.ReadMessage()
			if err != nil {
				utils.Debugf("[YDOCS] Read error: %v", err)
				t.SetConnected(false)
				t.peerBatch.Store(0)
				// If the session was healthy for a while, treat the next
				// connect as fresh (attempt -1 -> next attempt 0) so backoff
				// doesn't keep growing across normal long-lived reconnects.
				next := attempt
				if time.Since(connectedAt) > 15*time.Second {
					next = -1
				}
				t.scheduleReconnect(next)
				return
			}
			t.handleMessage(session, message)
		}
	}()
}

func (t *YandexDocsTransport) writerLoop() {
	for t.IsRunning() {
		t.Mu.RLock()
		session := t.session
		t.Mu.RUnlock()

		if session == nil || session.Conn == nil {
			time.Sleep(5 * time.Millisecond)
			continue
		}

		first, ok := waitYandexPacket(session)
		if !ok {
			continue
		}

		packets := [][]byte{first}
		if t.peerBatch.Load() == 1 {
			// Opportunistic batching only: drain packets already waiting, but do
			// not add a batching delay to an otherwise idle/interactive flow.
			for len(packets) < yandexBatchMaxPackets {
				packet, available := dequeueYandexPacket(session)
				if !available {
					break
				}
				packets = append(packets, packet)
			}
		}

		wirePayload := packets[0]
		if len(packets) > 1 {
			wirePayload = encodeYandexBatch(packets)
		}
		payload := base64.StdEncoding.EncodeToString(wirePayload)
		msg := fmt.Sprintf(`42["message",{"type":"cursor","cursor":"18;%s"}]`, payload)

		if err := session.safeWrite(websocket.TextMessage, []byte(msg)); err != nil {
			utils.Debugf("[YDOCS] Write error: %v", err)
			t.SetConnected(false)
			t.peerBatch.Store(0)
			_ = session.Conn.Close() // wake reader so reconnect starts promptly
		}
	}
}

func dequeueYandexPacket(session *DocSession) ([]byte, bool) {
	if session == nil {
		return nil, false
	}
	if session.PriorityQueue != nil {
		select {
		case packet := <-session.PriorityQueue:
			return packet, true
		default:
		}
	}
	select {
	case packet := <-session.WriteQueue:
		return packet, true
	default:
		return nil, false
	}
}

func waitYandexPacket(session *DocSession) ([]byte, bool) {
	if packet, ok := dequeueYandexPacket(session); ok {
		return packet, true
	}

	timer := time.NewTimer(100 * time.Millisecond)
	defer timer.Stop()
	select {
	case packet := <-session.PriorityQueue:
		return packet, true
	case packet := <-session.WriteQueue:
		return packet, true
	case <-timer.C:
		return nil, false
	}
}

func encodeYandexBatch(packets [][]byte) []byte {
	total := len(yandexBatchMagic)
	for _, packet := range packets {
		total += 4 + len(packet)
	}
	out := make([]byte, 0, total)
	out = append(out, yandexBatchMagic[:]...)
	var length [4]byte
	for _, packet := range packets {
		binary.BigEndian.PutUint32(length[:], uint32(len(packet)))
		out = append(out, length[:]...)
		out = append(out, packet...)
	}
	return out
}

func decodeYandexBatch(data []byte) ([][]byte, bool) {
	if len(data) < len(yandexBatchMagic) || string(data[:len(yandexBatchMagic)]) != string(yandexBatchMagic[:]) {
		return nil, false
	}
	pos := len(yandexBatchMagic)
	packets := make([][]byte, 0, yandexBatchMaxPackets)
	for pos < len(data) {
		if pos+4 > len(data) {
			return nil, false
		}
		n := int(binary.BigEndian.Uint32(data[pos : pos+4]))
		pos += 4
		if n <= 0 || pos+n > len(data) {
			return nil, false
		}
		packet := make([]byte, n)
		copy(packet, data[pos:pos+n])
		packets = append(packets, packet)
		pos += n
		if len(packets) > 64 {
			return nil, false
		}
	}
	return packets, len(packets) > 0
}

func (t *YandexDocsTransport) keepAliveLoop() {
	ticker := time.NewTicker(t.GetConfig().KeepAliveInterval)
	defer ticker.Stop()
	keepAliveMsg := `42["message",{"type":"cursor","cursor":"18;---KA---"}]`

	for t.IsRunning() {
		<-ticker.C
		t.Mu.RLock()
		session := t.session
		t.Mu.RUnlock()

		if session != nil && session.Conn != nil {
			if err := session.safeWrite(websocket.TextMessage, []byte(keepAliveMsg)); err != nil {
				utils.Debugf("[YDOCS] Keep-alive failed: %v", err)
				t.SetConnected(false)
				t.peerBatch.Store(0)
			}
		}
	}
}

func (t *YandexDocsTransport) handleMessage(session *DocSession, data []byte) {
	text := string(data)

	if strings.Contains(text, "---KA---") {
		return
	}
	if strings.Contains(text, yandexBatchCapability) {
		t.peerBatch.Store(1)
		return
	}

	// Socket.IO ping - respond with pong (use safeWrite)
	if text == "2" {
		if session != nil && session.Conn != nil {
			_ = session.safeWrite(websocket.TextMessage, []byte("3"))
		}
		return
	}
	if text == "3" {
		return
	}

	if strings.Contains(text, "saveChanges") || strings.Contains(text, "cursor") {
		base64Str := t.extractBase64String(text)
		if base64Str == "" {
			return
		}

		decoded, err := base64.StdEncoding.DecodeString(base64Str)
		if err != nil {
			utils.Debugf("[YDOCS] Base64 decode error: %v", err)
			return
		}

		if packets, isBatch := decodeYandexBatch(decoded); isBatch {
			for _, packet := range packets {
				t.RecordReceive(len(packet))
				t.CallReceive(packet)
			}
			return
		}

		t.RecordReceive(len(decoded))
		t.CallReceive(decoded)
	}
}

func (t *YandexDocsTransport) extractBase64String(response string) string {
	if strings.Contains(response, "saveChanges") {
		marker := `"excelAdditionalInfo":"`
		left := strings.Index(response, marker) + len(marker)
		if left < len(marker) {
			return ""
		}
		right := strings.Index(response[left:], `"`)
		if right == -1 {
			return ""
		}
		return response[left : left+right]
	}

	re := regexp.MustCompile(`"cursor":"[^;]+;([^"]+)"`)
	matches := re.FindStringSubmatch(response)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func (t *YandexDocsTransport) scheduleReconnect(attempt int) {
	next := attempt + 1
	if !t.IsRunning() || next >= t.GetConfig().MaxReconnectAttempts {
		return
	}

	// Back off before retrying so a server that closes us immediately doesn't
	// turn into a tight connect/close loop (previously reconnect was instant).
	d := reconnectBackoff(next)
	utils.Debugf("[YDOCS] reconnecting in %v (attempt %d)", d, next)
	time.Sleep(d)
	if !t.IsRunning() {
		return
	}

	t.RecordReconnect()
	t.connectToDoc(next)
}

// reconnectBackoff returns an exponential backoff with jitter, capped at 15s.
func reconnectBackoff(n int) time.Duration {
	if n < 1 {
		n = 1
	}
	shift := n - 1
	if shift > 5 {
		shift = 5
	}
	d := 500 * time.Millisecond * time.Duration(1<<uint(shift))
	if d > 15*time.Second {
		d = 15 * time.Second
	}
	// add up to +50% jitter
	d += time.Duration(rand.Int63n(int64(d/2) + 1))
	return d
}

func (t *YandexDocsTransport) fetchDocInfo(url, userID string) (YandexDocsInfo, error) {
	client := &http.Client{
		// Cap redirects so an auth/login redirect loop fails fast instead of
		// hanging until the timeout (a private doc redirects to passport).
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects (login required? doc not public?)")
			}
			return nil
		},
		Timeout: 15 * time.Second,
	}

	utils.Debugf("[YDOCS] fetchDocInfo GET %s", url)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := client.Do(req)
	if err != nil {
		return YandexDocsInfo{}, err
	}
	defer resp.Body.Close()

	htmlBytes, _ := io.ReadAll(resp.Body)
	html := string(htmlBytes)
	utils.Debugf("[YDOCS] response status=%d finalURL=%s body=%dB", resp.StatusCode, resp.Request.URL.String(), len(html))

	var cookies []string
	for _, c := range resp.Cookies() {
		cookies = append(cookies, fmt.Sprintf("%s=%s", c.Name, c.Value))
	}

	re := regexp.MustCompile(`<script[^>]*id="client-config"[^>]*>(.*?)</script>`)
	matches := re.FindStringSubmatch(html)
	if len(matches) < 2 {
		// Help diagnose: is this a login page, a new-editor page, etc.?
		hint := "no client-config script"
		if strings.Contains(html, "passport") || strings.Contains(strings.ToLower(html), "login") {
			hint = "looks like a login page (doc not public?)"
		}
		return YandexDocsInfo{}, fmt.Errorf("config not found: %s (status %d, final %s)", hint, resp.StatusCode, resp.Request.URL.String())
	}

	var config map[string]interface{}
	if err := json.Unmarshal([]byte(matches[1]), &config); err != nil {
		return YandexDocsInfo{}, fmt.Errorf("client-config is not valid JSON: %w", err)
	}

	officeAction, ok := config["officeActionData"].(map[string]interface{})
	if !ok || officeAction == nil {
		return YandexDocsInfo{}, fmt.Errorf("officeActionData missing - will reconnect")
	}

	editorConfigRaw, ok := officeAction["editor_config"].(map[string]interface{})
	if !ok || editorConfigRaw == nil {
		return YandexDocsInfo{}, fmt.Errorf("editor_config nil - will reconnect")
	}

	balancerURL, ok := officeAction["balancer_url"].(string)
	if !ok || balancerURL == "" {
		return YandexDocsInfo{}, fmt.Errorf("officeActionData.balancer_url missing - will reconnect")
	}
	host := strings.TrimPrefix(balancerURL, "https://")

	document, ok := editorConfigRaw["document"].(map[string]interface{})
	if !ok || document == nil {
		return YandexDocsInfo{}, fmt.Errorf("editor_config.document missing - will reconnect")
	}

	token, ok := editorConfigRaw["token"].(string)
	if !ok || token == "" {
		return YandexDocsInfo{}, fmt.Errorf("editor_config.token missing - will reconnect")
	}

	docKey, ok := document["key"].(string)
	if !ok || docKey == "" {
		return YandexDocsInfo{}, fmt.Errorf("editor_config.document.key missing - will reconnect")
	}

	perms, _ := document["permissions"].(map[string]interface{})
	if perms == nil {
		perms = make(map[string]interface{})
	}

	return YandexDocsInfo{
		CookieStr:   strings.Join(cookies, "; "),
		Token:       token,
		DocID:       docKey,
		Origin:      balancerURL,
		Host:        host,
		WsURL:       fmt.Sprintf("wss://%s/2024.1.1-375/doc/%s/c/?EIO=4&transport=websocket", host, docKey),
		Permissions: perms,
		OpenCmd: map[string]interface{}{
			"c":      "open",
			"id":     docKey,
			"userid": userID,
			"format": document["fileType"],
			"url":    document["url"],
			"title":  document["title"],
			"lcid":   25,
		},
	}, nil
}

func randUserID() string {
	return fmt.Sprintf("%010d", rand.New(rand.NewSource(time.Now().UnixNano())).Intn(1000000000))
}
