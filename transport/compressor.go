package transport

import (
	"bytes"
	"io"

	"github.com/pierrec/lz4/v4"
)

const (
	MinCompressSize   = 200
	CompressionMarker = 0x1F
)

// prioritySender is an optional extension implemented by transports that can
// schedule latency-sensitive packets ahead of bulk data. Keeping it optional
// preserves the normal Transport interface and all non-Yandex transports.
type prioritySender interface {
	SendPriority(data []byte, priority bool) error
}

type CompressedTransport struct {
	Transport
}

func NewCompressedTransport(inner Transport) Transport {
	return &CompressedTransport{Transport: inner}
}

func (c *CompressedTransport) Send(data []byte) error {
	compressed := compress(data)
	if sender, ok := c.Transport.(prioritySender); ok {
		return sender.SendPriority(compressed, isLatencySensitivePacket(data))
	}
	return c.Transport.Send(compressed)
}

func (c *CompressedTransport) Receive(callback func([]byte)) {
	c.Transport.Receive(func(data []byte) {
		decompressed, err := decompress(data)
		if err != nil {
			callback(data) // fallback
			return
		}
		callback(decompressed)
	})
}

// isLatencySensitivePacket keeps TCP control packets and small request/ACK
// packets out of a bulk-data backlog. This matters for transports such as
// Yandex Docs where many independent TCP flows share one serialized channel.
// Large payload packets remain on the normal queue so a download cannot crowd
// out DNS/TLS/HTTP setup traffic.
func isLatencySensitivePacket(data []byte) bool {
	if len(data) <= 512 {
		return true
	}

	// Raw tunnel traffic is IPv4 today. Preserve large SYN/FIN/RST packets as
	// priority too, while treating unknown payloads conservatively as bulk.
	if len(data) < 20 || data[0]>>4 != 4 || data[9] != 6 {
		return false
	}
	ihl := int(data[0]&0x0f) * 4
	if ihl < 20 || len(data) < ihl+14 {
		return false
	}
	flags := data[ihl+13]
	const tcpControlFlags = 0x02 | 0x01 | 0x04 // SYN | FIN | RST
	return flags&tcpControlFlags != 0
}

func compress(data []byte) []byte {
	if len(data) <= MinCompressSize {
		out := make([]byte, 1, len(data)+1)
		out[0] = 0x00
		out = append(out, data...)
		return out
	}

	var buf bytes.Buffer
	buf.WriteByte(CompressionMarker)

	w := lz4.NewWriter(&buf)
	w.Write(data)
	w.Close()

	if buf.Len() >= len(data)+1 {
		out := make([]byte, 1, len(data)+1)
		out[0] = 0x00
		out = append(out, data...)
		return out
	}

	return buf.Bytes()
}

func decompress(data []byte) ([]byte, error) {
	if len(data) < 1 {
		return data, nil
	}

	if data[0] == 0x00 {
		return data[1:], nil
	}

	r := lz4.NewReader(bytes.NewReader(data[1:]))
	return io.ReadAll(r)
}
