package transport

import "testing"

func TestLatencySensitiveSmallPacket(t *testing.T) {
	if !isLatencySensitivePacket(make([]byte, 128)) {
		t.Fatal("small packets should be latency-sensitive")
	}
}

func TestLatencySensitiveLargeSyn(t *testing.T) {
	packet := make([]byte, 900)
	packet[0] = 0x45 // IPv4, 20-byte header
	packet[9] = 6    // TCP
	packet[20+13] = 0x02 // SYN
	if !isLatencySensitivePacket(packet) {
		t.Fatal("TCP SYN should be latency-sensitive even when packet is large")
	}
}

func TestLatencySensitiveLargeDataIsBulk(t *testing.T) {
	packet := make([]byte, 1400)
	packet[0] = 0x45
	packet[9] = 6
	packet[20+13] = 0x18 // PSH|ACK
	if isLatencySensitivePacket(packet) {
		t.Fatal("large TCP data packet should stay on the bulk queue")
	}
}
