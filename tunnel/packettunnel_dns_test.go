package tunnel

import (
	"encoding/binary"
	"testing"
)

func makeDNSQuery(name string, qtype uint16) []byte {
	msg := make([]byte, 12)
	binary.BigEndian.PutUint16(msg[0:2], 0x1234)
	binary.BigEndian.PutUint16(msg[2:4], 0x0100) // RD
	binary.BigEndian.PutUint16(msg[4:6], 1)      // QDCOUNT

	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			label := name[start:i]
			msg = append(msg, byte(len(label)))
			msg = append(msg, label...)
			start = i + 1
		}
	}
	msg = append(msg, 0)
	var tail [4]byte
	binary.BigEndian.PutUint16(tail[0:2], qtype)
	binary.BigEndian.PutUint16(tail[2:4], 1) // IN
	msg = append(msg, tail[:]...)
	return msg
}

func TestShouldSuppressDNSQuery(t *testing.T) {
	if shouldSuppressDNSQuery(makeDNSQuery("example.com", 1)) {
		t.Fatal("A query must not be suppressed")
	}
	for _, qt := range []uint16{dnsTypeAAAA, dnsTypeSVCB, dnsTypeHTTPS} {
		if !shouldSuppressDNSQuery(makeDNSQuery("example.com", qt)) {
			t.Fatalf("qtype %d should be suppressed", qt)
		}
	}
}

func TestMakeDNSNoDataResponse(t *testing.T) {
	q := makeDNSQuery("vk.com", dnsTypeAAAA)
	resp, ok := makeDNSNoDataResponse(q)
	if !ok {
		t.Fatal("expected response")
	}
	if got := binary.BigEndian.Uint16(resp[0:2]); got != 0x1234 {
		t.Fatalf("transaction id=%x", got)
	}
	flags := binary.BigEndian.Uint16(resp[2:4])
	if flags&0x8000 == 0 {
		t.Fatal("QR bit is not set")
	}
	if flags&0x0100 == 0 {
		t.Fatal("RD bit was not preserved")
	}
	if binary.BigEndian.Uint16(resp[4:6]) != 1 {
		t.Fatal("QDCOUNT changed")
	}
	if binary.BigEndian.Uint16(resp[6:8]) != 0 {
		t.Fatal("ANCOUNT must be zero")
	}
	if firstDNSQType(resp) != dnsTypeAAAA {
		t.Fatal("question was not preserved")
	}
}
