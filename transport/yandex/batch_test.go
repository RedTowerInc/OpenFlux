package yandex

import (
	"bytes"
	"testing"
)

func TestYandexBatchRoundTrip(t *testing.T) {
	want := [][]byte{
		{0x00, 0x45, 0x00, 0x01},
		{0x1f, 0x04, 0x22, 0x4d, 0x18},
		bytes.Repeat([]byte{0xaa}, 1501),
	}

	encoded := encodeYandexBatch(want)
	got, ok := decodeYandexBatch(encoded)
	if !ok {
		t.Fatal("encoded batch was not recognized")
	}
	if len(got) != len(want) {
		t.Fatalf("decoded %d packets, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Fatalf("packet %d mismatch", i)
		}
	}
}

func TestYandexBatchDoesNotClaimLegacyPacket(t *testing.T) {
	legacy := []byte{0x00, 0x45, 0x00, 0x00, 0x28}
	if _, ok := decodeYandexBatch(legacy); ok {
		t.Fatal("legacy packet must not be interpreted as a batch")
	}
}

func TestYandexBatchRejectsTruncatedFrame(t *testing.T) {
	encoded := encodeYandexBatch([][]byte{{1, 2, 3}, {4, 5, 6}})
	encoded = encoded[:len(encoded)-1]
	if _, ok := decodeYandexBatch(encoded); ok {
		t.Fatal("truncated batch must be rejected")
	}
}
