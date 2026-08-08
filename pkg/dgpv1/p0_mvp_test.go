package dgpv1

import (
	"bytes"
	"errors"
	"testing"
)

func TestP0MVPHeaderLayoutAndReservedFlags(t *testing.T) {
	header := NewHeader(MessageTypeEncryptedData, [16]byte{1}, 1, 0, 0)
	wire, err := header.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire[:7], []byte{'D', 'G', 'P', '1', 0x01, 0x00, 0x03}) {
		t.Fatalf("header prefix = % x", wire[:7])
	}
	for _, offset := range []int{7, 37, 38, 39} {
		if wire[offset] != 0 {
			t.Fatalf("reserved byte %d = %#x", offset, wire[offset])
		}
	}
	wire[5] = byte(FlagObfuscated | FlagZeroRTT)
	var inbound Header
	if err := inbound.UnmarshalBinary(wire); err != nil {
		t.Fatalf("reserved inbound flags rejected: %v", err)
	}
	if _, err := inbound.MarshalBinary(); !errors.Is(err, ErrReservedFlags) {
		t.Fatalf("reserved outbound flags error = %v", err)
	}
}

func TestP0MVPSessionRejectsResumptionTicket(t *testing.T) {
	session, _ := testSessions(t)
	if _, err := session.Send(ResumptionTicket{Ticket: []byte{1}}, 0); !errors.Is(err, ErrMessageType) {
		t.Fatalf("Send resumption ticket error = %v", err)
	}
	if _, err := session.SendPayload(MessageTypeResumptionTicket, []byte{1}, 0); !errors.Is(err, ErrMessageType) {
		t.Fatalf("SendPayload resumption ticket error = %v", err)
	}
}
