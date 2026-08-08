package main

import (
	"bytes"
	"testing"

	"github.com/tr1xdev/datagram-server.git/pkg/dgpv1"
)

func TestResponseForRejectsUnsupportedMessages(t *testing.T) {
	tests := []struct {
		name    string
		message any
	}{
		{name: "nil interface", message: nil},
		{name: "nil encrypted data", message: (*dgpv1.EncryptedData)(nil)},
		{name: "control message", message: &dgpv1.Ack{}},
		{name: "unknown application type", message: &dgpv1.EncryptedData{AppMessageType: 0xff}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response, ok := responseFor(tt.message)
			if ok || response != nil {
				t.Fatalf("responseFor() = (%#v, %v), want (nil, false)", response, ok)
			}
		})
	}
}

func TestResponseForEchoCopiesEncryptedData(t *testing.T) {
	original := &dgpv1.EncryptedData{
		StreamID:       42,
		AppMessageType: appMessageTypeEcho,
		Fields:         []dgpv1.TLV{{Type: 3, Value: []byte{1, 2, 3}}},
	}

	response, ok := responseFor(original)
	if !ok || response == nil {
		t.Fatalf("responseFor() = (%#v, %v), want non-nil response and true", response, ok)
	}
	if response.StreamID != original.StreamID || response.AppMessageType != original.AppMessageType {
		t.Fatalf("metadata = (%v, %v), want (%v, %v)", response.StreamID, response.AppMessageType, original.StreamID, original.AppMessageType)
	}
	if len(response.Fields) != 1 || response.Fields[0].Type != original.Fields[0].Type || !bytes.Equal(response.Fields[0].Value, original.Fields[0].Value) {
		t.Fatalf("fields = %#v, want %#v", response.Fields, original.Fields)
	}

	original.Fields[0].Value[0] = 9
	if response.Fields[0].Value[0] != 1 {
		t.Fatalf("response changed after source mutation: %v", response.Fields[0].Value)
	}
	response.Fields[0].Value[1] = 8
	if original.Fields[0].Value[1] != 2 {
		t.Fatalf("source changed after response mutation: %v", original.Fields[0].Value)
	}
}

func TestResponseForInfo(t *testing.T) {
	original := &dgpv1.EncryptedData{
		StreamID:       84,
		AppMessageType: appMessageTypeInfo,
		Fields:         []dgpv1.TLV{{Type: 9, Value: []byte("ignored")}},
	}

	response, ok := responseFor(original)
	if !ok || response == nil {
		t.Fatalf("responseFor() = (%#v, %v), want non-nil response and true", response, ok)
	}
	if response.StreamID != original.StreamID || response.AppMessageType != original.AppMessageType {
		t.Fatalf("metadata = (%v, %v), want (%v, %v)", response.StreamID, response.AppMessageType, original.StreamID, original.AppMessageType)
	}
	want := []dgpv1.TLV{
		{Type: infoTLVProtocol, Value: []byte("dgpv1")},
		{Type: infoTLVService, Value: []byte("api_datagram")},
	}
	if len(response.Fields) != len(want) {
		t.Fatalf("fields = %#v, want %#v", response.Fields, want)
	}
	for i := range want {
		if response.Fields[i].Type != want[i].Type || !bytes.Equal(response.Fields[i].Value, want[i].Value) {
			t.Fatalf("fields = %#v, want %#v", response.Fields, want)
		}
	}
}
