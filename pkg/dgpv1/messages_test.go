package dgpv1

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestMessageGoldenVectors(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	tests := []struct {
		name  string
		value interface{ MarshalBinary() ([]byte, error) }
		want  []byte
	}{
		{"ping", PingPong{Nonce: 0x0807060504030201}, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8}},
		{"pong", PingPong{IsResponse: true, Nonce: 1}, []byte{1, 1, 0, 0, 0, 0, 0, 0, 0}},
		{"ack", Ack{Sequences: []uint64{1, 0x0102030405060708}}, []byte{2, 1, 0, 0, 0, 0, 0, 0, 0, 8, 7, 6, 5, 4, 3, 2, 1}},
		{"rekey", RekeyInit{Epoch: 0x04030201, KeyConfirm: key}, append([]byte{1, 2, 3, 4}, key[:]...)},
		{"close-empty", SessionClose{Code: 2}, []byte{2, 0}},
		{"close", SessionClose{Code: 3, Reason: "bye"}, []byte{3, 0, 1, 3, 0, 'b', 'y', 'e', 0, 0}},
		{"encrypted-empty", EncryptedData{StreamID: 0x1234, AppMessageType: 7}, []byte{0x34, 0x12, 7, 0}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.value.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tt.want) {
				t.Fatalf("got % x want % x", got, tt.want)
			}
		})
	}
}

func TestHandshakeWrappersRoundTripAndOwnership(t *testing.T) {
	var e [32]byte
	for i := range e {
		e[i] = byte(i)
	}
	ik := HandshakeInit{Pattern: NoisePatternXX, ClientEphemeral: e}
	wire, err := ik.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var got HandshakeInit
	if err = got.UnmarshalBinary(wire); err != nil {
		t.Fatal(err)
	}
	wire[4] = 9
	if !reflect.DeepEqual(got, ik) {
		t.Fatalf("got %#v want %#v", got, ik)
	}
	resp := HandshakeResponse{ServerEphemeral: e, NoisePayload: bytes.Repeat([]byte{5}, 64)}
	wire, err = resp.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var gotResp HandshakeResponse
	if err = gotResp.UnmarshalBinary(wire); err != nil {
		t.Fatal(err)
	}
	wire[32] = 9
	if !reflect.DeepEqual(gotResp, resp) {
		t.Fatalf("got %#v want %#v", gotResp, resp)
	}
}

func TestHandshakeInitRejectsIK(t *testing.T) {
	if _, err := (HandshakeInit{Pattern: NoisePatternIK}).MarshalBinary(); !errors.Is(err, ErrInvalidNoisePattern) {
		t.Fatalf("marshal IK: %v", err)
	}
	wire := make([]byte, HandshakeInitFixedSize)
	wire[0] = byte(NoisePatternIK)
	var init HandshakeInit
	if err := init.UnmarshalBinary(wire); !errors.Is(err, ErrInvalidNoisePattern) {
		t.Fatalf("unmarshal IK: %v", err)
	}
}

func TestEncryptedDataTLVsRoundTripUnknownAndOwnership(t *testing.T) {
	want := EncryptedData{StreamID: 9, AppMessageType: 4, Fields: []TLV{{Type: 0xfe, Value: []byte{1, 2}}, {Type: 1, Value: nil}}}
	wire, err := want.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var got EncryptedData
	if err = got.UnmarshalBinary(wire); err != nil {
		t.Fatal(err)
	}
	wire[7] = 9
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v want %#v", got, want)
	}
}

func TestAckBoundariesRoundTripAndOwnership(t *testing.T) {
	for _, n := range []int{1, MaxAckSequences} {
		seq := make([]uint64, n)
		for i := range seq {
			seq[i] = uint64(i + 1)
		}
		wire, err := (Ack{Sequences: seq}).MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var got Ack
		if err = got.UnmarshalBinary(wire); err != nil {
			t.Fatal(err)
		}
		wire[1] = 99
		if got.Sequences[0] != 1 {
			t.Fatal("Ack aliases input")
		}
	}
	for _, n := range []int{0, MaxAckSequences + 1} {
		if _, err := (Ack{Sequences: make([]uint64, n)}).MarshalBinary(); !errors.Is(err, ErrAckCount) {
			t.Fatalf("count %d: %v", n, err)
		}
	}
}

func TestTextMessagesRoundTripBoundariesAndUTF8(t *testing.T) {
	for _, text := range []string{"", "hello", "π"} {
		wire, err := (ErrorMessage{Code: 4, Context: text}).MarshalBinary()
		if err != nil {
			t.Fatal(err)
		}
		var got ErrorMessage
		if err = got.UnmarshalBinary(wire); err != nil {
			t.Fatal(err)
		}
		if got.Context != text || got.Code != 4 {
			t.Fatalf("got %#v", got)
		}
	}
	max := strings.Repeat("a", MaxReasonSize)
	encoded, err := (SessionClose{Reason: max}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var decoded SessionClose
	if err := decoded.UnmarshalBinary(encoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Reason != max {
		t.Fatal("maximum reason did not round trip")
	}
	if _, err := (SessionClose{Reason: strings.Repeat("a", MaxReasonSize+1)}).MarshalBinary(); !errors.Is(err, ErrReasonTooLong) {
		t.Fatalf("%v", err)
	}
	if _, err := (SessionClose{Reason: string([]byte{0xff})}).MarshalBinary(); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("%v", err)
	}
	bad := []byte{0, 0, 1, 1, 0, 0xff}
	var close SessionClose
	if err := close.UnmarshalBinary(bad); !errors.Is(err, ErrInvalidUTF8) {
		t.Fatalf("%v", err)
	}
}

func TestMalformedMessages(t *testing.T) {
	var init HandshakeInit
	if err := init.UnmarshalBinary(make([]byte, 35)); !errors.Is(err, ErrMessageTooShort) {
		t.Fatal(err)
	}
	bad := make([]byte, 36)
	bad[0] = 1
	bad[1] = 1
	if err := init.UnmarshalBinary(bad); !errors.Is(err, ErrMessageReserved) {
		t.Fatal(err)
	}
	bad = make([]byte, 40)
	bad[0] = 1
	if err := init.UnmarshalBinary(bad); !errors.Is(err, ErrUnexpectedNoiseData) {
		t.Fatal(err)
	}
	bad = make([]byte, 37)
	bad[0] = byte(NoisePatternXX)
	if err := init.UnmarshalBinary(bad); !errors.Is(err, ErrHandshakeAlignment) {
		t.Fatal(err)
	}
	bad = make([]byte, 36)
	bad[0] = 3
	if err := init.UnmarshalBinary(bad); !errors.Is(err, ErrInvalidNoisePattern) {
		t.Fatal(err)
	}
	var data EncryptedData
	if err := data.UnmarshalBinary([]byte{0, 0, 0, 1}); !errors.Is(err, ErrMessageReserved) {
		t.Fatal(err)
	}
	var ping PingPong
	if err := ping.UnmarshalBinary(make([]byte, 10)); !errors.Is(err, ErrMessageLength) {
		t.Fatal(err)
	}
	bad = make([]byte, 9)
	bad[0] = 2
	if err := ping.UnmarshalBinary(bad); !errors.Is(err, ErrInvalidPingResponse) {
		t.Fatal(err)
	}
	var ack Ack
	if err := ack.UnmarshalBinary([]byte{0}); !errors.Is(err, ErrAckCount) {
		t.Fatal(err)
	}
	if err := ack.UnmarshalBinary([]byte{1}); !errors.Is(err, ErrMessageLength) {
		t.Fatal(err)
	}
	var rekey RekeyInit
	if err := rekey.UnmarshalBinary(make([]byte, 37)); !errors.Is(err, ErrMessageLength) {
		t.Fatal(err)
	}
	var close SessionClose
	if err := close.UnmarshalBinary([]byte{0}); !errors.Is(err, ErrMessageTooShort) {
		t.Fatal(err)
	}
	if err := close.UnmarshalBinary([]byte{0, 0, 2, 0, 0, 0}); !errors.Is(err, ErrUnknownMessageTLV) {
		t.Fatal(err)
	}
	if err := close.UnmarshalBinary([]byte{0, 0, 1, 0, 0, 0, 1, 0, 0, 0}); !errors.Is(err, ErrDuplicateMessageTLV) {
		t.Fatal(err)
	}
}

func TestTrailingBytesRejected(t *testing.T) {
	cases := []struct {
		name  string
		wire  []byte
		parse func([]byte) error
	}{
		{"ping", append(make([]byte, 9), 0), func(b []byte) error { var v PingPong; return v.UnmarshalBinary(b) }},
		{"ack", append([]byte{1, 1, 0, 0, 0, 0, 0, 0, 0}, 0), func(b []byte) error { var v Ack; return v.UnmarshalBinary(b) }},
		{"rekey", make([]byte, 37), func(b []byte) error { var v RekeyInit; return v.UnmarshalBinary(b) }},
	}
	for _, tc := range cases {
		if err := tc.parse(tc.wire); err == nil {
			t.Fatalf("%s accepted trailing byte", tc.name)
		}
	}
}

func TestTruncationAtEveryBoundary(t *testing.T) {
	wire, _ := (Ack{Sequences: []uint64{1, 2}}).MarshalBinary()
	for n := range len(wire) {
		var got Ack
		if err := got.UnmarshalBinary(wire[:n]); err == nil {
			t.Fatalf("accepted %d bytes", n)
		}
	}
}

func TestHandshakePayloadSizeLimits(t *testing.T) {
	oversizedInit := HandshakeInit{
		Pattern:      NoisePatternXX,
		NoisePayload: make([]byte, MaxHandshakePayloadSize-HandshakeInitFixedSize+1),
	}
	if _, err := oversizedInit.MarshalBinary(); !errors.Is(err, ErrUnexpectedNoiseData) {
		t.Fatalf("oversized init marshal: %v", err)
	}
	initWire := make([]byte, MaxHandshakePayloadSize+1)
	initWire[0] = byte(NoisePatternXX)
	var init HandshakeInit
	if err := init.UnmarshalBinary(initWire); !errors.Is(err, ErrMessageLength) {
		t.Fatalf("oversized init unmarshal: %v", err)
	}

	oversizedResponse := HandshakeResponse{
		NoisePayload: make([]byte, MaxHandshakePayloadSize-HandshakeResponseFixedSize+1),
	}
	if _, err := oversizedResponse.MarshalBinary(); !errors.Is(err, ErrMessageLength) {
		t.Fatalf("oversized response marshal: %v", err)
	}
	var response HandshakeResponse
	if err := response.UnmarshalBinary(make([]byte, MaxHandshakePayloadSize+1)); !errors.Is(err, ErrMessageLength) {
		t.Fatalf("oversized response unmarshal: %v", err)
	}
}

func TestTextMessageDuplicateTLVDetectedRegardlessOfOrder(t *testing.T) {
	wire := []byte{
		0, 0,
		2, 0, 0, 0,
		1, 0, 0, 0,
		1, 0, 0, 0,
	}
	var message ErrorMessage
	if err := message.UnmarshalBinary(wire); !errors.Is(err, ErrDuplicateMessageTLV) {
		t.Fatalf("duplicate TLV: %v", err)
	}
}
