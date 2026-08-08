package dgpv1

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestStage3PayloadRoundTrips(t *testing.T) {
	var confirm [32]byte
	confirm[0], confirm[31] = 1, 2
	tests := []struct {
		name string
		in   interface{ MarshalBinary() ([]byte, error) }
		out  interface{ UnmarshalBinary([]byte) error }
	}{
		{"ping", PingPong{Nonce: 9}, &PingPong{}},
		{"pong", PingPong{IsResponse: true, Nonce: 9}, &PingPong{}},
		{"ack", Ack{Sequences: []uint64{1, 7}}, &Ack{}},
		{"close", SessionClose{Code: 3, Reason: "idle"}, &SessionClose{}},
		{"rekey", RekeyInit{Epoch: 2, KeyConfirm: confirm}, &RekeyInit{}},
		{"error", ErrorMessage{Code: 9, Context: "bad frame"}, &ErrorMessage{}},
		{"ticket", ResumptionTicket{Ticket: []byte{1, 2, 3}, ValidUntil: 0x0807060504030201}, &ResumptionTicket{}},
		{"data unknown extension", EncryptedData{StreamID: 1, AppMessageType: 2, Fields: []TLV{{Type: 0xfe, Value: []byte{3}}}}, &EncryptedData{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wire, err := tt.in.MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if err := tt.out.UnmarshalBinary(wire); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(reflect.ValueOf(tt.in).Interface(), reflect.ValueOf(tt.out).Elem().Interface()) {
				t.Fatalf("round trip mismatch: %#v %#v", tt.in, tt.out)
			}
		})
	}
}

func TestStage3StrictValidation(t *testing.T) {
	duplicate, _ := EncodeTLVs([]TLV{{Type: 1}, {Type: 1}})
	cases := []struct {
		name string
		err  error
		want error
	}{
		{"duplicate data marshal", func() error {
			_, err := (EncryptedData{Fields: []TLV{{Type: 1}, {Type: 1}}}).MarshalBinary()
			return err
		}(), ErrDuplicateMessageTLV},
		{"duplicate data unmarshal", func() error { return (&EncryptedData{}).UnmarshalBinary(append([]byte{0, 0, 1, 0}, duplicate...)) }(), ErrDuplicateMessageTLV},
		{"invalid close marshal", func() error { _, err := (SessionClose{Code: 4}).MarshalBinary(); return err }(), ErrInvalidCloseCode},
		{"invalid close unmarshal", (&SessionClose{}).UnmarshalBinary([]byte{4, 0}), ErrInvalidCloseCode},
		{"zero rekey marshal", func() error { _, err := (RekeyInit{}).MarshalBinary(); return err }(), ErrInvalidEpoch},
		{"zero rekey unmarshal", (&RekeyInit{}).UnmarshalBinary(make([]byte, RekeyInitSize)), ErrInvalidEpoch},
		{"empty ticket marshal", func() error { _, err := (ResumptionTicket{}).MarshalBinary(); return err }(), ErrResumptionTicket},
		{"short ticket", (&ResumptionTicket{}).UnmarshalBinary(make([]byte, 8)), ErrResumptionTicket},
	}
	for _, tc := range cases {
		if !errors.Is(tc.err, tc.want) {
			t.Errorf("%s: got %v want %v", tc.name, tc.err, tc.want)
		}
	}
}

func TestMessageType09IsError(t *testing.T) {
	if MessageTypeError != 0x09 {
		t.Fatalf("error type = %#x", MessageTypeError)
	}
	message, err := newInboundMessage(0x09)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := message.(*ErrorMessage); !ok {
		t.Fatalf("0x09 decoded as %T", message)
	}
}

func TestResumptionTicketWireAndOwnership(t *testing.T) {
	want := []byte{1, 2, 3, 8, 7, 6, 5, 4, 3, 2, 1}
	wire, err := (ResumptionTicket{Ticket: []byte{1, 2, 3}, ValidUntil: 0x0102030405060708}).MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(wire, want) {
		t.Fatalf("got % x want % x", wire, want)
	}
	var got ResumptionTicket
	if err := got.UnmarshalBinary(wire); err != nil {
		t.Fatal(err)
	}
	wire[0] = 9
	if got.Ticket[0] != 1 {
		t.Fatal("ticket aliases input")
	}
}
