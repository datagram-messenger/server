package dgpv1

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

func TestFrameMarshalBinaryWireLayout(t *testing.T) {
	payload := []byte{0x10, 0x20, 0x30}
	tag := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	padding := []byte{0xa1, 0xb2}
	frame, err := NewFrame(MessageTypeEncryptedData, [16]byte{1, 2, 3}, 0x0102030405060708, payload, tag, padding)
	if err != nil {
		t.Fatalf("NewFrame() error = %v", err)
	}

	got, err := frame.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	want := make([]byte, HeaderSize+len(payload)+AEADTagSize+len(padding))
	copy(want[:4], Magic[:])
	want[4] = Version
	want[5] = byte(FlagPadding)
	want[6] = byte(MessageTypeEncryptedData)
	copy(want[8:24], []byte{1, 2, 3})
	binary.LittleEndian.PutUint64(want[24:32], 0x0102030405060708)
	binary.LittleEndian.PutUint32(want[32:36], uint32(len(payload)))
	want[36] = byte(len(padding))
	copy(want[40:], payload)
	copy(want[43:], tag)
	copy(want[59:], padding)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MarshalBinary() = % x, want % x", got, want)
	}
}

func TestFrameRoundTripAndOwnership(t *testing.T) {
	payload := []byte{1, 2, 3}
	tag := make([]byte, AEADTagSize)
	padding := []byte{4, 5}
	frame, err := NewFrame(MessageTypeAck, [16]byte{9}, 7, payload, tag, padding)
	if err != nil {
		t.Fatal(err)
	}
	payload[0], tag[0], padding[0] = 99, 99, 99
	if frame.Payload[0] != 1 || frame.Tag[0] != 0 || frame.Padding[0] != 4 {
		t.Fatal("NewFrame retained caller-owned storage")
	}

	wire, err := frame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var got Frame
	if err := got.UnmarshalBinary(wire); err != nil {
		t.Fatal(err)
	}
	wire[HeaderSize] = 88
	if got.Payload[0] != 1 {
		t.Fatal("UnmarshalBinary retained input storage")
	}
	if !reflect.DeepEqual(got, frame) {
		t.Fatalf("round trip = %+v, want %+v", got, frame)
	}
}

func TestNewFrameBoundariesAndErrors(t *testing.T) {
	tag := make([]byte, AEADTagSize)
	maxPayload := MaxFrameSize - HeaderSize - AEADTagSize
	tests := []struct {
		name    string
		payload []byte
		tag     []byte
		padding []byte
		wantErr error
	}{
		{name: "empty payload", tag: tag},
		{name: "maximum frame", payload: make([]byte, maxPayload), tag: tag},
		{name: "maximum padding", payload: make([]byte, maxPayload-255), tag: tag, padding: make([]byte, 255)},
		{name: "short tag", tag: make([]byte, AEADTagSize-1), wantErr: ErrTagLength},
		{name: "long tag", tag: make([]byte, AEADTagSize+1), wantErr: ErrTagLength},
		{name: "padding over uint8", tag: tag, padding: make([]byte, 256), wantErr: ErrPaddingLength},
		{name: "oversized frame", payload: make([]byte, maxPayload+1), tag: tag, wantErr: ErrPayloadTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewFrame(MessageTypePingPong, [16]byte{}, 1, tt.payload, tt.tag, tt.padding)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("NewFrame() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestFrameValidate(t *testing.T) {
	tag := make([]byte, AEADTagSize)
	valid, err := NewFrame(MessageTypeEncryptedData, [16]byte{}, 1, []byte{1}, tag, []byte{2})
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		mutate  func(*Frame)
		wantErr error
	}{
		{name: "valid", mutate: func(*Frame) {}},
		{name: "payload mismatch", mutate: func(f *Frame) { f.Header.PayloadLength++ }, wantErr: ErrFrameLengthMismatch},
		{name: "padding mismatch", mutate: func(f *Frame) { f.Padding = nil }, wantErr: ErrFrameLengthMismatch},
		{name: "header validation first", mutate: func(f *Frame) { f.Header.Version++; f.Payload = nil }, wantErr: ErrUnsupportedVersion},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := valid
			tt.mutate(&got)
			if err := got.Validate(); !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestFrameUnmarshalBinaryErrors(t *testing.T) {
	frame, err := NewFrame(MessageTypeAck, [16]byte{}, 1, []byte{1, 2}, make([]byte, AEADTagSize), []byte{3})
	if err != nil {
		t.Fatal(err)
	}
	valid, err := frame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		data    func() []byte
		wantErr error
	}{
		{name: "empty", data: func() []byte { return nil }, wantErr: ErrFrameTooShort},
		{name: "missing tag byte", data: func() []byte { return make([]byte, HeaderSize+AEADTagSize-1) }, wantErr: ErrFrameTooShort},
		{name: "invalid header", data: func() []byte { b := append([]byte(nil), valid...); b[0] = 0; return b }, wantErr: ErrInvalidMagic},
		{name: "truncated payload", data: func() []byte { return append([]byte(nil), valid[:len(valid)-1]...) }, wantErr: ErrFrameLengthMismatch},
		{name: "trailing byte", data: func() []byte { return append(append([]byte(nil), valid...), 0) }, wantErr: ErrFrameLengthMismatch},
		{name: "oversized declaration", data: func() []byte {
			b := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(b[32:36], MaxFrameSize)
			return b
		}, wantErr: ErrFrameTooLarge},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := Frame{Header: Header{Version: 99}, Payload: []byte{9}}
			got := original
			err := got.UnmarshalBinary(tt.data())
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("UnmarshalBinary() error = %v, want %v", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, original) {
				t.Fatalf("frame changed on error: got %+v, want %+v", got, original)
			}
		})
	}
}

func TestFrameUnmarshalAcceptsReservedReceiveFields(t *testing.T) {
	frame, err := NewFrame(MessageTypeEncryptedData, [16]byte{}, 1, nil, make([]byte, AEADTagSize), nil)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := frame.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	wire[5] |= 0x80
	wire[7], wire[37], wire[38], wire[39] = 1, 2, 3, 4
	var got Frame
	if err := got.UnmarshalBinary(wire); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if got.Header.Flags != 0x80 {
		t.Fatalf("Flags = %#x, want %#x", got.Header.Flags, Flags(0x80))
	}
}
