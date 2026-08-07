package dgpv1

import (
	"encoding/binary"
	"errors"
	"reflect"
	"testing"
)

func TestNewHeader(t *testing.T) {
	sessionID := [16]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}

	tests := []struct {
		name      string
		padLength uint8
		wantFlags Flags
	}{
		{name: "without padding", wantFlags: 0},
		{name: "with padding", padLength: 7, wantFlags: FlagPadding},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewHeader(MessageTypeEncryptedData, sessionID, 42, 100, tt.padLength)
			want := Header{
				Version:       Version,
				Flags:         tt.wantFlags,
				MessageType:   MessageTypeEncryptedData,
				SessionID:     sessionID,
				Sequence:      42,
				PayloadLength: 100,
				PadLength:     tt.padLength,
			}
			if got != want {
				t.Fatalf("NewHeader() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestHeaderFrameSize(t *testing.T) {
	tests := []struct {
		name   string
		header Header
		want   uint64
	}{
		{name: "empty payload", header: Header{}, want: HeaderSize + AEADTagSize},
		{name: "payload and padding", header: Header{PayloadLength: 123, PadLength: 9}, want: HeaderSize + AEADTagSize + 123 + 9},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.header.FrameSize(); got != tt.want {
				t.Fatalf("FrameSize() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestHeaderValidate(t *testing.T) {
	maxPayload := uint32(MaxFrameSize - HeaderSize - AEADTagSize)
	tests := []struct {
		name    string
		header  Header
		wantErr error
	}{
		{name: "valid", header: Header{Version: Version}},
		{name: "valid known flags", header: Header{Version: Version, Flags: FlagObfuscated | FlagZeroRTT}},
		{name: "valid maximum frame", header: Header{Version: Version, PayloadLength: maxPayload}},
		{name: "unsupported version", header: Header{Version: Version + 1}, wantErr: ErrUnsupportedVersion},
		{name: "reserved flag", header: Header{Version: Version, Flags: 0x80}, wantErr: ErrReservedFlags},
		{name: "padding flag without padding", header: Header{Version: Version, Flags: FlagPadding}, wantErr: ErrPaddingFlag},
		{name: "padding without flag", header: Header{Version: Version, PadLength: 1}, wantErr: ErrPaddingFlag},
		{name: "frame too large", header: Header{Version: Version, PayloadLength: maxPayload + 1}, wantErr: ErrFrameTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.header.Validate()
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Validate() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestHeaderMarshalUnmarshalRoundTrip(t *testing.T) {
	want := NewHeader(
		MessageTypeError,
		[16]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
		0x0102030405060708,
		0x1020,
		5,
	)
	want.Flags |= FlagObfuscated | FlagZeroRTT

	data, err := want.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	var got Header
	if err := got.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if got != want {
		t.Fatalf("round trip header = %+v, want %+v", got, want)
	}
}

func TestHeaderMarshalBinaryWireLayout(t *testing.T) {
	sessionID := [16]byte{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	header := Header{
		Version:       Version,
		Flags:         FlagObfuscated | FlagPadding,
		MessageType:   MessageTypeAck,
		SessionID:     sessionID,
		Sequence:      0x0102030405060708,
		PayloadLength: 0x0a0b,
		PadLength:     0x0e,
	}

	got, err := header.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() error = %v", err)
	}
	want := make([]byte, HeaderSize)
	copy(want[0:4], []byte{'D', 'G', 'P', '1'})
	want[4] = Version
	want[5] = byte(FlagObfuscated | FlagPadding)
	want[6] = byte(MessageTypeAck)
	copy(want[8:24], sessionID[:])
	binary.LittleEndian.PutUint64(want[24:32], 0x0102030405060708)
	binary.LittleEndian.PutUint32(want[32:36], 0x0a0b)
	want[36] = 0x0e

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("MarshalBinary() = % x, want % x", got, want)
	}
	for _, offset := range []int{7, 37, 38, 39} {
		if got[offset] != 0 {
			t.Errorf("reserved byte at offset %d = %#x, want 0", offset, got[offset])
		}
	}
}

func TestHeaderUnmarshalBinaryErrors(t *testing.T) {
	valid, err := NewHeader(MessageTypePingPong, [16]byte{}, 1, 0, 0).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() fixture error = %v", err)
	}
	maxPayload := uint32(MaxFrameSize - HeaderSize - AEADTagSize)

	tests := []struct {
		name    string
		data    func() []byte
		wantErr error
	}{
		{name: "empty", data: func() []byte { return nil }, wantErr: ErrHeaderTooShort},
		{name: "one byte short", data: func() []byte { return append([]byte(nil), valid[:HeaderSize-1]...) }, wantErr: ErrHeaderTooShort},
		{name: "invalid magic", data: func() []byte { b := append([]byte(nil), valid...); b[0] = 'X'; return b }, wantErr: ErrInvalidMagic},
		{name: "unsupported version", data: func() []byte { b := append([]byte(nil), valid...); b[4] = Version + 1; return b }, wantErr: ErrUnsupportedVersion},
		{name: "frame too large", data: func() []byte {
			b := append([]byte(nil), valid...)
			binary.LittleEndian.PutUint32(b[32:36], maxPayload+1)
			return b
		}, wantErr: ErrFrameTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			original := Header{Version: 99, Sequence: 99}
			got := original
			err := got.UnmarshalBinary(tt.data())
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("UnmarshalBinary() error = %v, want %v", err, tt.wantErr)
			}
			if got != original {
				t.Fatalf("header changed on error: got %+v, want %+v", got, original)
			}
		})
	}
}

func TestHeaderUnmarshalBinaryIgnoresReservedReceiveFields(t *testing.T) {
	data, err := NewHeader(MessageTypeEncryptedData, [16]byte{1, 2, 3}, 7, 11, 0).MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary() fixture error = %v", err)
	}
	data[5] |= 0x80
	data[7] = 0xa7
	data[37] = 0xb7
	data[38] = 0xb8
	data[39] = 0xb9

	var got Header
	if err := got.UnmarshalBinary(data); err != nil {
		t.Fatalf("UnmarshalBinary() error = %v", err)
	}
	if got.Flags != Flags(0x80) {
		t.Fatalf("Flags = %#x, want %#x", got.Flags, Flags(0x80))
	}
	if got.MessageType != MessageTypeEncryptedData || got.Sequence != 7 || got.PayloadLength != 11 {
		t.Fatalf("decoded header = %+v", got)
	}
}
