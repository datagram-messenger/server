package dgpv1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	codec, err := NewCodec(CipherChaCha20Poly1305, bytes.Repeat([]byte{0x42}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte("authenticated DGPv1 payload")
	frame, err := codec.Encrypt(MessageTypeEncryptedData, [16]byte{1}, 0x0102030405060708, plaintext, 17)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame.Payload) != len(plaintext) || len(frame.Padding) != 17 {
		t.Fatalf("body lengths = %d, %d", len(frame.Payload), len(frame.Padding))
	}
	got, err := codec.Decrypt(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext = %q, want %q", got, plaintext)
	}
}

func TestNonceLayout(t *testing.T) {
	got := nonce(0x0102030405060708)
	want := make([]byte, 12)
	binary.LittleEndian.PutUint64(want[4:], 0x0102030405060708)
	if !bytes.Equal(got, want) {
		t.Fatalf("nonce = %x, want %x", got, want)
	}
}

func TestNewCodecErrors(t *testing.T) {
	for _, size := range []int{0, KeySize - 1, KeySize + 1} {
		if _, err := NewCodec(CipherChaCha20Poly1305, make([]byte, size)); !errors.Is(err, ErrInvalidKeySize) {
			t.Fatalf("key size %d error = %v", size, err)
		}
	}
	for _, suite := range []CipherSuite{CipherAES256GCM, 99} {
		if _, err := NewCodec(suite, make([]byte, KeySize)); !errors.Is(err, ErrUnsupportedCipher) {
			t.Fatalf("suite %d error = %v", suite, err)
		}
	}
}

func TestCodecRejectsInvalidEncryptedHeader(t *testing.T) {
	codec, err := NewCodec(CipherChaCha20Poly1305, make([]byte, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		msgType   MessageType
		sessionID [16]byte
		sequence  uint64
		want      error
	}{
		{"handshake type", MessageTypeHandshakeInit, [16]byte{1}, 1, ErrUnencryptedType},
		{"zero session", MessageTypeEncryptedData, [16]byte{}, 1, ErrInvalidSessionID},
		{"zero sequence", MessageTypeEncryptedData, [16]byte{1}, 0, ErrInvalidSequence},
		{"reserved resumption type", MessageTypeResumptionTicket, [16]byte{1}, 1, ErrUnencryptedType},
		{"unknown type", 0xff, [16]byte{1}, 1, ErrUnencryptedType},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := codec.Encrypt(tt.msgType, tt.sessionID, tt.sequence, nil, 0); !errors.Is(err, tt.want) {
				t.Fatalf("Encrypt() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestCodecAuthenticationFailuresAreUniform(t *testing.T) {
	codec, err := NewCodec(CipherChaCha20Poly1305, bytes.Repeat([]byte{1}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	frame, err := codec.Encrypt(MessageTypeAck, [16]byte{1}, 7, []byte("secret"), 0)
	if err != nil {
		t.Fatal(err)
	}

	mutations := []func(*Frame){
		func(f *Frame) { f.Payload[0] ^= 1 },
		func(f *Frame) { f.Tag[0] ^= 1 },
		func(f *Frame) { f.Header.Sequence++ },
		func(f *Frame) { f.Header.SessionID[0]++ },
		func(f *Frame) { f.Header.MessageType = MessageTypePingPong },
	}
	for i, mutate := range mutations {
		got := frame
		got.Payload = append([]byte(nil), frame.Payload...)
		mutate(&got)
		if _, err := codec.Decrypt(got); err != ErrAuthentication {
			t.Fatalf("mutation %d error = %v, want exact ErrAuthentication", i, err)
		}
	}
}

func TestCodecWrongKeyFailsAuthentication(t *testing.T) {
	codec, _ := NewCodec(CipherChaCha20Poly1305, bytes.Repeat([]byte{1}, KeySize))
	frame, err := codec.Encrypt(MessageTypeEncryptedData, [16]byte{1}, 1, []byte("secret"), 0)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewCodec(CipherChaCha20Poly1305, bytes.Repeat([]byte{2}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Decrypt(frame); err != ErrAuthentication {
		t.Fatalf("Decrypt() error = %v", err)
	}
}

func TestCodecAcceptsZeroPaddingByte(t *testing.T) {
	codec, _ := NewCodec(CipherChaCha20Poly1305, make([]byte, KeySize))
	frame, err := codec.Encrypt(MessageTypeEncryptedData, [16]byte{1}, 1, nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	frame.Padding[0] = 0
	if _, err := codec.Decrypt(frame); err != nil {
		t.Fatalf("Decrypt() error = %v", err)
	}
}

func TestCodecAADUsesExactReceivedReservedBytes(t *testing.T) {
	codec, _ := NewCodec(CipherChaCha20Poly1305, make([]byte, KeySize))
	header := NewHeader(MessageTypeEncryptedData, [16]byte{1}, 1, 1, 0)
	header.Reserved = [4]byte{0xa7, 0xb7, 0xb8, 0xb9}
	aad, err := header.marshalBinary(false)
	if err != nil {
		t.Fatal(err)
	}
	sealed := codec.aead.Seal(nil, nonce(header.Sequence), []byte("x"), aad)
	frame := Frame{Header: header, Payload: append([]byte(nil), sealed[:1]...)}
	copy(frame.Tag[:], sealed[1:])

	plaintext, err := codec.Decrypt(frame)
	if err != nil || !bytes.Equal(plaintext, []byte("x")) {
		t.Fatalf("Decrypt() = %q, %v", plaintext, err)
	}
	for i := range frame.Header.Reserved {
		tampered := frame
		tampered.Header.Reserved[i] ^= 1
		if _, err := codec.Decrypt(tampered); err != ErrAuthentication {
			t.Fatalf("reserved byte %d tamper error = %v", i, err)
		}
	}
	if _, err := frame.MarshalBinary(); !errors.Is(err, ErrReservedFlags) {
		t.Fatalf("sender accepted nonzero reserved bytes: %v", err)
	}
}

func TestRandomBytes(t *testing.T) {
	got, err := randomBytes(bytes.NewReader([]byte{0, 1, 2}), 3)
	if err != nil || !bytes.Equal(got, []byte{0, 1, 2}) {
		t.Fatalf("padding = %v, error = %v", got, err)
	}
	if _, err := randomBytes(bytes.NewReader(nil), 1); err == nil {
		t.Fatal("expected entropy error")
	}
	if _, err := randomBytes(bytes.NewReader(nil), 256); !errors.Is(err, ErrPaddingLength) {
		t.Fatalf("length error = %v", err)
	}
}
