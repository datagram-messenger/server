package dgpv1

import (
	"bytes"
	"context"
	"encoding"
	"encoding/binary"
	"io"
	"net"
	"reflect"
	"testing"
	"time"
)

func FuzzHeaderUnmarshalBinary(f *testing.F) {
	valid, _ := NewHeader(MessageTypePingPong, [16]byte{1, 2, 3}, 7, 9, 0).MarshalBinary()
	f.Add(valid)
	f.Add(valid[:HeaderSize-1])
	f.Add([]byte("DGP1"))

	f.Fuzz(func(t *testing.T, wire []byte) {
		input := append([]byte(nil), wire...)
		var got Header
		if err := got.UnmarshalBinary(input); err != nil {
			return
		}
		if err := got.ValidateReceive(); err != nil {
			t.Fatalf("successful decode does not validate: %v", err)
		}
		canonical, err := got.marshalBinary(false)
		if err != nil {
			t.Fatalf("receive-valid header cannot be encoded: %v", err)
		}
		var again Header
		if err := again.UnmarshalBinary(canonical); err != nil {
			t.Fatalf("canonical header cannot be decoded: %v", err)
		}
		if got != again {
			t.Fatalf("header changed after canonical round trip: got %+v, want %+v", again, got)
		}
	})
}

func FuzzFrameUnmarshalBinary(f *testing.F) {
	seed, _ := NewFrame(MessageTypeEncryptedData, [16]byte{1}, 9, []byte{1, 2, 3}, make([]byte, AEADTagSize), []byte{4})
	wire, _ := seed.MarshalBinary()
	f.Add(wire)
	f.Add(wire[:len(wire)-1])
	f.Add([]byte("DGP1"))

	f.Fuzz(func(t *testing.T, wire []byte) {
		input := append([]byte(nil), wire...)
		var got Frame
		if err := got.UnmarshalBinary(input); err != nil {
			return
		}
		if err := got.ValidateReceive(); err != nil {
			t.Fatalf("successful decode does not validate: %v", err)
		}

		owned := got
		owned.Payload = append([]byte(nil), got.Payload...)
		owned.Padding = append([]byte(nil), got.Padding...)
		for i := range input {
			input[i] ^= 0xff
		}
		if !reflect.DeepEqual(got, owned) {
			t.Fatal("decoded frame aliases its input")
		}

		if err := got.Validate(); err != nil {
			return // Reserved receive-only flag bits are intentionally not sendable.
		}
		canonical, err := got.MarshalBinary()
		if err != nil {
			t.Fatalf("valid frame cannot be encoded: %v", err)
		}
		var again Frame
		if err := again.UnmarshalBinary(canonical); err != nil {
			t.Fatalf("canonical frame cannot be decoded: %v", err)
		}
		reencoded, err := again.MarshalBinary()
		if err != nil || !bytes.Equal(reencoded, canonical) {
			t.Fatalf("frame encoding is not stable: error=%v", err)
		}
	})
}

func FuzzDecodeTLVs(f *testing.F) {
	golden := []byte{0x2a, 0x03, 0x00, 0x10, 0x20, 0x30, 0x00, 0x00}
	f.Add(golden)
	f.Add([]byte{1, 0, 0, 0xa5})
	f.Add(golden[:len(golden)-1])

	f.Fuzz(func(t *testing.T, wire []byte) {
		input := append([]byte(nil), wire...)
		fields, err := DecodeTLVs(input, 0)
		if err != nil {
			return
		}
		canonical, err := EncodeTLVs(fields)
		if err != nil {
			t.Fatalf("decoded TLVs cannot be encoded: %v", err)
		}
		for i := range input {
			input[i] ^= 0xff
		}
		reencoded, err := EncodeTLVs(fields)
		if err != nil || !bytes.Equal(reencoded, canonical) {
			t.Fatalf("decoded TLVs alias input or encode unstably: error=%v", err)
		}
		again, err := DecodeTLVs(canonical, 0)
		if err != nil || !reflect.DeepEqual(again, fields) {
			t.Fatalf("canonical TLVs do not round trip: error=%v", err)
		}
	})
}

func FuzzMessageUnmarshalBinary(f *testing.F) {
	f.Add(uint8(MessageTypePingPong), []byte{0, 1, 2, 3, 4, 5, 6, 7, 8})
	f.Add(uint8(MessageTypeAck), []byte{1, 1, 0, 0, 0, 0, 0, 0, 0})
	f.Add(uint8(MessageTypeEncryptedData), []byte{0x34, 0x12, 7, 0})
	f.Add(uint8(MessageTypeSessionClose), []byte{3, 0, 1, 3, 0, 'b', 'y', 'e', 0, 0})
	f.Add(uint8(MessageTypeResumptionTicket), []byte{1, 1, 0, 0, 0, 0, 0, 0, 0})
	f.Add(uint8(MessageTypeRekeyInit), append([]byte{1, 0, 0, 0}, make([]byte, 32)...))
	f.Add(uint8(MessageTypeError), []byte{9, 0})
	f.Add(uint8(MessageTypeHandshakeInit), append([]byte{byte(NoisePatternXX), 0, 0, 0}, make([]byte, 32)...))
	f.Add(uint8(MessageTypeHandshakeResponse), make([]byte, HandshakeResponseFixedSize))
	f.Add(uint8(10), make([]byte, HandshakeFinishFixedSize))
	f.Add(uint8(0xff), []byte{0})

	f.Fuzz(func(t *testing.T, kind uint8, wire []byte) {
		message := fuzzMessage(MessageType(kind))
		if message == nil {
			return
		}
		input := append([]byte(nil), wire...)
		if err := message.UnmarshalBinary(input); err != nil {
			return
		}
		marshaler := message.(encoding.BinaryMarshaler)
		canonical, err := marshaler.MarshalBinary()
		if err != nil {
			t.Fatalf("decoded message cannot be encoded: %v", err)
		}
		for i := range input {
			input[i] ^= 0xff
		}
		reencoded, err := marshaler.MarshalBinary()
		if err != nil || !bytes.Equal(reencoded, canonical) {
			t.Fatalf("decoded message aliases input or encodes unstably: error=%v", err)
		}
		again := fuzzMessage(MessageType(kind))
		if err := again.UnmarshalBinary(canonical); err != nil {
			t.Fatalf("canonical message cannot be decoded: %v", err)
		}
		stable, err := again.(encoding.BinaryMarshaler).MarshalBinary()
		if err != nil || !bytes.Equal(stable, canonical) {
			t.Fatalf("message encoding is not stable: error=%v", err)
		}
	})
}

func fuzzMessage(kind MessageType) encoding.BinaryUnmarshaler {
	switch kind {
	case MessageTypeHandshakeInit:
		return &HandshakeInit{}
	case MessageTypeHandshakeResponse:
		return &HandshakeResponse{}
	case MessageTypeEncryptedData:
		return &EncryptedData{}
	case MessageTypePingPong:
		return &PingPong{}
	case MessageTypeSessionClose:
		return &SessionClose{}
	case MessageTypeAck:
		return &Ack{}
	case MessageTypeResumptionTicket:
		return &ResumptionTicket{}
	case MessageTypeRekeyInit:
		return &RekeyInit{}
	case MessageTypeError:
		return &ErrorMessage{}
	case MessageType(10): // Fuzz-only selector for the nested handshake finish payload.
		return &HandshakeFinish{}
	default:
		return nil
	}
}

func FuzzTCPTransportReadFrame(f *testing.F) {
	frame, _ := NewFrame(MessageTypeEncryptedData, [16]byte{1}, 1, []byte("seed"), make([]byte, AEADTagSize), nil)
	wire, _ := frame.MarshalBinary()
	packet := make([]byte, 4+len(wire))
	binary.LittleEndian.PutUint32(packet, uint32(len(wire)))
	copy(packet[4:], wire)
	f.Add(packet)
	f.Add([]byte{39, 0, 0, 0})
	f.Add([]byte{0, 0, 1, 0})

	f.Fuzz(func(t *testing.T, packet []byte) {
		conn := &fuzzReadConn{Reader: bytes.NewReader(packet)}
		got, err := NewTCPTransport(conn).ReadFrame(context.Background())
		if err != nil {
			return
		}
		if err := got.ValidateReceive(); err != nil {
			t.Fatalf("transport returned invalid frame: %v", err)
		}
	})
}

type fuzzReadConn struct{ *bytes.Reader }

func (c *fuzzReadConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (c *fuzzReadConn) Close() error                     { return nil }
func (c *fuzzReadConn) LocalAddr() net.Addr              { return fuzzAddr("local") }
func (c *fuzzReadConn) RemoteAddr() net.Addr             { return fuzzAddr("remote") }
func (c *fuzzReadConn) SetDeadline(time.Time) error      { return nil }
func (c *fuzzReadConn) SetReadDeadline(time.Time) error  { return nil }
func (c *fuzzReadConn) SetWriteDeadline(time.Time) error { return nil }

type fuzzAddr string

func (a fuzzAddr) Network() string { return "fuzz" }
func (a fuzzAddr) String() string  { return string(a) }
