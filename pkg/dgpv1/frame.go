package dgpv1

import (
	"errors"
	"fmt"
)

var (
	ErrFrameTooShort       = errors.New("dgpv1: frame too short")
	ErrFrameLengthMismatch = errors.New("dgpv1: frame length does not match header")
	ErrPayloadTooLarge     = errors.New("dgpv1: payload exceeds maximum frame size")
	ErrTagLength           = errors.New("dgpv1: AEAD tag must be 16 bytes")
	ErrPaddingLength       = errors.New("dgpv1: padding length exceeds 255 bytes")
)

// Frame is a complete plaintext-header DGPv1 frame. Payload contains the
// ciphertext only; Tag and Padding are represented separately.
type Frame struct {
	Header  Header
	Payload []byte
	Tag     [AEADTagSize]byte
	Padding []byte
}

// NewFrame constructs a frame and copies all caller-owned byte slices.
// Handshake frames do not carry the outer data-frame AEAD tag. A legacy
// all-zero 16-byte tag is accepted for them but is not emitted on the wire.
func NewFrame(messageType MessageType, sessionID [16]byte, sequence uint64, payload, tag, padding []byte) (Frame, error) {
	if len(padding) > 255 {
		return Frame{}, fmt.Errorf("%w: got %d", ErrPaddingLength, len(padding))
	}
	if uint64(len(payload)) > uint64(^uint32(0)) {
		return Frame{}, fmt.Errorf("%w: %d bytes", ErrPayloadTooLarge, len(payload))
	}
	header := NewHeader(messageType, sessionID, sequence, uint32(len(payload)), uint8(len(padding)))
	if header.hasAEADTag() {
		if len(tag) != AEADTagSize {
			return Frame{}, fmt.Errorf("%w: got %d", ErrTagLength, len(tag))
		}
	} else if len(tag) != 0 && (len(tag) != AEADTagSize || !allZero(tag)) {
		return Frame{}, fmt.Errorf("%w: handshake frames have no AEAD tag", ErrTagLength)
	}
	if header.FrameSize() > MaxFrameSize {
		return Frame{}, fmt.Errorf("%w: %d bytes", ErrPayloadTooLarge, len(payload))
	}

	frame := Frame{
		Header:  header,
		Payload: append([]byte(nil), payload...),
		Padding: append([]byte(nil), padding...),
	}
	if header.hasAEADTag() {
		copy(frame.Tag[:], tag)
	}
	return frame, nil
}

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}

func (f Frame) validateLengths() error {
	if uint64(len(f.Payload)) != uint64(f.Header.PayloadLength) {
		return fmt.Errorf("%w: payload has %d bytes, header declares %d", ErrFrameLengthMismatch, len(f.Payload), f.Header.PayloadLength)
	}
	if len(f.Padding) != int(f.Header.PadLength) {
		return fmt.Errorf("%w: padding has %d bytes, header declares %d", ErrFrameLengthMismatch, len(f.Padding), f.Header.PadLength)
	}
	return nil
}

// Validate checks outbound canonical form and body lengths.
func (f Frame) Validate() error {
	if err := f.Header.Validate(); err != nil {
		return err
	}
	return f.validateLengths()
}

// ValidateReceive checks inbound invariants while permitting reserved flag bits.
func (f Frame) ValidateReceive() error {
	if err := f.Header.ValidateReceive(); err != nil {
		return err
	}
	return f.validateLengths()
}

// MarshalBinary encodes f in DGPv1 wire format.
func (f Frame) MarshalBinary() ([]byte, error) {
	if err := f.Validate(); err != nil {
		return nil, err
	}
	header, err := f.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}

	buf := make([]byte, 0, int(f.Header.FrameSize()))
	buf = append(buf, header...)
	buf = append(buf, f.Payload...)
	if f.Header.hasAEADTag() {
		buf = append(buf, f.Tag[:]...)
	}
	buf = append(buf, f.Padding...)
	return buf, nil
}

// UnmarshalBinary decodes exactly one plaintext-header DGPv1 frame and copies
// its body so the result does not alias data.
func (f *Frame) UnmarshalBinary(data []byte) error {
	if len(data) < HeaderSize {
		return fmt.Errorf("%w: got %d bytes, want at least %d", ErrFrameTooShort, len(data), HeaderSize)
	}

	var header Header
	if err := header.UnmarshalBinary(data[:HeaderSize]); err != nil {
		return err
	}
	want := header.FrameSize()
	if uint64(len(data)) != want {
		return fmt.Errorf("%w: got %d bytes, header declares %d", ErrFrameLengthMismatch, len(data), want)
	}

	payloadEnd := HeaderSize + int(header.PayloadLength)
	tagEnd := payloadEnd
	if header.hasAEADTag() {
		tagEnd += AEADTagSize
	}
	decoded := Frame{
		Header:  header,
		Payload: append([]byte(nil), data[HeaderSize:payloadEnd]...),
		Padding: append([]byte(nil), data[tagEnd:]...),
	}
	if header.hasAEADTag() {
		copy(decoded.Tag[:], data[payloadEnd:tagEnd])
	}
	*f = decoded
	return nil
}
