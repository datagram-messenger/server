package dgpv1

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// HeaderSize is the encoded size of a DGPv1 fixed header.
	HeaderSize = 40
	// Version is the protocol version encoded in every DGPv1 header.
	Version uint8 = 1
	// AEADTagSize is the authentication tag size used by DGPv1 ciphers.
	AEADTagSize = 16
	// MaxFrameSize is the largest DGPv1 frame permitted by TCP framing.
	MaxFrameSize = 65535
)

var (
	// Magic is the fixed plaintext header prefix.
	Magic = [4]byte{'D', 'G', 'P', '1'}

	// ErrHeaderTooShort indicates that input is shorter than HeaderSize.
	ErrHeaderTooShort = errors.New("dgpv1: header too short")
	// ErrInvalidMagic indicates that a header does not begin with Magic.
	ErrInvalidMagic = errors.New("dgpv1: invalid magic")
	// ErrUnsupportedVersion indicates that a header version is not 0x01.
	ErrUnsupportedVersion = errors.New("dgpv1: unsupported version")
	// ErrReservedFlags indicates that an outbound header uses flags other than padding.
	ErrReservedFlags = errors.New("dgpv1: reserved flag bits set")
	// ErrPaddingFlag indicates that FlagPadding and PadLength disagree.
	ErrPaddingFlag = errors.New("dgpv1: padding flag does not match pad length")
	// ErrFrameTooLarge indicates that header lengths describe a frame exceeding MaxFrameSize.
	ErrFrameTooLarge = errors.New("dgpv1: frame exceeds maximum size")
)

// Flags controls optional DGPv1 frame behavior.
type Flags uint8

const (
	// FlagObfuscated is reserved for post-MVP and MUST NOT be sent by MVP sessions.
	FlagObfuscated Flags = 1 << iota
	// FlagPadding is the only optional flag supported by the MVP profile.
	FlagPadding
	// FlagZeroRTT is reserved for post-MVP and MUST NOT be sent by MVP sessions.
	FlagZeroRTT

	mvpSenderFlags = FlagPadding
)

// MessageType identifies the payload carried by a frame.
type MessageType uint8

const (
	MessageTypeHandshakeInit     MessageType = 0x01
	MessageTypeHandshakeResponse MessageType = 0x02
	MessageTypeEncryptedData     MessageType = 0x03
	MessageTypePingPong          MessageType = 0x04
	MessageTypeSessionClose      MessageType = 0x05
	MessageTypeAck               MessageType = 0x06
	// MessageTypeResumptionTicket is reserved for post-MVP and rejected by Session.
	MessageTypeResumptionTicket MessageType = 0x07
	MessageTypeRekeyInit        MessageType = 0x08
	MessageTypeError            MessageType = 0x09
)

// Header is the 40-byte fixed DGPv1 frame header. Reserved wire fields are
// omitted because senders must encode them as zero and receivers ignore them.
type Header struct {
	Version       uint8
	Flags         Flags
	MessageType   MessageType
	SessionID     [16]byte
	Sequence      uint64
	PayloadLength uint32
	PadLength     uint8
}

// NewHeader returns a header initialized with the current protocol version.
func NewHeader(messageType MessageType, sessionID [16]byte, sequence uint64, payloadLength uint32, padLength uint8) Header {
	flags := Flags(0)
	if padLength != 0 {
		flags |= FlagPadding
	}

	return Header{
		Version:       Version,
		Flags:         flags,
		MessageType:   messageType,
		SessionID:     sessionID,
		Sequence:      sequence,
		PayloadLength: payloadLength,
		PadLength:     padLength,
	}
}

func (h Header) hasAEADTag() bool {
	return h.MessageType != MessageTypeHandshakeInit && h.MessageType != MessageTypeHandshakeResponse
}

// FrameSize returns the complete wire-frame size. DGPv1 has no transport
// prefix. Handshake frames carry Noise messages directly and have no outer
// 16-byte AEAD tag.
func (h Header) FrameSize() uint64 {
	size := uint64(HeaderSize) + uint64(h.PayloadLength) + uint64(h.PadLength)
	if h.hasAEADTag() {
		size += AEADTagSize
	}
	return size
}

func (h Header) validateCommon() error {
	if h.Version != Version {
		return fmt.Errorf("%w: got %d, want %d", ErrUnsupportedVersion, h.Version, Version)
	}
	if (h.Flags&FlagPadding != 0) != (h.PadLength != 0) {
		return ErrPaddingFlag
	}
	if h.FrameSize() > MaxFrameSize {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, h.FrameSize())
	}
	return nil
}

// Validate checks fields that senders must encode canonically.
func (h Header) Validate() error {
	if err := h.validateCommon(); err != nil {
		return err
	}
	if h.Flags&^mvpSenderFlags != 0 {
		return fmt.Errorf("%w: 0x%02x", ErrReservedFlags, uint8(h.Flags&^mvpSenderFlags))
	}
	return nil
}

// ValidateReceive checks invariants required when accepting a peer header.
// Unknown flag bits are retained and ignored for forward compatibility.
func (h Header) ValidateReceive() error { return h.validateCommon() }

func (h Header) marshalBinary(validateSend bool) ([]byte, error) {
	var err error
	if validateSend {
		err = h.Validate()
	} else {
		err = h.ValidateReceive()
	}
	if err != nil {
		return nil, err
	}

	buf := make([]byte, HeaderSize)
	copy(buf[0:4], Magic[:])
	buf[4] = h.Version
	buf[5] = byte(h.Flags)
	buf[6] = byte(h.MessageType)
	copy(buf[8:24], h.SessionID[:])
	binary.LittleEndian.PutUint64(buf[24:32], h.Sequence)
	binary.LittleEndian.PutUint32(buf[32:36], h.PayloadLength)
	buf[36] = h.PadLength
	return buf, nil
}

// MarshalBinary encodes h in the DGPv1 little-endian wire format.
func (h Header) MarshalBinary() ([]byte, error) { return h.marshalBinary(true) }

// UnmarshalBinary decodes a plaintext DGPv1 fixed header. Reserved bytes and
// unknown reserved flag bits are accepted as required for forward compatibility.
func (h *Header) UnmarshalBinary(data []byte) error {
	if len(data) < HeaderSize {
		return fmt.Errorf("%w: got %d bytes, want %d", ErrHeaderTooShort, len(data), HeaderSize)
	}
	if [4]byte(data[0:4]) != Magic {
		return ErrInvalidMagic
	}
	if data[4] != Version {
		return fmt.Errorf("%w: got %d, want %d", ErrUnsupportedVersion, data[4], Version)
	}

	var sessionID [16]byte
	copy(sessionID[:], data[8:24])
	decoded := Header{
		Version:       data[4],
		Flags:         Flags(data[5]),
		MessageType:   MessageType(data[6]),
		SessionID:     sessionID,
		Sequence:      binary.LittleEndian.Uint64(data[24:32]),
		PayloadLength: binary.LittleEndian.Uint32(data[32:36]),
		PadLength:     data[36],
	}
	if err := decoded.ValidateReceive(); err != nil {
		return err
	}

	*h = decoded
	return nil
}
