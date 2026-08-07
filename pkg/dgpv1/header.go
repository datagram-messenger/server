// Package dgpv1 implements Datagram Protocol Version 1 framing.
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

	ErrHeaderTooShort     = errors.New("dgpv1: header too short")
	ErrInvalidMagic       = errors.New("dgpv1: invalid magic")
	ErrUnsupportedVersion = errors.New("dgpv1: unsupported version")
	ErrReservedFlags      = errors.New("dgpv1: reserved flag bits set")
	ErrPaddingFlag        = errors.New("dgpv1: padding flag does not match pad length")
	ErrFrameTooLarge      = errors.New("dgpv1: frame exceeds maximum size")
)

// Flags controls optional DGPv1 frame behavior.
type Flags uint8

const (
	FlagObfuscated Flags = 1 << iota
	FlagPadding
	FlagZeroRTT

	knownFlags = FlagObfuscated | FlagPadding | FlagZeroRTT
)

// MessageType identifies the payload carried by a frame.
type MessageType uint8

const (
	MessageTypeHandshakeInit MessageType = 0x01 + iota
	MessageTypeHandshakeResponse
	MessageTypeEncryptedData
	MessageTypePingPong
	MessageTypeSessionClose
	MessageTypeAck
	MessageTypeResumptionTicket
	MessageTypeRekeyInit
	MessageTypeRekeyAck
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

// FrameSize returns the complete frame size, excluding any transport prefix.
func (h Header) FrameSize() uint64 {
	return HeaderSize + uint64(h.PayloadLength) + AEADTagSize + uint64(h.PadLength)
}

// Validate checks fields that senders must encode canonically.
func (h Header) Validate() error {
	if h.Version != Version {
		return fmt.Errorf("%w: got %d, want %d", ErrUnsupportedVersion, h.Version, Version)
	}
	if h.Flags&^knownFlags != 0 {
		return fmt.Errorf("%w: 0x%02x", ErrReservedFlags, uint8(h.Flags&^knownFlags))
	}
	if (h.Flags&FlagPadding != 0) != (h.PadLength != 0) {
		return ErrPaddingFlag
	}
	if h.FrameSize() > MaxFrameSize {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, h.FrameSize())
	}
	return nil
}

// MarshalBinary encodes h in the DGPv1 little-endian wire format.
func (h Header) MarshalBinary() ([]byte, error) {
	if err := h.Validate(); err != nil {
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
	if decoded.FrameSize() > MaxFrameSize {
		return fmt.Errorf("%w: %d bytes", ErrFrameTooLarge, decoded.FrameSize())
	}

	*h = decoded
	return nil
}
