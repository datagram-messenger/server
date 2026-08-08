package dgpv1

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	HandshakeInitFixedSize     = 36
	HandshakeResponseFixedSize = 32
	HandshakeFinishFixedSize   = 64
	PingPongSize               = 9
	RekeyInitSize              = 36
	MaxAckSequences            = 64
	MaxEncryptedPayloadSize    = MaxFrameSize - HeaderSize - AEADTagSize
	MaxHandshakePayloadSize    = MaxFrameSize - HeaderSize
	MaxResumptionTicketSize    = MaxEncryptedPayloadSize - 8
	// MaxReasonSize is the largest text value whose aligned TLV and message code
	// fit in the DGPv1 maximum encrypted frame payload.
	MaxReasonSize = MaxEncryptedPayloadSize - 2 - TLVHeaderSize - 1

	textTLVType = 1
)

var (
	ErrMessageTooShort     = errors.New("dgpv1: message payload too short")
	ErrMessageLength       = errors.New("dgpv1: invalid message payload length")
	ErrMessageReserved     = errors.New("dgpv1: reserved message field must be zero")
	ErrInvalidNoisePattern = errors.New("dgpv1: invalid Noise pattern")
	ErrHandshakeAlignment  = errors.New("dgpv1: handshake payload must be 4-byte aligned")
	ErrUnexpectedNoiseData = errors.New("dgpv1: Noise XX initial payload must be empty")
	ErrInvalidPingResponse = errors.New("dgpv1: invalid ping response flag")
	ErrAckCount            = errors.New("dgpv1: acknowledgement count must be between 1 and 64")
	ErrInvalidUTF8         = errors.New("dgpv1: text is not valid UTF-8")
	ErrReasonTooLong       = errors.New("dgpv1: reason exceeds maximum length")
	ErrUnknownMessageTLV   = errors.New("dgpv1: unknown message TLV")
	ErrDuplicateMessageTLV = errors.New("dgpv1: duplicate message TLV")
	ErrInvalidCloseCode    = errors.New("dgpv1: invalid close code")
	ErrResumptionTicket    = errors.New("dgpv1: invalid resumption ticket")
)

type NoisePattern uint8

const (
	NoisePatternXX NoisePattern = 1
	NoisePatternIK NoisePattern = 2
)

// HandshakeInit is the explicitly defined outer wrapper around Noise message 1.
type HandshakeInit struct {
	Pattern         NoisePattern
	ClientEphemeral [32]byte
	NoisePayload    []byte
}

func (m HandshakeInit) MarshalBinary() ([]byte, error) {
	if m.Pattern != NoisePatternXX && m.Pattern != NoisePatternIK {
		return nil, fmt.Errorf("%w: 0x%02x", ErrInvalidNoisePattern, m.Pattern)
	}
	if m.Pattern == NoisePatternXX && len(m.NoisePayload) != 0 {
		return nil, ErrUnexpectedNoiseData
	}
	total := HandshakeInitFixedSize + len(m.NoisePayload)
	if total > MaxHandshakePayloadSize {
		return nil, fmt.Errorf("%w: got %d, limit %d", ErrMessageLength, total, MaxHandshakePayloadSize)
	}
	if total%4 != 0 {
		return nil, ErrHandshakeAlignment
	}
	buf := make([]byte, total)
	buf[0] = byte(m.Pattern)
	copy(buf[4:36], m.ClientEphemeral[:])
	copy(buf[36:], m.NoisePayload)
	return buf, nil
}

func (m *HandshakeInit) UnmarshalBinary(data []byte) error {
	if len(data) < HandshakeInitFixedSize {
		return fmt.Errorf("%w: got %d, want at least %d", ErrMessageTooShort, len(data), HandshakeInitFixedSize)
	}
	if len(data) > MaxHandshakePayloadSize {
		return fmt.Errorf("%w: got %d, limit %d", ErrMessageLength, len(data), MaxHandshakePayloadSize)
	}
	if len(data)%4 != 0 {
		return ErrHandshakeAlignment
	}
	pattern := NoisePattern(data[0])
	if pattern != NoisePatternXX && pattern != NoisePatternIK {
		return fmt.Errorf("%w: 0x%02x", ErrInvalidNoisePattern, pattern)
	}
	if data[1] != 0 || data[2] != 0 || data[3] != 0 {
		return ErrMessageReserved
	}
	if pattern == NoisePatternXX && len(data) != HandshakeInitFixedSize {
		return ErrUnexpectedNoiseData
	}
	var ephemeral [32]byte
	copy(ephemeral[:], data[4:36])
	*m = HandshakeInit{Pattern: pattern, ClientEphemeral: ephemeral, NoisePayload: append([]byte(nil), data[36:]...)}
	return nil
}

// HandshakeResponse is the defined outer wrapper around the server Noise flight.
type HandshakeResponse struct {
	ServerEphemeral [32]byte
	NoisePayload    []byte
}

func (m HandshakeResponse) MarshalBinary() ([]byte, error) {
	total := HandshakeResponseFixedSize + len(m.NoisePayload)
	if total > MaxHandshakePayloadSize {
		return nil, fmt.Errorf("%w: got %d, limit %d", ErrMessageLength, total, MaxHandshakePayloadSize)
	}
	if total%4 != 0 {
		return nil, ErrHandshakeAlignment
	}
	buf := make([]byte, total)
	copy(buf[:32], m.ServerEphemeral[:])
	copy(buf[32:], m.NoisePayload)
	return buf, nil
}

func (m *HandshakeResponse) UnmarshalBinary(data []byte) error {
	if len(data) < HandshakeResponseFixedSize {
		return fmt.Errorf("%w: got %d, want at least %d", ErrMessageTooShort, len(data), HandshakeResponseFixedSize)
	}
	if len(data) > MaxHandshakePayloadSize {
		return fmt.Errorf("%w: got %d, limit %d", ErrMessageLength, len(data), MaxHandshakePayloadSize)
	}
	if len(data)%4 != 0 {
		return ErrHandshakeAlignment
	}
	var ephemeral [32]byte
	copy(ephemeral[:], data[:32])
	*m = HandshakeResponse{ServerEphemeral: ephemeral, NoisePayload: append([]byte(nil), data[32:]...)}
	return nil
}

// HandshakeFinish carries the third and final Noise XX flight.
type HandshakeFinish struct {
	NoisePayload []byte
}

func (m HandshakeFinish) MarshalBinary() ([]byte, error) {
	if len(m.NoisePayload) != HandshakeFinishFixedSize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrMessageLength, len(m.NoisePayload), HandshakeFinishFixedSize)
	}
	return append([]byte(nil), m.NoisePayload...), nil
}

func (m *HandshakeFinish) UnmarshalBinary(data []byte) error {
	if len(data) != HandshakeFinishFixedSize {
		return fmt.Errorf("%w: got %d, want %d", ErrMessageLength, len(data), HandshakeFinishFixedSize)
	}
	*m = HandshakeFinish{NoisePayload: append([]byte(nil), data...)}
	return nil
}

// EncryptedData is the application envelope carried inside an encrypted frame.
type EncryptedData struct {
	StreamID       uint16
	AppMessageType uint8
	Fields         []TLV
}

func (m EncryptedData) MarshalBinary() ([]byte, error) {
	if err := rejectDuplicateTLVs(m.Fields); err != nil {
		return nil, err
	}
	fields, err := EncodeTLVs(m.Fields)
	if err != nil {
		return nil, err
	}
	if len(fields) > MaxEncryptedPayloadSize-4 {
		return nil, fmt.Errorf("%w: got %d, limit %d", ErrMessageLength, 4+len(fields), MaxEncryptedPayloadSize)
	}
	buf := make([]byte, 4, 4+len(fields))
	binary.LittleEndian.PutUint16(buf[:2], m.StreamID)
	buf[2] = m.AppMessageType
	return append(buf, fields...), nil
}

func (m *EncryptedData) UnmarshalBinary(data []byte) error {
	if len(data) < 4 {
		return fmt.Errorf("%w: got %d, want at least 4", ErrMessageTooShort, len(data))
	}
	if data[3] != 0 {
		return ErrMessageReserved
	}
	fields, err := DecodeTLVs(data[4:], MaxEncryptedPayloadSize-4)
	if err != nil {
		return err
	}
	if err := rejectDuplicateTLVs(fields); err != nil {
		return err
	}
	*m = EncryptedData{StreamID: binary.LittleEndian.Uint16(data[:2]), AppMessageType: data[2], Fields: fields}
	return nil
}

// ResumptionTicket carries the opaque server ticket followed by its expiry.
type ResumptionTicket struct {
	Ticket     []byte
	ValidUntil uint64
}

func (m ResumptionTicket) MarshalBinary() ([]byte, error) {
	if len(m.Ticket) == 0 || len(m.Ticket) > MaxResumptionTicketSize {
		return nil, fmt.Errorf("%w: ticket length %d", ErrResumptionTicket, len(m.Ticket))
	}
	buf := make([]byte, len(m.Ticket)+8)
	copy(buf, m.Ticket)
	binary.LittleEndian.PutUint64(buf[len(m.Ticket):], m.ValidUntil)
	return buf, nil
}

func (m *ResumptionTicket) UnmarshalBinary(data []byte) error {
	if len(data) < 9 || len(data) > MaxEncryptedPayloadSize {
		return fmt.Errorf("%w: payload length %d", ErrResumptionTicket, len(data))
	}
	ticketEnd := len(data) - 8
	*m = ResumptionTicket{Ticket: append([]byte(nil), data[:ticketEnd]...), ValidUntil: binary.LittleEndian.Uint64(data[ticketEnd:])}
	return nil
}

func rejectDuplicateTLVs(fields []TLV) error {
	var seen [256]bool
	for _, field := range fields {
		if seen[field.Type] {
			return fmt.Errorf("%w: 0x%02x", ErrDuplicateMessageTLV, field.Type)
		}
		seen[field.Type] = true
	}
	return nil
}

// PingPong carries a keepalive nonce and whether it is a response.
type PingPong struct {
	IsResponse bool
	Nonce      uint64
}

func (m PingPong) MarshalBinary() ([]byte, error) {
	buf := make([]byte, PingPongSize)
	if m.IsResponse {
		buf[0] = 1
	}
	binary.LittleEndian.PutUint64(buf[1:], m.Nonce)
	return buf, nil
}

func (m *PingPong) UnmarshalBinary(data []byte) error {
	if len(data) != PingPongSize {
		return fmt.Errorf("%w: got %d, want %d", ErrMessageLength, len(data), PingPongSize)
	}
	if data[0] > 1 {
		return fmt.Errorf("%w: 0x%02x", ErrInvalidPingResponse, data[0])
	}
	*m = PingPong{IsResponse: data[0] == 1, Nonce: binary.LittleEndian.Uint64(data[1:])}
	return nil
}

// Ack selectively acknowledges one to 64 sequence numbers.
type Ack struct{ Sequences []uint64 }

func (m Ack) MarshalBinary() ([]byte, error) {
	if len(m.Sequences) < 1 || len(m.Sequences) > MaxAckSequences {
		return nil, fmt.Errorf("%w: got %d", ErrAckCount, len(m.Sequences))
	}
	buf := make([]byte, 1+8*len(m.Sequences))
	buf[0] = byte(len(m.Sequences))
	for i, sequence := range m.Sequences {
		binary.LittleEndian.PutUint64(buf[1+8*i:], sequence)
	}
	return buf, nil
}

func (m *Ack) UnmarshalBinary(data []byte) error {
	if len(data) < 1 {
		return ErrMessageTooShort
	}
	count := int(data[0])
	if count < 1 || count > MaxAckSequences {
		return fmt.Errorf("%w: got %d", ErrAckCount, count)
	}
	if len(data) != 1+8*count {
		return fmt.Errorf("%w: got %d, want %d", ErrMessageLength, len(data), 1+8*count)
	}
	sequences := make([]uint64, count)
	for i := range sequences {
		sequences[i] = binary.LittleEndian.Uint64(data[1+8*i:])
	}
	*m = Ack{Sequences: sequences}
	return nil
}

// RekeyInit announces a new epoch and carries its key confirmation value.
type RekeyInit struct {
	Epoch      uint32
	KeyConfirm [32]byte
}

func (m RekeyInit) MarshalBinary() ([]byte, error) {
	if m.Epoch == 0 {
		return nil, ErrInvalidEpoch
	}
	buf := make([]byte, RekeyInitSize)
	binary.LittleEndian.PutUint32(buf[:4], m.Epoch)
	copy(buf[4:], m.KeyConfirm[:])
	return buf, nil
}

func (m *RekeyInit) UnmarshalBinary(data []byte) error {
	if len(data) != RekeyInitSize {
		return fmt.Errorf("%w: got %d, want %d", ErrMessageLength, len(data), RekeyInitSize)
	}
	epoch := binary.LittleEndian.Uint32(data[:4])
	if epoch == 0 {
		return ErrInvalidEpoch
	}
	var confirm [32]byte
	copy(confirm[:], data[4:])
	*m = RekeyInit{Epoch: epoch, KeyConfirm: confirm}
	return nil
}

// SessionClose requests graceful termination with an optional UTF-8 reason.
type SessionClose struct {
	Code   uint16
	Reason string
}

func (m SessionClose) MarshalBinary() ([]byte, error) {
	if m.Code > 3 {
		return nil, fmt.Errorf("%w: 0x%04x", ErrInvalidCloseCode, m.Code)
	}
	return marshalTextMessage(m.Code, m.Reason)
}
func (m *SessionClose) UnmarshalBinary(data []byte) error {
	code, text, err := unmarshalTextMessage(data)
	if err != nil {
		return err
	}
	if code > 3 {
		return fmt.Errorf("%w: 0x%04x", ErrInvalidCloseCode, code)
	}
	*m = SessionClose{Code: code, Reason: text}
	return nil
}

// ErrorMessage reports a recoverable protocol condition with optional context.
type ErrorMessage struct {
	Code    uint16
	Context string
}

func (m ErrorMessage) MarshalBinary() ([]byte, error) { return marshalTextMessage(m.Code, m.Context) }
func (m *ErrorMessage) UnmarshalBinary(data []byte) error {
	code, text, err := unmarshalTextMessage(data)
	if err == nil {
		*m = ErrorMessage{Code: code, Context: text}
	}
	return err
}

func marshalTextMessage(code uint16, text string) ([]byte, error) {
	if !utf8.ValidString(text) {
		return nil, ErrInvalidUTF8
	}
	if len(text) > MaxReasonSize {
		return nil, fmt.Errorf("%w: got %d", ErrReasonTooLong, len(text))
	}
	buf := make([]byte, 2)
	binary.LittleEndian.PutUint16(buf, code)
	if text == "" {
		return buf, nil
	}
	field, _ := NewTLV(textTLVType, []byte(text))
	encoded, err := field.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return append(buf, encoded...), nil
}

func unmarshalTextMessage(data []byte) (uint16, string, error) {
	if len(data) < 2 {
		return 0, "", ErrMessageTooShort
	}
	code := binary.LittleEndian.Uint16(data[:2])
	if len(data) == 2 {
		return code, "", nil
	}
	fields, err := DecodeTLVs(data[2:], align4(TLVHeaderSize+MaxReasonSize))
	if err != nil {
		return 0, "", err
	}
	if err := rejectDuplicateTLVs(fields); err != nil {
		return 0, "", err
	}
	if len(fields) != 1 {
		return 0, "", ErrUnknownMessageTLV
	}
	if fields[0].Type != textTLVType {
		return 0, "", fmt.Errorf("%w: 0x%02x", ErrUnknownMessageTLV, fields[0].Type)
	}
	if !utf8.Valid(fields[0].Value) {
		return 0, "", ErrInvalidUTF8
	}
	return code, string(fields[0].Value), nil
}
