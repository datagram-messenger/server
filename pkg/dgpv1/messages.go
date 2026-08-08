package dgpv1

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unicode/utf8"
)

const (
	// HandshakeInitFixedSize is the 36-byte Noise XX message-one wrapper size.
	HandshakeInitFixedSize = 36
	// HandshakeResponseFixedSize is the 32-byte server-ephemeral prefix size.
	HandshakeResponseFixedSize = 32
	// HandshakeFinishFixedSize is the 64-byte Noise XX final-flight size.
	HandshakeFinishFixedSize = 64
	// PingPongSize is the fixed ping or pong payload size.
	PingPongSize = 9
	// RekeyInitSize is the fixed rekey payload size.
	RekeyInitSize = 36
	// MaxAckSequences is the largest number of sequences in one Ack.
	MaxAckSequences = 64
	// MaxEncryptedPayloadSize excludes the header and 16-byte AEAD tag.
	MaxEncryptedPayloadSize = MaxFrameSize - HeaderSize - AEADTagSize
	// MaxHandshakePayloadSize excludes the header; handshakes have no outer tag.
	MaxHandshakePayloadSize = MaxFrameSize - HeaderSize
	// MaxResumptionTicketSize is the post-MVP ticket byte limit.
	MaxResumptionTicketSize = MaxEncryptedPayloadSize - 8
	// MaxReasonSize is the largest text value whose aligned TLV and message code
	// fit in the DGPv1 maximum encrypted frame payload.
	MaxReasonSize = MaxEncryptedPayloadSize - 2 - TLVHeaderSize - 1

	textTLVType = 1
)

var (
	// ErrMessageTooShort indicates that a message lacks its required fixed prefix.
	ErrMessageTooShort = errors.New("dgpv1: message payload too short")
	// ErrMessageLength indicates that a message payload has an invalid encoded length.
	ErrMessageLength = errors.New("dgpv1: invalid message payload length")
	// ErrMessageReserved indicates that a reserved message field is nonzero.
	ErrMessageReserved = errors.New("dgpv1: reserved message field must be zero")
	// ErrInvalidNoisePattern indicates an unregistered Noise pattern value.
	ErrInvalidNoisePattern = errors.New("dgpv1: invalid Noise pattern")
	// ErrHandshakeAlignment indicates that a handshake payload is not 4-byte aligned.
	ErrHandshakeAlignment = errors.New("dgpv1: handshake payload must be 4-byte aligned")
	// ErrUnexpectedNoiseData indicates that a Noise XX initial wrapper carries extra payload.
	ErrUnexpectedNoiseData = errors.New("dgpv1: Noise XX initial payload must be empty")
	// ErrInvalidPingResponse indicates that the ping response byte is neither zero nor one.
	ErrInvalidPingResponse = errors.New("dgpv1: invalid ping response flag")
	// ErrAckCount indicates that an acknowledgement contains fewer than one or more than MaxAckSequences entries.
	ErrAckCount = errors.New("dgpv1: acknowledgement count must be between 1 and 64")
	// ErrInvalidUTF8 indicates that a textual message field is not valid UTF-8.
	ErrInvalidUTF8 = errors.New("dgpv1: text is not valid UTF-8")
	// ErrReasonTooLong indicates that a textual message field exceeds MaxReasonSize.
	ErrReasonTooLong = errors.New("dgpv1: reason exceeds maximum length")
	// ErrUnknownMessageTLV indicates an unsupported TLV in a typed protocol message.
	ErrUnknownMessageTLV = errors.New("dgpv1: unknown message TLV")
	// ErrDuplicateMessageTLV indicates repeated TLV types where a typed message requires uniqueness.
	ErrDuplicateMessageTLV = errors.New("dgpv1: duplicate message TLV")
	// ErrInvalidCloseCode indicates a SessionClose code outside the MVP range zero through three.
	ErrInvalidCloseCode = errors.New("dgpv1: invalid close code")
	// ErrResumptionTicket indicates an invalid post-MVP resumption-ticket encoding.
	ErrResumptionTicket = errors.New("dgpv1: invalid resumption ticket")
)

// NoisePattern identifies a Noise handshake pattern in the wire wrapper.
// The strict MVP handshake implementation accepts only NoisePatternXX.
type NoisePattern uint8

const (
	// NoisePatternXX identifies the Noise XX pattern used by the strict MVP.
	NoisePatternXX NoisePattern = 1
	// NoisePatternIK identifies the registered Noise IK pattern, which the strict-MVP Handshake does not execute.
	NoisePatternIK NoisePattern = 2
)

// HandshakeInit is the explicitly defined outer wrapper around Noise message 1.
type HandshakeInit struct {
	// Pattern identifies the wrapped Noise handshake pattern.
	Pattern NoisePattern
	// ClientEphemeral is the 32-byte client ephemeral public key.
	ClientEphemeral [32]byte
	// NoisePayload contains Noise handshake bytes.
	NoisePayload []byte
}

// MarshalBinary encodes m as a handshake-init payload and returns owned storage.
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

// UnmarshalBinary decodes a handshake-init payload and copies NoisePayload.
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
	// ServerEphemeral is the 32-byte server ephemeral public key.
	ServerEphemeral [32]byte
	// NoisePayload contains Noise handshake bytes.
	NoisePayload []byte
}

// MarshalBinary encodes m as a handshake-response payload and returns owned storage.
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

// UnmarshalBinary decodes a handshake-response payload and copies NoisePayload.
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
	// NoisePayload is the fixed 64-byte final Noise XX flight.
	NoisePayload []byte
}

// MarshalBinary validates and copies the fixed-size final Noise XX flight.
func (m HandshakeFinish) MarshalBinary() ([]byte, error) {
	if len(m.NoisePayload) != HandshakeFinishFixedSize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrMessageLength, len(m.NoisePayload), HandshakeFinishFixedSize)
	}
	return append([]byte(nil), m.NoisePayload...), nil
}

// UnmarshalBinary decodes and copies the fixed-size final Noise XX flight.
func (m *HandshakeFinish) UnmarshalBinary(data []byte) error {
	if len(data) != HandshakeFinishFixedSize {
		return fmt.Errorf("%w: got %d, want %d", ErrMessageLength, len(data), HandshakeFinishFixedSize)
	}
	*m = HandshakeFinish{NoisePayload: append([]byte(nil), data...)}
	return nil
}

// EncryptedData is the application envelope carried inside an encrypted frame.
type EncryptedData struct {
	// StreamID identifies the application stream.
	StreamID uint16
	// AppMessageType identifies the application-defined message kind.
	AppMessageType uint8
	// Fields contains uniquely typed application TLVs.
	Fields []TLV
}

// MarshalBinary encodes m, rejecting duplicate field types, and returns owned storage.
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

// UnmarshalBinary decodes data into m and copies all TLV values.
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

// ResumptionTicket is a wire-registry representation reserved for post-MVP.
// The MVP Session API rejects this message type.
type ResumptionTicket struct {
	// Ticket contains the opaque post-MVP ticket bytes.
	Ticket []byte
	// ValidUntil contains the encoded ticket-expiration value.
	ValidUntil uint64
}

// MarshalBinary encodes the post-MVP ticket representation and returns owned storage.
func (m ResumptionTicket) MarshalBinary() ([]byte, error) {
	if len(m.Ticket) == 0 || len(m.Ticket) > MaxResumptionTicketSize {
		return nil, fmt.Errorf("%w: ticket length %d", ErrResumptionTicket, len(m.Ticket))
	}
	buf := make([]byte, len(m.Ticket)+8)
	copy(buf, m.Ticket)
	binary.LittleEndian.PutUint64(buf[len(m.Ticket):], m.ValidUntil)
	return buf, nil
}

// UnmarshalBinary decodes the post-MVP ticket representation and copies Ticket.
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
	// IsResponse distinguishes a pong from a ping.
	IsResponse bool
	// Nonce correlates a response with its request.
	Nonce uint64
}

// MarshalBinary encodes m as the fixed-size ping or pong payload.
func (m PingPong) MarshalBinary() ([]byte, error) {
	buf := make([]byte, PingPongSize)
	if m.IsResponse {
		buf[0] = 1
	}
	binary.LittleEndian.PutUint64(buf[1:], m.Nonce)
	return buf, nil
}

// UnmarshalBinary decodes a fixed-size ping or pong payload into m.
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
type Ack struct {
	// Sequences contains the acknowledged sequence numbers.
	Sequences []uint64
}

// MarshalBinary encodes one to MaxAckSequences sequence numbers.
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

// UnmarshalBinary decodes an acknowledgement payload into newly allocated Sequences.
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
	// Epoch is the nonzero proposed key epoch.
	Epoch uint32
	// KeyConfirm authenticates the proposed epoch key.
	KeyConfirm [32]byte
}

// MarshalBinary encodes m as the fixed-size rekey-init payload.
func (m RekeyInit) MarshalBinary() ([]byte, error) {
	if m.Epoch == 0 {
		return nil, ErrInvalidEpoch
	}
	buf := make([]byte, RekeyInitSize)
	binary.LittleEndian.PutUint32(buf[:4], m.Epoch)
	copy(buf[4:], m.KeyConfirm[:])
	return buf, nil
}

// UnmarshalBinary decodes a fixed-size rekey-init payload into m.
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
	// Code is an MVP close code in the range zero through three.
	Code uint16
	// Reason is optional UTF-8 close text.
	Reason string
}

// MarshalBinary encodes the close code and optional UTF-8 reason.
func (m SessionClose) MarshalBinary() ([]byte, error) {
	if m.Code > 3 {
		return nil, fmt.Errorf("%w: 0x%04x", ErrInvalidCloseCode, m.Code)
	}
	return marshalTextMessage(m.Code, m.Reason)
}

// UnmarshalBinary decodes a session-close payload into m.
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
	// Code identifies the reported protocol condition.
	Code uint16
	// Context is optional UTF-8 diagnostic text.
	Context string
}

// MarshalBinary encodes the error code and optional UTF-8 context.
func (m ErrorMessage) MarshalBinary() ([]byte, error) { return marshalTextMessage(m.Code, m.Context) }

// UnmarshalBinary decodes an error-message payload into m.
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
