package dgpv1

import (
	"encoding"
	"errors"
	"fmt"
	"math"
	"sync"
)

var (
	ErrSessionClosed     = errors.New("dgpv1: session is closed")
	ErrWrongSession      = errors.New("dgpv1: frame belongs to another session")
	ErrSequenceExhausted = errors.New("dgpv1: send sequence exhausted")
	ErrMessageType       = errors.New("dgpv1: message does not match encrypted frame type")
)

// HandshakeSecrets is the directional material needed to open a session.
type HandshakeSecrets struct {
	SessionID  [16]byte
	SendKey    [KeySize]byte
	ReceiveKey [KeySize]byte
}

// Secrets returns an owned copy of the session material established by a handshake.
func (r HandshakeResult) Secrets() HandshakeSecrets {
	return HandshakeSecrets{SessionID: r.SessionID, SendKey: r.SendKey, ReceiveKey: r.ReceiveKey}
}

// Session owns directional codecs, sequence allocation, and receive replay state.
type Session struct {
	sessionID [16]byte
	send      *Codec
	receive   *Codec

	sendMu       sync.Mutex
	nextSequence uint64
	closed       bool

	receiveMu sync.Mutex
	replay    ReplayWindow
}

// NewSession opens a session from role-oriented handshake secrets.
func NewSession(suite CipherSuite, secrets HandshakeSecrets) (*Session, error) {
	if secrets.SessionID == ([16]byte{}) {
		return nil, ErrInvalidSessionID
	}
	send, err := NewCodec(suite, secrets.SendKey[:])
	if err != nil {
		return nil, err
	}
	receive, err := NewCodec(suite, secrets.ReceiveKey[:])
	if err != nil {
		return nil, err
	}
	return &Session{sessionID: secrets.SessionID, send: send, receive: receive, nextSequence: 1}, nil
}

// NewSessionFromHandshake opens a session from a completed handshake result.
func NewSessionFromHandshake(suite CipherSuite, result HandshakeResult) (*Session, error) {
	return NewSession(suite, result.Secrets())
}

// SessionID returns this session's identifier.
func (s *Session) SessionID() [16]byte {
	if s == nil {
		return [16]byte{}
	}
	return s.sessionID
}

// Close prevents subsequent sends and receives. It is idempotent.
func (s *Session) Close() error {
	if s == nil {
		return ErrSessionClosed
	}
	s.sendMu.Lock()
	s.receiveMu.Lock()
	s.closed = true
	s.receiveMu.Unlock()
	s.sendMu.Unlock()
	return nil
}

// Closed reports whether the session has been closed.
func (s *Session) Closed() bool {
	if s == nil {
		return true
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return s.closed
}

// Send marshals and encrypts a typed DGPv1 message.
func (s *Session) Send(message any, padLength uint8) (Frame, error) {
	messageType, marshaler, err := outboundMessage(message)
	if err != nil {
		return Frame{}, err
	}
	plaintext, err := marshaler.MarshalBinary()
	if err != nil {
		return Frame{}, err
	}
	return s.SendPayload(messageType, plaintext, padLength)
}

// SendPayload encrypts an already encoded payload of an encrypted message type.
func (s *Session) SendPayload(messageType MessageType, plaintext []byte, padLength uint8) (Frame, error) {
	if !validSessionMessageType(messageType) {
		return Frame{}, fmt.Errorf("%w: 0x%02x", ErrMessageType, messageType)
	}
	if s == nil {
		return Frame{}, ErrSessionClosed
	}

	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.closed {
		return Frame{}, ErrSessionClosed
	}
	if s.nextSequence == 0 {
		return Frame{}, ErrSequenceExhausted
	}
	sequence := s.nextSequence
	frame, err := s.send.Encrypt(messageType, s.sessionID, sequence, plaintext, padLength)
	if err != nil {
		return Frame{}, err
	}
	if sequence == math.MaxUint64 {
		s.nextSequence = 0
	} else {
		s.nextSequence++
	}
	return frame, nil
}

// Receive authenticates a frame, commits its sequence, and decodes its message.
func (s *Session) Receive(frame Frame) (any, error) {
	plaintext, err := s.ReceivePayload(frame)
	if err != nil {
		return nil, err
	}
	message, err := newInboundMessage(frame.Header.MessageType)
	if err != nil {
		return nil, err
	}
	if err := message.UnmarshalBinary(plaintext); err != nil {
		return nil, err
	}
	return message, nil
}

// ReceivePayload performs replay Check, AEAD authentication, then replay Commit.
func (s *Session) ReceivePayload(frame Frame) ([]byte, error) {
	if s == nil {
		return nil, ErrSessionClosed
	}
	if frame.Header.SessionID != s.sessionID {
		return nil, ErrWrongSession
	}
	if !validSessionMessageType(frame.Header.MessageType) {
		return nil, fmt.Errorf("%w: 0x%02x", ErrMessageType, frame.Header.MessageType)
	}

	s.receiveMu.Lock()
	defer s.receiveMu.Unlock()
	if s.closed {
		return nil, ErrSessionClosed
	}
	token, err := s.replay.Check(frame.Header.Sequence)
	if err != nil {
		return nil, err
	}
	plaintext, err := s.receive.Decrypt(frame)
	if err != nil {
		return nil, err
	}
	if err := s.replay.Commit(token); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func validSessionMessageType(messageType MessageType) bool {
	return messageType >= MessageTypeEncryptedData && messageType <= MessageTypeError
}

func outboundMessage(message any) (MessageType, encoding.BinaryMarshaler, error) {
	var messageType MessageType
	switch message.(type) {
	case EncryptedData, *EncryptedData:
		messageType = MessageTypeEncryptedData
	case PingPong, *PingPong:
		messageType = MessageTypePingPong
	case SessionClose, *SessionClose:
		messageType = MessageTypeSessionClose
	case Ack, *Ack:
		messageType = MessageTypeAck
	case RekeyInit, *RekeyInit:
		messageType = MessageTypeRekeyInit
	case ErrorMessage, *ErrorMessage:
		messageType = MessageTypeError
	default:
		return 0, nil, fmt.Errorf("%w: %T", ErrMessageType, message)
	}
	marshaler, ok := message.(encoding.BinaryMarshaler)
	if !ok || marshaler == nil {
		return 0, nil, fmt.Errorf("%w: %T", ErrMessageType, message)
	}
	return messageType, marshaler, nil
}

func newInboundMessage(messageType MessageType) (encoding.BinaryUnmarshaler, error) {
	switch messageType {
	case MessageTypeEncryptedData:
		return &EncryptedData{}, nil
	case MessageTypePingPong:
		return &PingPong{}, nil
	case MessageTypeSessionClose:
		return &SessionClose{}, nil
	case MessageTypeAck:
		return &Ack{}, nil
	case MessageTypeRekeyInit:
		return &RekeyInit{}, nil
	case MessageTypeError:
		return &ErrorMessage{}, nil
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrMessageType, messageType)
	}
}
