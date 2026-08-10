package dgpv1

import (
	"crypto/hmac"
	"encoding"
	"errors"
	"fmt"
	"math"
	"sync"
	"time"
)

var (
	// ErrSessionClosed indicates an operation on a closed or nil session.
	ErrSessionClosed = errors.New("dgpv1: session is closed")
	// ErrWrongSession indicates that a frame carries a different session ID.
	ErrWrongSession = errors.New("dgpv1: frame belongs to another session")
	// ErrSequenceExhausted indicates that no further send sequence can be allocated.
	ErrSequenceExhausted = errors.New("dgpv1: send sequence exhausted")
	// ErrMessageType indicates that a value or frame type is unavailable through the strict-MVP Session API.
	ErrMessageType = errors.New("dgpv1: message does not match encrypted frame type")
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

// Session owns directional codecs, sequence allocation, and receive replay
// state. Its exported methods are safe for concurrent use. The Session API is
// strict MVP: it rejects post-MVP message type 0x07.
type Session struct {
	sessionID [16]byte
	suite     CipherSuite

	sendMu          sync.Mutex
	send            *Codec
	sendKey         [KeySize]byte
	sendEpoch       uint32
	nextSequence    uint64
	sentInEpoch     uint64
	epochStarted    time.Time
	rekeyFrameLimit uint64
	rekeyInterval   time.Duration
	now             func() time.Time
	pendingRekey    *pendingSendRekey
	closed          bool

	receiveMu       sync.Mutex
	receive         *Codec
	receiveKey      [KeySize]byte
	receiveEpoch    uint32
	replay          ReplayWindow
	previousReceive *Codec
	previousReplay  ReplayWindow
	graceRemaining  uint64
	graceUntil      time.Time
	graceFrames     uint64
	gracePeriod     time.Duration
}

// NewSession opens a session from role-oriented handshake secrets.
func NewSession(suite CipherSuite, secrets HandshakeSecrets) (*Session, error) {
	if suite != CipherChaCha20Poly1305 {
		return nil, fmt.Errorf("%w: DGPv1 requires ChaCha20-Poly1305", ErrUnsupportedCipher)
	}
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
	now := time.Now
	return &Session{
		sessionID:       secrets.SessionID,
		suite:           suite,
		send:            send,
		sendKey:         secrets.SendKey,
		sendEpoch:       1,
		nextSequence:    1,
		epochStarted:    now(),
		rekeyFrameLimit: DefaultRekeyFrameLimit,
		rekeyInterval:   DefaultRekeyInterval,
		now:             now,
		receive:         receive,
		receiveKey:      secrets.ReceiveKey,
		receiveEpoch:    1,
		graceFrames:     DefaultRekeyGraceFrames,
		gracePeriod:     DefaultRekeyGracePeriod,
	}, nil
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

// ErrRekeyPending indicates that Send is blocked until the caller confirms
// that the previously returned RekeyInit was transmitted.
var ErrRekeyPending = errors.New("dgpv1: rekey frame has not been marked sent")

type pendingSendRekey struct {
	frame Frame
	key   [KeySize]byte
	codec *Codec
	epoch uint32
}

// Send marshals and encrypts a strict-MVP typed message. Nil typed-message
// pointers are rejected with ErrMessageType. It is safe for concurrent use. At
// a rekey boundary it returns an internally generated RekeyInit. A direct caller
// MUST transmit it, call MarkRekeySent, and retry the
// original message. Until then all sends fail with ErrRekeyPending, so no
// new-epoch application frame can overtake RekeyInit. Connection does this
// automatically.
func (s *Session) Send(message any, padLength uint8) (Frame, error) {
	if s == nil {
		return Frame{}, ErrSessionClosed
	}
	messageType, marshaler, err := outboundMessage(message)
	if err != nil {
		return Frame{}, err
	}
	plaintext, err := marshaler.MarshalBinary()
	if err != nil {
		return Frame{}, err
	}
	return s.sendPayload(messageType, plaintext, padLength)
}

// SendPayload encrypts an already encoded payload of an MVP encrypted message
// type. RekeyInit, message type 0x07, and handshake types are rejected. It uses
// the same MarkRekeySent protocol as Send.
func (s *Session) SendPayload(messageType MessageType, plaintext []byte, padLength uint8) (Frame, error) {
	if messageType == MessageTypeResumptionTicket {
		return Frame{}, fmt.Errorf("%w: 0x%02x is post-MVP", ErrMessageType, messageType)
	}
	if messageType == MessageTypeRekeyInit {
		return Frame{}, fmt.Errorf("%w: 0x%02x is generated by the session", ErrMessageType, messageType)
	}
	if s == nil {
		return Frame{}, ErrSessionClosed
	}
	return s.sendPayload(messageType, plaintext, padLength)
}

func (s *Session) sendPayload(messageType MessageType, plaintext []byte, padLength uint8) (Frame, error) {
	if !validSessionMessageType(messageType) {
		return Frame{}, fmt.Errorf("%w: 0x%02x", ErrMessageType, messageType)
	}

	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.closed {
		return Frame{}, ErrSessionClosed
	}
	if s.pendingRekey != nil {
		return Frame{}, ErrRekeyPending
	}
	if s.rekeyDueLocked() {
		return s.startRekeyLocked(padLength)
	}
	return s.encryptLocked(messageType, plaintext, padLength)
}

// MarkRekeySent commits the pending send-key transition after frame has been
// successfully transmitted. It rejects any frame other than the exact pending
// RekeyInit and is safe for concurrent use.
func (s *Session) MarkRekeySent(frame Frame) error {
	if s == nil {
		return ErrSessionClosed
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.closed {
		return ErrSessionClosed
	}
	if s.pendingRekey == nil || !sameRekeyFrame(s.pendingRekey.frame, frame) {
		return ErrRekeyPending
	}
	pending := s.pendingRekey
	s.sendKey, s.send, s.sendEpoch = pending.key, pending.codec, pending.epoch
	s.nextSequence, s.sentInEpoch, s.epochStarted = 1, 0, s.now()
	s.pendingRekey = nil
	return nil
}

func sameRekeyFrame(a, b Frame) bool {
	return a.Header == b.Header && a.Tag == b.Tag &&
		string(a.Payload) == string(b.Payload) && string(a.Padding) == string(b.Padding)
}

func (s *Session) encryptLocked(messageType MessageType, plaintext []byte, padLength uint8) (Frame, error) {
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
	s.sentInEpoch++
	return frame, nil
}

func (s *Session) rekeyDueLocked() bool {
	return (s.rekeyFrameLimit != 0 && s.sentInEpoch >= s.rekeyFrameLimit) ||
		(s.rekeyInterval > 0 && !s.now().Before(s.epochStarted.Add(s.rekeyInterval)))
}

func (s *Session) startRekeyLocked(padLength uint8) (Frame, error) {
	// Wrapping the epoch would reuse epoch zero and its sequence space, so
	// exhaustion is terminal for sending rather than a ratchet rollover.
	if s.sendEpoch == math.MaxUint32 {
		return Frame{}, ErrEpochExhausted
	}
	nextEpoch := s.sendEpoch + 1
	confirm, err := (&RekeyState{Epoch: s.sendEpoch}).ComputeKeyConfirm(s.sendKey[:], nextEpoch)
	if err != nil {
		return Frame{}, err
	}
	payload, err := (RekeyInit{Epoch: nextEpoch, KeyConfirm: confirm}).MarshalBinary()
	if err != nil {
		return Frame{}, err
	}
	frame, err := s.encryptLocked(MessageTypeRekeyInit, payload, padLength)
	if err != nil {
		return Frame{}, err
	}
	nextKey := deriveNextTrafficKey(s.sendKey)
	nextCodec, err := NewCodec(s.suite, nextKey[:])
	if err != nil {
		return Frame{}, err
	}
	s.pendingRekey = &pendingSendRekey{
		frame: frame,
		key:   nextKey,
		codec: nextCodec,
		epoch: nextEpoch,
	}
	return frame, nil
}

// Receive authenticates a frame, commits its sequence, and decodes its message.
// Reserved inbound header flags are ignored. Authentication failures do not
// commit replay state. RekeyInit is fully decoded and validated before its key,
// epoch, replay, and grace state are committed atomically. For other message
// types, an authenticated but malformed payload still consumes its sequence;
// retrying the same frame is therefore rejected as a replay.
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

// ReceivePayload validates and authenticates a frame before committing any
// receive state. Rekey validation, replay advancement, and the key transition
// are committed together while receiveMu is held.
func (s *Session) ReceivePayload(frame Frame) ([]byte, error) {
	if frame.Header.MessageType == MessageTypeResumptionTicket {
		return nil, fmt.Errorf("%w: 0x%02x is post-MVP", ErrMessageType, frame.Header.MessageType)
	}
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

	candidate, err := s.decryptEpochLocked(frame)
	if err != nil {
		return nil, err
	}
	if !candidate.current && frame.Header.MessageType == MessageTypeRekeyInit {
		return nil, fmt.Errorf("%w: rekey from previous epoch", ErrInvalidEpoch)
	}

	if candidate.current && frame.Header.MessageType == MessageTypeRekeyInit {
		var init RekeyInit
		if err := init.UnmarshalBinary(candidate.plaintext); err != nil {
			return nil, err
		}
		nextKey, nextCodec, err := s.prepareRekeyLocked(init)
		if err != nil {
			return nil, err
		}

		committedReplay := s.replay
		if err := committedReplay.Commit(candidate.token); err != nil {
			return nil, err
		}
		s.previousReceive, s.previousReplay = s.receive, committedReplay
		s.receive, s.receiveKey, s.receiveEpoch = nextCodec, nextKey, init.Epoch
		s.replay = ReplayWindow{}
		s.graceRemaining = s.graceFrames
		s.graceUntil = s.now().Add(s.gracePeriod)
		s.expireGraceLocked()
		return candidate.plaintext, nil
	}

	if candidate.current {
		committedReplay := s.replay
		if err := committedReplay.Commit(candidate.token); err != nil {
			return nil, err
		}
		s.replay = committedReplay
		if s.previousReceive != nil {
			if s.graceRemaining > 0 {
				s.graceRemaining--
			}
			s.expireGraceLocked()
		}
	} else {
		committedReplay := s.previousReplay
		if err := committedReplay.Commit(candidate.token); err != nil {
			return nil, err
		}
		s.previousReplay = committedReplay
	}
	return candidate.plaintext, nil
}

type receiveCandidate struct {
	plaintext []byte
	current   bool
	token     ReplayToken
}

func (s *Session) decryptEpochLocked(frame Frame) (receiveCandidate, error) {
	currentToken, currentCheck := s.replay.Check(frame.Header.Sequence)
	if currentCheck == nil {
		plaintext, err := s.receive.Decrypt(frame)
		if err == nil {
			return receiveCandidate{plaintext: plaintext, current: true, token: currentToken}, nil
		}
		if !errors.Is(err, ErrAuthentication) {
			return receiveCandidate{}, err
		}
	}

	previousAvailable := s.previousReceive != nil && s.graceRemaining > 0 &&
		s.gracePeriod > 0 && s.now().Before(s.graceUntil)
	if previousAvailable {
		previousToken, previousCheck := s.previousReplay.Check(frame.Header.Sequence)
		if previousCheck == nil || frame.Header.MessageType == MessageTypeRekeyInit {
			plaintext, err := s.previousReceive.Decrypt(frame)
			if err == nil {
				return receiveCandidate{plaintext: plaintext, current: false, token: previousToken}, nil
			}
			if !errors.Is(err, ErrAuthentication) {
				return receiveCandidate{}, err
			}
		}
		if currentCheck != nil && previousCheck != nil {
			return receiveCandidate{}, currentCheck
		}
	}
	if currentCheck != nil {
		return receiveCandidate{}, currentCheck
	}
	return receiveCandidate{}, ErrAuthentication
}

func (s *Session) prepareRekeyLocked(init RekeyInit) ([KeySize]byte, *Codec, error) {
	if s.receiveEpoch == math.MaxUint32 {
		return [KeySize]byte{}, nil, ErrEpochExhausted
	}
	if init.Epoch != s.receiveEpoch+1 {
		return [KeySize]byte{}, nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidEpoch, init.Epoch, s.receiveEpoch+1)
	}
	expected, err := (&RekeyState{Epoch: s.receiveEpoch}).ComputeKeyConfirm(s.receiveKey[:], init.Epoch)
	if err != nil {
		return [KeySize]byte{}, nil, err
	}
	if !hmac.Equal(expected[:], init.KeyConfirm[:]) {
		return [KeySize]byte{}, nil, ErrKeyConfirmFailed
	}
	nextKey := deriveNextTrafficKey(s.receiveKey)
	nextCodec, err := NewCodec(s.suite, nextKey[:])
	if err != nil {
		return [KeySize]byte{}, nil, err
	}
	return nextKey, nextCodec, nil
}

func (s *Session) expireGraceLocked() {
	// The retained key is usable only while both grace budgets remain; clearing
	// it eagerly prevents a later frame from reviving an expired epoch.
	if s.previousReceive == nil {
		return
	}
	if s.graceRemaining == 0 || s.gracePeriod <= 0 || !s.now().Before(s.graceUntil) {
		s.previousReceive = nil
		s.previousReplay = ReplayWindow{}
		s.graceRemaining = 0
		s.graceUntil = time.Time{}
	}
}

func validSessionMessageType(messageType MessageType) bool {
	return messageType >= MessageTypeEncryptedData && messageType <= MessageTypeError
}

func outboundMessage(message any) (MessageType, encoding.BinaryMarshaler, error) {
	var messageType MessageType
	switch typed := message.(type) {
	case EncryptedData:
		messageType = MessageTypeEncryptedData
	case *EncryptedData:
		if typed == nil {
			return 0, nil, fmt.Errorf("%w: nil %T", ErrMessageType, message)
		}
		messageType = MessageTypeEncryptedData
	case PingPong:
		messageType = MessageTypePingPong
	case *PingPong:
		if typed == nil {
			return 0, nil, fmt.Errorf("%w: nil %T", ErrMessageType, message)
		}
		messageType = MessageTypePingPong
	case SessionClose:
		messageType = MessageTypeSessionClose
	case *SessionClose:
		if typed == nil {
			return 0, nil, fmt.Errorf("%w: nil %T", ErrMessageType, message)
		}
		messageType = MessageTypeSessionClose
	case Ack:
		messageType = MessageTypeAck
	case *Ack:
		if typed == nil {
			return 0, nil, fmt.Errorf("%w: nil %T", ErrMessageType, message)
		}
		messageType = MessageTypeAck
	case ErrorMessage:
		messageType = MessageTypeError
	case *ErrorMessage:
		if typed == nil {
			return 0, nil, fmt.Errorf("%w: nil %T", ErrMessageType, message)
		}
		messageType = MessageTypeError
	default:
		return 0, nil, fmt.Errorf("%w: %T", ErrMessageType, message)
	}
	marshaler, ok := message.(encoding.BinaryMarshaler)
	if !ok {
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
