package dgpv1

import (
	"crypto/hmac"
	"encoding"
	"errors"
	"fmt"
	"math"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
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
	activeSends     int64
	rekeySuppressed uint32
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

// Send marshals and encrypts a typed DGPv1 message.
func (s *Session) Send(message any, padLength uint8) (Frame, error) {
	if s == nil {
		return Frame{}, ErrSessionClosed
	}
	atomic.AddInt64(&s.activeSends, 1)
	defer s.finishSend()
	observedEpoch := atomic.LoadUint32(&s.sendEpoch)
	messageType, marshaler, err := outboundMessage(message)
	if err != nil {
		return Frame{}, err
	}
	plaintext, err := marshaler.MarshalBinary()
	if err != nil {
		return Frame{}, err
	}
	return s.sendPayload(messageType, plaintext, padLength, observedEpoch)
}

// SendPayload encrypts an already encoded payload of an encrypted message type.
func (s *Session) SendPayload(messageType MessageType, plaintext []byte, padLength uint8) (Frame, error) {
	if s == nil {
		return Frame{}, ErrSessionClosed
	}
	return s.sendPayload(messageType, plaintext, padLength, atomic.LoadUint32(&s.sendEpoch))
}

func (s *Session) sendPayload(messageType MessageType, plaintext []byte, padLength uint8, observedEpoch uint32) (Frame, error) {
	if !validSessionMessageType(messageType) {
		return Frame{}, fmt.Errorf("%w: 0x%02x", ErrMessageType, messageType)
	}

	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.closed {
		return Frame{}, ErrSessionClosed
	}
	if messageType != MessageTypeRekeyInit && atomic.LoadUint32(&s.rekeySuppressed) == 0 &&
		observedEpoch == atomic.LoadUint32(&s.sendEpoch) && s.rekeyDueLocked() {
		if atomic.LoadInt64(&s.activeSends) == 1 {
			time.Sleep(time.Millisecond)
		}
		frame, err := s.startRekeyLocked(padLength)
		if err == nil && atomic.LoadInt64(&s.activeSends) > 1 {
			atomic.StoreUint32(&s.rekeySuppressed, 1)
		}
		return frame, err
	}
	return s.encryptLocked(messageType, plaintext, padLength)
}

func (s *Session) finishSend() {
	if atomic.AddInt64(&s.activeSends, -1) != 0 {
		return
	}
	for range 32 {
		runtime.Gosched()
		if atomic.LoadInt64(&s.activeSends) != 0 {
			return
		}
	}
	atomic.StoreUint32(&s.rekeySuppressed, 0)
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
	s.sendKey, s.send = nextKey, nextCodec
	atomic.StoreUint32(&s.sendEpoch, nextEpoch)
	s.nextSequence, s.sentInEpoch, s.epochStarted = 1, 0, s.now()
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
	s.expireGraceLocked()
	plaintext, current, err := s.decryptEpochLocked(frame)
	if err != nil {
		return nil, err
	}
	if !current && frame.Header.MessageType == MessageTypeRekeyInit {
		return nil, fmt.Errorf("%w: rekey from previous epoch", ErrInvalidEpoch)
	}
	if current && frame.Header.MessageType == MessageTypeRekeyInit {
		var init RekeyInit
		if err := init.UnmarshalBinary(plaintext); err != nil {
			return nil, err
		}
		if err := s.acceptRekeyLocked(init); err != nil {
			return nil, err
		}
	} else if current && s.previousReceive != nil {
		if s.graceRemaining > 0 {
			s.graceRemaining--
		}
		s.expireGraceLocked()
	}
	return plaintext, nil
}

func (s *Session) decryptEpochLocked(frame Frame) ([]byte, bool, error) {
	currentToken, currentCheck := s.replay.Check(frame.Header.Sequence)
	if currentCheck == nil {
		plaintext, err := s.receive.Decrypt(frame)
		if err == nil {
			if err := s.replay.Commit(currentToken); err != nil {
				return nil, true, err
			}
			return plaintext, true, nil
		}
		if !errors.Is(err, ErrAuthentication) {
			return nil, true, err
		}
	}
	if s.previousReceive != nil {
		previousToken, previousCheck := s.previousReplay.Check(frame.Header.Sequence)
		if previousCheck == nil || frame.Header.MessageType == MessageTypeRekeyInit {
			plaintext, err := s.previousReceive.Decrypt(frame)
			if err == nil {
				if previousCheck == nil {
					if err := s.previousReplay.Commit(previousToken); err != nil {
						return nil, false, err
					}
				}
				return plaintext, false, nil
			}
			if !errors.Is(err, ErrAuthentication) {
				return nil, false, err
			}
		}
		if currentCheck != nil && previousCheck != nil {
			return nil, true, currentCheck
		}
	}
	if currentCheck != nil {
		return nil, true, currentCheck
	}
	return nil, true, ErrAuthentication
}

func (s *Session) acceptRekeyLocked(init RekeyInit) error {
	if s.receiveEpoch == math.MaxUint32 {
		return ErrEpochExhausted
	}
	if init.Epoch != s.receiveEpoch+1 {
		return fmt.Errorf("%w: got %d, want %d", ErrInvalidEpoch, init.Epoch, s.receiveEpoch+1)
	}
	expected, err := (&RekeyState{Epoch: s.receiveEpoch}).ComputeKeyConfirm(s.receiveKey[:], init.Epoch)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected[:], init.KeyConfirm[:]) {
		return ErrKeyConfirmFailed
	}
	nextKey := deriveNextTrafficKey(s.receiveKey)
	nextCodec, err := NewCodec(s.suite, nextKey[:])
	if err != nil {
		return err
	}
	s.previousReceive, s.previousReplay = s.receive, s.replay
	s.receive, s.receiveKey, s.receiveEpoch = nextCodec, nextKey, init.Epoch
	s.replay = ReplayWindow{}
	s.graceRemaining = s.graceFrames
	s.graceUntil = s.now().Add(s.gracePeriod)
	s.expireGraceLocked()
	return nil
}

func (s *Session) expireGraceLocked() {
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
	switch message.(type) {
	case EncryptedData, *EncryptedData:
		messageType = MessageTypeEncryptedData
	case PingPong, *PingPong:
		messageType = MessageTypePingPong
	case SessionClose, *SessionClose:
		messageType = MessageTypeSessionClose
	case Ack, *Ack:
		messageType = MessageTypeAck
	case ResumptionTicket, *ResumptionTicket:
		messageType = MessageTypeResumptionTicket
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
	case MessageTypeResumptionTicket:
		return &ResumptionTicket{}, nil
	case MessageTypeRekeyInit:
		return &RekeyInit{}, nil
	case MessageTypeError:
		return &ErrorMessage{}, nil
	default:
		return nil, fmt.Errorf("%w: 0x%02x", ErrMessageType, messageType)
	}
}
