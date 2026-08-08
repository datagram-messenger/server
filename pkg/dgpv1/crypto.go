package dgpv1

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const KeySize = 32

var (
	ErrInvalidKeySize    = errors.New("dgpv1: invalid key size")
	ErrUnsupportedCipher = errors.New("dgpv1: unsupported cipher suite")
	ErrUnencryptedType   = errors.New("dgpv1: message type is not encrypted data")
	ErrInvalidSequence   = errors.New("dgpv1: encrypted frame sequence must be nonzero")
	ErrInvalidSessionID  = errors.New("dgpv1: encrypted frame session ID must be nonzero")
	ErrAuthentication    = errors.New("dgpv1: authentication failed")
)

// CipherSuite identifies a DGPv1 data-frame AEAD.
type CipherSuite uint8

const (
	CipherChaCha20Poly1305 CipherSuite = iota + 1
	CipherAES256GCM
)

// Codec performs stateless DGPv1 data-frame authenticated encryption. Session
// state owns sequence allocation, replay protection, direction, and epochs.
type Codec struct {
	aead cipher.AEAD
}

// NewCodec constructs a data-frame codec for a negotiated cipher suite.
func NewCodec(suite CipherSuite, key []byte) (*Codec, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidKeySize, len(key), KeySize)
	}

	var (
		aead cipher.AEAD
		err  error
	)
	switch suite {
	case CipherChaCha20Poly1305:
		aead, err = chacha20poly1305.New(key)
	case CipherAES256GCM:
		var block cipher.Block
		block, err = aes.NewCipher(key)
		if err == nil {
			aead, err = cipher.NewGCM(block)
		}
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedCipher, suite)
	}
	if err != nil {
		return nil, err
	}
	return &Codec{aead: aead}, nil
}

// Encrypt creates an encrypted frame. Padding is generated independently of
// the ciphertext and is authenticated only indirectly through PadLength in AAD.
func (c *Codec) Encrypt(messageType MessageType, sessionID [16]byte, sequence uint64, plaintext []byte, padLength uint8) (Frame, error) {
	if err := validateEncryptedHeader(messageType, sessionID, sequence); err != nil {
		return Frame{}, err
	}
	if uint64(HeaderSize)+uint64(len(plaintext))+AEADTagSize+uint64(padLength) > MaxFrameSize {
		return Frame{}, fmt.Errorf("%w: %d bytes", ErrPayloadTooLarge, len(plaintext))
	}

	header := NewHeader(messageType, sessionID, sequence, uint32(len(plaintext)), padLength)
	aad, err := header.MarshalBinary()
	if err != nil {
		return Frame{}, err
	}
	sealed := c.aead.Seal(nil, nonce(sequence), plaintext, aad)
	padding, err := randomBytes(rand.Reader, int(padLength))
	if err != nil {
		return Frame{}, fmt.Errorf("dgpv1: generate padding: %w", err)
	}
	return NewFrame(messageType, sessionID, sequence, sealed[:len(plaintext)], sealed[len(plaintext):], padding)
}

// Decrypt authenticates and decrypts an encrypted frame. All authentication
// failures return the same error and reveal no underlying AEAD detail.
func (c *Codec) Decrypt(frame Frame) ([]byte, error) {
	if err := frame.ValidateReceive(); err != nil {
		return nil, err
	}
	if err := validateEncryptedHeader(frame.Header.MessageType, frame.Header.SessionID, frame.Header.Sequence); err != nil {
		return nil, err
	}
	aad, err := frame.Header.marshalBinary(false)
	if err != nil {
		return nil, err
	}
	sealed := make([]byte, 0, len(frame.Payload)+AEADTagSize)
	sealed = append(sealed, frame.Payload...)
	sealed = append(sealed, frame.Tag[:]...)
	plaintext, err := c.aead.Open(nil, nonce(frame.Header.Sequence), sealed, aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func nonce(sequence uint64) []byte {
	value := make([]byte, chacha20poly1305.NonceSize)
	binary.LittleEndian.PutUint64(value[4:], sequence)
	return value
}

func validateEncryptedHeader(messageType MessageType, sessionID [16]byte, sequence uint64) error {
	if messageType < MessageTypeEncryptedData || messageType > MessageTypeError {
		return fmt.Errorf("%w: 0x%02x", ErrUnencryptedType, messageType)
	}
	if sequence == 0 {
		return ErrInvalidSequence
	}
	if sessionID == ([16]byte{}) {
		return ErrInvalidSessionID
	}
	return nil
}

func randomBytes(reader io.Reader, length int) ([]byte, error) {
	if length < 0 || length > 255 {
		return nil, ErrPaddingLength
	}
	padding := make([]byte, length)
	if _, err := io.ReadFull(reader, padding); err != nil {
		return nil, err
	}
	return padding, nil
}
