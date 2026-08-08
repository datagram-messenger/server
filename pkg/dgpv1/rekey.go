package dgpv1

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

const (
	// DefaultRekeyFrameLimit is the default number of sent frames per key epoch.
	DefaultRekeyFrameLimit = uint64(1) << 32
	// DefaultRekeyInterval is the default maximum duration of a send-key epoch.
	DefaultRekeyInterval = 10 * time.Minute
	// DefaultRekeyGraceFrames is the default current-epoch frame budget before the previous receive key expires.
	DefaultRekeyGraceFrames = uint64(ReplayWindowSize)
	// DefaultRekeyGracePeriod is the default time limit for accepting previous-epoch frames.
	DefaultRekeyGracePeriod = 30 * time.Second
)

var (
	// ErrInvalidEpoch indicates that a rekey epoch is not the immediate successor.
	ErrInvalidEpoch = errors.New("dgpv1: invalid rekey epoch")
	// ErrEpochExhausted indicates that the uint32 rekey epoch cannot advance.
	ErrEpochExhausted = errors.New("dgpv1: rekey epoch exhausted")
	// ErrKeyConfirmFailed indicates that a RekeyInit confirmation does not match.
	ErrKeyConfirmFailed = errors.New("dgpv1: rekey confirmation failed")
)

// RekeyState tracks one directional key epoch. Epoch one is established by
// the handshake; every accepted RekeyInit advances it exactly once.
type RekeyState struct {
	Epoch uint32
}

// NewRekeyState returns directional rekey state at handshake epoch one.
func NewRekeyState() *RekeyState { return &RekeyState{Epoch: 1} }

// ComputeKeyConfirm returns the HMAC-SHA256 confirmation for the immediately
// following epoch. It rejects skipped epochs and exhausted state.
func (r *RekeyState) ComputeKeyConfirm(secret []byte, epoch uint32) ([32]byte, error) {
	if r == nil || r.Epoch == ^uint32(0) {
		return [32]byte{}, ErrEpochExhausted
	}
	if epoch != r.Epoch+1 {
		return [32]byte{}, fmt.Errorf("%w: got %d, want %d", ErrInvalidEpoch, epoch, r.Epoch+1)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("DGPv1 Rekey Confirm"))
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], epoch)
	mac.Write(buf[:])
	var confirm [32]byte
	copy(confirm[:], mac.Sum(nil))
	return confirm, nil
}

// DeriveNextKeys preserves the key-ratchet labels already used by DGPv1.
// Session applies the send-labelled result independently to each crossed
// directional traffic secret, so both peers derive the same next key.
func DeriveNextKeys(currentSecret []byte) ([]byte, []byte, error) {
	if len(currentSecret) != KeySize {
		return nil, nil, fmt.Errorf("%w: got %d, want %d", ErrInvalidKeySize, len(currentSecret), KeySize)
	}
	mac := hmac.New(sha256.New, currentSecret)
	mac.Write([]byte("DGPv1 Rekey Send Key"))
	sendKey := mac.Sum(nil)

	mac.Reset()
	mac.Write([]byte("DGPv1 Rekey Receive Key"))
	receiveKey := mac.Sum(nil)
	return sendKey, receiveKey, nil
}

func deriveNextTrafficKey(current [KeySize]byte) [KeySize]byte {
	next, _, _ := DeriveNextKeys(current[:])
	var key [KeySize]byte
	copy(key[:], next)
	return key
}
