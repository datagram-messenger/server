package dgpv1

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

var (
	ErrInvalidEpoch     = errors.New("dgpv1: invalid rekey epoch")
	ErrKeyConfirmFailed = errors.New("dgpv1: rekey confirmation failed")
)

type RekeyState struct {
	Epoch uint32
}

func NewRekeyState() *RekeyState {
	return &RekeyState{Epoch: 1}
}

func (r *RekeyState) ComputeKeyConfirm(secret []byte, epoch uint32) ([32]byte, error) {
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

func DeriveNextKeys(currentSecret []byte) ([]byte, []byte, error) {
	mac := hmac.New(sha256.New, currentSecret)
	mac.Write([]byte("DGPv1 Rekey Send Key"))
	sendKey := mac.Sum(nil)

	mac.Reset()
	mac.Write([]byte("DGPv1 Rekey Receive Key"))
	receiveKey := mac.Sum(nil)

	return sendKey, receiveKey, nil
}
