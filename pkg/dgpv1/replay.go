package dgpv1

import "errors"

const (
	// ReplayWindowSize is the number of recent sequence numbers tracked.
	ReplayWindowSize = 2048
	replayWordCount  = ReplayWindowSize / 64
)

var (
	ErrReplayZero      = errors.New("dgpv1: sequence number is zero")
	ErrReplayDuplicate = errors.New("dgpv1: duplicate sequence number")
	ErrReplayTooOld    = errors.New("dgpv1: sequence number is outside replay window")
	ErrReplayStale     = errors.New("dgpv1: stale replay commit token")
)

// ReplayWindow tracks authenticated receive sequences. It is session-owned
// state and is not safe for concurrent use.
type ReplayWindow struct {
	highest    uint64
	bitmap     [replayWordCount]uint64
	generation uint64
}

// ReplayToken records a successful Check for later authenticated Commit.
type ReplayToken struct {
	sequence   uint64
	generation uint64
}

// Check validates sequence without changing the replay window.
func (w *ReplayWindow) Check(sequence uint64) (ReplayToken, error) {
	if sequence == 0 {
		return ReplayToken{}, ErrReplayZero
	}
	if sequence <= w.highest {
		distance := w.highest - sequence
		if distance >= ReplayWindowSize {
			return ReplayToken{}, ErrReplayTooOld
		}
		if w.marked(distance) {
			return ReplayToken{}, ErrReplayDuplicate
		}
	}
	return ReplayToken{sequence: sequence, generation: w.generation}, nil
}

// Commit records a sequence after its packet has been authenticated. A token
// becomes stale after any successful Commit and must then be checked again.
func (w *ReplayWindow) Commit(token ReplayToken) error {
	if token.sequence == 0 || token.generation != w.generation {
		return ErrReplayStale
	}

	sequence := token.sequence
	if sequence <= w.highest {
		distance := w.highest - sequence
		if distance >= ReplayWindowSize || w.marked(distance) {
			return ErrReplayStale
		}
		w.set(distance)
	} else {
		w.advance(sequence - w.highest)
		w.highest = sequence
		w.set(0)
	}
	w.generation++
	return nil
}

func (w *ReplayWindow) marked(distance uint64) bool {
	return w.bitmap[distance/64]&(uint64(1)<<(distance%64)) != 0
}

func (w *ReplayWindow) set(distance uint64) {
	w.bitmap[distance/64] |= uint64(1) << (distance % 64)
}

func (w *ReplayWindow) advance(shift uint64) {
	if shift >= ReplayWindowSize {
		clear(w.bitmap[:])
		return
	}

	wordShift := int(shift / 64)
	bitShift := uint(shift % 64)
	for dst := replayWordCount - 1; dst >= 0; dst-- {
		src := dst - wordShift
		var value uint64
		if src >= 0 {
			value = w.bitmap[src] << bitShift
			if bitShift != 0 && src > 0 {
				value |= w.bitmap[src-1] >> (64 - bitShift)
			}
		}
		w.bitmap[dst] = value
	}
}
