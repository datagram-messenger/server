package dgpv1

import (
	"errors"
	"math"
	"testing"
)

func commitSequence(t *testing.T, w *ReplayWindow, sequence uint64) {
	t.Helper()
	token, err := w.Check(sequence)
	if err != nil {
		t.Fatalf("Check(%d) error = %v", sequence, err)
	}
	if err := w.Commit(token); err != nil {
		t.Fatalf("Commit(%d) error = %v", sequence, err)
	}
}

func checkError(t *testing.T, w *ReplayWindow, sequence uint64, want error) {
	t.Helper()
	_, err := w.Check(sequence)
	if !errors.Is(err, want) {
		t.Fatalf("Check(%d) error = %v, want %v", sequence, err, want)
	}
}

func TestReplayWindowFirstAndInOrder(t *testing.T) {
	var w ReplayWindow
	commitSequence(t, &w, 1)
	commitSequence(t, &w, 2)
	commitSequence(t, &w, 3)
	checkError(t, &w, 1, ErrReplayDuplicate)
}

func TestReplayWindowOutOfOrderAndDuplicate(t *testing.T) {
	var w ReplayWindow
	commitSequence(t, &w, 10)
	commitSequence(t, &w, 8)
	commitSequence(t, &w, 9)
	checkError(t, &w, 8, ErrReplayDuplicate)
	checkError(t, &w, 10, ErrReplayDuplicate)
}

func TestReplayWindowBoundaryAndTooOld(t *testing.T) {
	var w ReplayWindow
	commitSequence(t, &w, 3000)
	commitSequence(t, &w, 953)              // distance 2047: still in the window
	checkError(t, &w, 952, ErrReplayTooOld) // distance 2048: exact boundary
}

func TestReplayWindowLargeJump(t *testing.T) {
	var w ReplayWindow
	commitSequence(t, &w, 7)
	commitSequence(t, &w, 1<<40)
	checkError(t, &w, 7, ErrReplayTooOld)
	commitSequence(t, &w, (1<<40)-1)
}

func TestReplayWindowRejectsZero(t *testing.T) {
	var w ReplayWindow
	checkError(t, &w, 0, ErrReplayZero)
}

func TestReplayWindowUint64Max(t *testing.T) {
	var w ReplayWindow
	commitSequence(t, &w, math.MaxUint64-1)
	commitSequence(t, &w, math.MaxUint64)
	commitSequence(t, &w, math.MaxUint64-2)
	checkError(t, &w, math.MaxUint64, ErrReplayDuplicate)
	checkError(t, &w, math.MaxUint64-ReplayWindowSize, ErrReplayTooOld)
}

func TestReplayWindowCheckWithoutCommit(t *testing.T) {
	var w ReplayWindow
	first, err := w.Check(42)
	if err != nil {
		t.Fatalf("first Check() error = %v", err)
	}
	second, err := w.Check(42)
	if err != nil {
		t.Fatalf("second Check() error = %v", err)
	}
	if err := w.Commit(second); err != nil {
		t.Fatalf("Commit(second) error = %v", err)
	}
	if err := w.Commit(first); !errors.Is(err, ErrReplayStale) {
		t.Fatalf("Commit(first) error = %v, want %v", err, ErrReplayStale)
	}
}

func TestReplayWindowStaleCommitTokens(t *testing.T) {
	var w ReplayWindow
	old, err := w.Check(10)
	if err != nil {
		t.Fatalf("Check(10) error = %v", err)
	}
	newer, err := w.Check(11)
	if err != nil {
		t.Fatalf("Check(11) error = %v", err)
	}
	if err := w.Commit(newer); err != nil {
		t.Fatalf("Commit(11) error = %v", err)
	}
	if err := w.Commit(old); !errors.Is(err, ErrReplayStale) {
		t.Fatalf("Commit(stale) error = %v, want %v", err, ErrReplayStale)
	}

	old, err = w.Check(10)
	if err != nil {
		t.Fatalf("recheck(10) error = %v", err)
	}
	if err := w.Commit(old); err != nil {
		t.Fatalf("Commit(rechecked 10) error = %v", err)
	}
}

func TestReplayWindowShifts(t *testing.T) {
	var w ReplayWindow
	for _, sequence := range []uint64{1, 2, 63, 64, 65, 127, 128, 129, 2048} {
		commitSequence(t, &w, sequence)
	}
	for _, sequence := range []uint64{1, 2, 63, 64, 65, 127, 128, 129, 2048} {
		checkError(t, &w, sequence, ErrReplayDuplicate)
	}

	commitSequence(t, &w, 2049)
	checkError(t, &w, 1, ErrReplayTooOld)
	checkError(t, &w, 2, ErrReplayDuplicate)
	commitSequence(t, &w, 3)
}
