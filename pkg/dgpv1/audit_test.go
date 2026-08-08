package dgpv1

import (
	"context"
	"errors"
	"io"
	"math"
	"net"
	"testing"
	"time"
)

func TestSessionPreviousEpochGraceFrameBoundary(t *testing.T) {
	for _, tc := range []struct {
		name          string
		currentFrames int
		wantErr       error
	}{
		{name: "last frame inside grace", currentFrames: 1},
		{name: "exact frame limit expires grace", currentFrames: 2, wantErr: ErrAuthentication},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender, receiver := testSessions(t)
			now := time.Unix(100, 0)
			sender.now = func() time.Time { return now }
			receiver.now = func() time.Time { return now }
			receiver.graceFrames = 2

			// Advance the old epoch so the delayed frame's sequence does not
			// collide with current-epoch sequences used to exhaust the grace budget.
			for i := 0; i < 2; i++ {
				frame, err := sender.Send(PingPong{Nonce: uint64(i)}, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := receiver.Receive(frame); err != nil {
					t.Fatal(err)
				}
			}
			delayed, err := sender.Send(PingPong{Nonce: 99}, 0)
			if err != nil {
				t.Fatal(err)
			}
			sender.sendMu.Lock()
			rekey, err := sender.startRekeyLocked(0)
			sender.sendMu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if err := sender.MarkRekeySent(rekey); err != nil {
				t.Fatal(err)
			}
			receiveRekey(t, receiver, rekey)

			for i := 0; i < tc.currentFrames; i++ {
				frame, err := sender.Send(PingPong{Nonce: uint64(i)}, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := receiver.Receive(frame); err != nil {
					t.Fatal(err)
				}
			}

			_, err = receiver.Receive(delayed)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("delayed previous-epoch frame error = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestSessionRekeyEpochExhaustionIsAtomic(t *testing.T) {
	t.Run("sender", func(t *testing.T) {
		sender, _ := testSessions(t)
		sender.sendEpoch = math.MaxUint32
		sender.rekeyFrameLimit = 1
		sender.sentInEpoch = 1
		beforeKey, beforeSequence := sender.sendKey, sender.nextSequence

		if _, err := sender.Send(PingPong{}, 0); !errors.Is(err, ErrEpochExhausted) {
			t.Fatalf("Send() error = %v, want %v", err, ErrEpochExhausted)
		}
		if sender.sendKey != beforeKey || sender.nextSequence != beforeSequence || sender.sendEpoch != math.MaxUint32 {
			t.Fatal("sender state changed after exhausted rekey")
		}
	})

	t.Run("receiver", func(t *testing.T) {
		_, receiver := testSessions(t)
		receiver.receiveEpoch = math.MaxUint32
		before := snapshotReceiveState(receiver)

		if _, _, err := receiver.prepareRekeyLocked(RekeyInit{Epoch: 1}); !errors.Is(err, ErrEpochExhausted) {
			t.Fatalf("prepareRekeyLocked() error = %v, want %v", err, ErrEpochExhausted)
		}
		if after := snapshotReceiveState(receiver); after != before {
			t.Fatal("receiver state changed after exhausted rekey")
		}
	})
}

func TestSessionMalformedAuthenticatedMessageConsumesSequence(t *testing.T) {
	sender, receiver := testSessions(t)
	frame, err := sender.SendPayload(MessageTypePingPong, []byte{0}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiver.Receive(frame); !errors.Is(err, ErrMessageLength) {
		t.Fatalf("first Receive() error = %v, want %v", err, ErrMessageLength)
	}
	if _, err := receiver.Receive(frame); !errors.Is(err, ErrReplayDuplicate) {
		t.Fatalf("second Receive() error = %v, want %v", err, ErrReplayDuplicate)
	}
}

func TestNilSessionAPI(t *testing.T) {
	var session *Session
	if session.SessionID() != ([16]byte{}) || !session.Closed() {
		t.Fatal("nil session did not report zero ID and closed state")
	}
	if err := session.Close(); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := session.Send(PingPong{}, 0); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("Send() error = %v", err)
	}
	if _, err := session.SendPayload(MessageTypePingPong, nil, 0); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("SendPayload() error = %v", err)
	}
	if _, err := session.ReceivePayload(Frame{}); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("ReceivePayload() error = %v", err)
	}
}

type zeroWriteConn struct{}

func (zeroWriteConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (zeroWriteConn) Write([]byte) (int, error)        { return 0, nil }
func (zeroWriteConn) Close() error                     { return nil }
func (zeroWriteConn) LocalAddr() net.Addr              { return fuzzAddr("local") }
func (zeroWriteConn) RemoteAddr() net.Addr             { return fuzzAddr("remote") }
func (zeroWriteConn) SetDeadline(time.Time) error      { return nil }
func (zeroWriteConn) SetReadDeadline(time.Time) error  { return nil }
func (zeroWriteConn) SetWriteDeadline(time.Time) error { return nil }

func TestTCPTransportWriteNoProgressAndPreCanceledContext(t *testing.T) {
	frame := testTransportFrame(t, 1, nil)
	transport := NewTCPTransport(zeroWriteConn{})
	if err := transport.WriteFrame(context.Background(), frame); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero-progress WriteFrame() error = %v, want %v", err, io.ErrShortWrite)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := transport.ReadFrame(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled ReadFrame() error = %v, want %v", err, context.Canceled)
	}
	if err := transport.WriteFrame(ctx, frame); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-canceled WriteFrame() error = %v, want %v", err, context.Canceled)
	}
}
