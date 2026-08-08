package dgpv1

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func receiveRekey(t *testing.T, receiver *Session, frame Frame) {
	t.Helper()
	message, err := receiver.Receive(frame)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := message.(*RekeyInit); !ok {
		t.Fatalf("message = %T, want *RekeyInit", message)
	}
}

func TestSessionRekeyTriggers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*Session, *time.Time)
	}{
		{"count boundary", func(s *Session, _ *time.Time) { s.rekeyFrameLimit = 1 }},
		{"time boundary", func(s *Session, now *time.Time) {
			s.rekeyFrameLimit = 0
			s.rekeyInterval = time.Minute
			s.epochStarted = *now
			*now = now.Add(time.Minute)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := testSessions(t)
			now := time.Unix(100, 0)
			client.now = func() time.Time { return now }
			client.epochStarted = now
			tc.setup(client, &now)
			if tc.name == "count boundary" {
				frame, err := client.Send(PingPong{Nonce: 1}, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := server.Receive(frame); err != nil {
					t.Fatal(err)
				}
			}
			frame, err := client.Send(PingPong{Nonce: 2}, 0)
			if err != nil {
				t.Fatal(err)
			}
			if frame.Header.MessageType != MessageTypeRekeyInit {
				t.Fatalf("type = 0x%02x", frame.Header.MessageType)
			}
			if err := client.MarkRekeySent(frame); err != nil {
				t.Fatal(err)
			}
			receiveRekey(t, server, frame)
			if client.sendEpoch != 2 || server.receiveEpoch != 2 || client.nextSequence != 1 {
				t.Fatalf("epochs/sequences = %d/%d/%d", client.sendEpoch, server.receiveEpoch, client.nextSequence)
			}
			frame, err = client.Send(PingPong{Nonce: 3}, 0)
			if err != nil {
				t.Fatal(err)
			}
			if frame.Header.Sequence != 1 {
				t.Fatalf("new epoch sequence = %d", frame.Header.Sequence)
			}
			if _, err := server.Receive(frame); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSessionRekeyBothDirections(t *testing.T) {
	client, server := testSessions(t)
	client.rekeyFrameLimit, server.rekeyFrameLimit = 0, 0
	for _, pair := range [][2]*Session{{client, server}, {server, client}} {
		pair[0].sendMu.Lock()
		frame, err := pair[0].startRekeyLocked(0)
		pair[0].sendMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if err := pair[0].MarkRekeySent(frame); err != nil {
			t.Fatal(err)
		}
		receiveRekey(t, pair[1], frame)
		data, err := pair[0].Send(PingPong{Nonce: 9}, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := pair[1].Receive(data); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSessionRekeyGraceAcceptanceAndExpiry(t *testing.T) {
	for _, tc := range []struct {
		name    string
		expire  func(*Session, *time.Time)
		wantErr bool
	}{
		{"accepted", func(*Session, *time.Time) {}, false},
		{"frame limit", func(s *Session, _ *time.Time) { s.graceRemaining = 0 }, true},
		{"time limit", func(s *Session, now *time.Time) { *now = now.Add(s.gracePeriod) }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client, server := testSessions(t)
			now := time.Unix(100, 0)
			client.now, server.now = func() time.Time { return now }, func() time.Time { return now }
			delayed, err := client.Send(PingPong{Nonce: 1}, 0)
			if err != nil {
				t.Fatal(err)
			}
			client.sendMu.Lock()
			rekey, err := client.startRekeyLocked(0)
			client.sendMu.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			if err := client.MarkRekeySent(rekey); err != nil {
				t.Fatal(err)
			}
			receiveRekey(t, server, rekey)
			tc.expire(server, &now)
			_, err = server.Receive(delayed)
			if tc.wantErr && !errors.Is(err, ErrAuthentication) {
				t.Fatalf("error = %v", err)
			}
			if !tc.wantErr && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestSessionRejectsDuplicateRollbackFutureAndBadConfirm(t *testing.T) {
	client, server := testSessions(t)
	client.sendMu.Lock()
	rekey, err := client.startRekeyLocked(0)
	client.sendMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.MarkRekeySent(rekey); err != nil {
		t.Fatal(err)
	}
	receiveRekey(t, server, rekey)
	if _, err := server.Receive(rekey); !errors.Is(err, ErrInvalidEpoch) {
		t.Fatalf("duplicate/rollback error = %v", err)
	}

	for _, epoch := range []uint32{2, 4} {
		confirm, err := (&RekeyState{Epoch: client.sendEpoch}).ComputeKeyConfirm(client.sendKey[:], client.sendEpoch+1)
		if err != nil {
			t.Fatal(err)
		}
		if epoch == 2 {
			confirm[0] ^= 1
		}
		payload, _ := (RekeyInit{Epoch: epoch, KeyConfirm: confirm}).MarshalBinary()
		client.sendMu.Lock()
		frame, encErr := client.encryptLocked(MessageTypeRekeyInit, payload, 0)
		client.sendMu.Unlock()
		if encErr != nil {
			t.Fatal(encErr)
		}
		_, gotErr := server.Receive(frame)
		if epoch == 2 && !errors.Is(gotErr, ErrInvalidEpoch) {
			t.Fatalf("rollback error = %v", gotErr)
		}
		if epoch == 4 && !errors.Is(gotErr, ErrInvalidEpoch) {
			t.Fatalf("future error = %v", gotErr)
		}
	}
}

type receiveStateSnapshot struct {
	receive         *Codec
	receiveKey      [KeySize]byte
	receiveEpoch    uint32
	replay          ReplayWindow
	previousReceive *Codec
	previousReplay  ReplayWindow
	graceRemaining  uint64
	graceUntil      time.Time
}

func snapshotReceiveState(s *Session) receiveStateSnapshot {
	return receiveStateSnapshot{
		receive:         s.receive,
		receiveKey:      s.receiveKey,
		receiveEpoch:    s.receiveEpoch,
		replay:          s.replay,
		previousReceive: s.previousReceive,
		previousReplay:  s.previousReplay,
		graceRemaining:  s.graceRemaining,
		graceUntil:      s.graceUntil,
	}
}

func TestSessionRejectedRekeyIsAtomic(t *testing.T) {
	for _, tc := range []struct {
		name    string
		payload func(t *testing.T, sender *Session) []byte
		wantErr error
	}{
		{
			name: "bad confirm",
			payload: func(t *testing.T, sender *Session) []byte {
				confirm, err := (&RekeyState{Epoch: sender.sendEpoch}).ComputeKeyConfirm(sender.sendKey[:], sender.sendEpoch+1)
				if err != nil {
					t.Fatal(err)
				}
				confirm[0] ^= 1
				payload, err := (RekeyInit{Epoch: sender.sendEpoch + 1, KeyConfirm: confirm}).MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				return payload
			},
			wantErr: ErrKeyConfirmFailed,
		},
		{
			name: "bad epoch",
			payload: func(t *testing.T, sender *Session) []byte {
				confirm, err := (&RekeyState{Epoch: sender.sendEpoch + 1}).ComputeKeyConfirm(sender.sendKey[:], sender.sendEpoch+2)
				if err != nil {
					t.Fatal(err)
				}
				payload, err := (RekeyInit{Epoch: sender.sendEpoch + 2, KeyConfirm: confirm}).MarshalBinary()
				if err != nil {
					t.Fatal(err)
				}
				return payload
			},
			wantErr: ErrInvalidEpoch,
		},
		{
			name: "malformed authenticated payload",
			payload: func(*testing.T, *Session) []byte {
				return make([]byte, RekeyInitSize-1)
			},
			wantErr: ErrMessageLength,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sender, receiver := testSessions(t)
			const sequence = uint64(7)
			bad, err := sender.send.Encrypt(MessageTypeRekeyInit, sender.sessionID, sequence, tc.payload(t, sender), 0)
			if err != nil {
				t.Fatal(err)
			}

			before := snapshotReceiveState(receiver)
			if _, err := receiver.Receive(bad); !errors.Is(err, tc.wantErr) {
				t.Fatalf("rejected rekey error = %v, want %v", err, tc.wantErr)
			}
			if after := snapshotReceiveState(receiver); after != before {
				t.Fatalf("receive state changed after rejected rekey\nbefore: %#v\nafter:  %#v", before, after)
			}

			confirm, err := (&RekeyState{Epoch: sender.sendEpoch}).ComputeKeyConfirm(sender.sendKey[:], sender.sendEpoch+1)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := (RekeyInit{Epoch: sender.sendEpoch + 1, KeyConfirm: confirm}).MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			valid, err := sender.send.Encrypt(MessageTypeRekeyInit, sender.sessionID, sequence, payload, 0)
			if err != nil {
				t.Fatal(err)
			}
			receiveRekey(t, receiver, valid)
			if receiver.receiveEpoch != 2 {
				t.Fatalf("receive epoch = %d, want 2", receiver.receiveEpoch)
			}
			if _, err := receiver.Receive(valid); !errors.Is(err, ErrInvalidEpoch) {
				t.Fatalf("duplicate rekey error = %v, want %v", err, ErrInvalidEpoch)
			}
		})
	}
}

func TestSessionConcurrentRekeySafe(t *testing.T) {
	client, server := testSessions(t)
	client.rekeyFrameLimit = 1
	first, err := client.Send(PingPong{Nonce: 0}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Receive(first); err != nil {
		t.Fatal(err)
	}

	const count = 64
	type result struct {
		frame Frame
		err   error
	}
	results := make(chan result, count)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			frame, err := client.Send(PingPong{Nonce: 1}, 0)
			results <- result{frame: frame, err: err}
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	var rekey Frame
	pending := 0
	for result := range results {
		switch {
		case result.err == nil && result.frame.Header.MessageType == MessageTypeRekeyInit:
			if rekey.Header.MessageType != 0 {
				t.Fatal("multiple rekeys at one trigger boundary")
			}
			rekey = result.frame
		case errors.Is(result.err, ErrRekeyPending):
			pending++
		default:
			t.Fatalf("unexpected concurrent send result: type=%#x error=%v", result.frame.Header.MessageType, result.err)
		}
	}
	if rekey.Header.MessageType == 0 || pending != count-1 {
		t.Fatalf("rekey/pending = %#x/%d, want %#x/%d", rekey.Header.MessageType, pending, MessageTypeRekeyInit, count-1)
	}
	if err := client.MarkRekeySent(rekey); err != nil {
		t.Fatal(err)
	}
	receiveRekey(t, server, rekey)
	data, err := client.Send(PingPong{Nonce: 1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if data.Header.Sequence != 1 {
		t.Fatalf("new epoch sequence = %d, want 1", data.Header.Sequence)
	}
	if _, err := server.Receive(data); err != nil {
		t.Fatal(err)
	}
}
