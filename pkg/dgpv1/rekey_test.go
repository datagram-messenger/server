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
	frames := make(chan Frame, count)
	var wg sync.WaitGroup
	for range count {
		wg.Add(1)
		go func() {
			defer wg.Done()
			frame, err := client.Send(PingPong{Nonce: 1}, 0)
			if err != nil {
				t.Errorf("send: %v", err)
				return
			}
			frames <- frame
		}()
	}
	wg.Wait()
	close(frames)

	var rekey Frame
	data := make([]Frame, 0, count-1)
	for frame := range frames {
		if frame.Header.MessageType == MessageTypeRekeyInit {
			if rekey.Header.MessageType != 0 {
				t.Fatal("multiple rekeys at one trigger boundary")
			}
			rekey = frame
		} else {
			data = append(data, frame)
		}
	}
	if rekey.Header.MessageType == 0 {
		t.Fatal("missing rekey")
	}
	receiveRekey(t, server, rekey)
	for _, frame := range data {
		if _, err := server.Receive(frame); err != nil {
			t.Fatalf("receive: %v", err)
		}
	}
}
