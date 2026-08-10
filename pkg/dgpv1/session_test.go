package dgpv1

import (
	"bytes"
	"errors"
	"math"
	"sync"
	"testing"
)

func testSessions(t *testing.T) (*Session, *Session) {
	t.Helper()
	id := [16]byte{1, 2, 3}
	clientSend := [KeySize]byte{1}
	serverSend := [KeySize]byte{2}
	client, err := NewSession(CipherChaCha20Poly1305, HandshakeSecrets{SessionID: id, SendKey: clientSend, ReceiveKey: serverSend})
	if err != nil {
		t.Fatal(err)
	}
	server, err := NewSession(CipherChaCha20Poly1305, HandshakeSecrets{SessionID: id, SendKey: serverSend, ReceiveKey: clientSend})
	if err != nil {
		t.Fatal(err)
	}
	return client, server
}

func TestSessionCrossedSecretsRoundTrip(t *testing.T) {
	client, server := testSessions(t)
	frame, err := client.Send(PingPong{Nonce: 42}, 7)
	if err != nil {
		t.Fatal(err)
	}
	got, err := server.Receive(frame)
	if err != nil {
		t.Fatal(err)
	}
	ping, ok := got.(*PingPong)
	if !ok || ping.Nonce != 42 || ping.IsResponse {
		t.Fatalf("message = %#v", got)
	}

	reply, err := server.Send(EncryptedData{StreamID: 9, AppMessageType: 3}, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err = client.Receive(reply)
	if err != nil {
		t.Fatal(err)
	}
	data, ok := got.(*EncryptedData)
	if !ok || data.StreamID != 9 || data.AppMessageType != 3 {
		t.Fatalf("message = %#v", got)
	}
}

func TestSessionConcurrentSendSequences(t *testing.T) {
	client, _ := testSessions(t)
	const count = 256
	frames := make(chan Frame, count)
	errs := make(chan error, count)
	var wg sync.WaitGroup
	for range count {
		wg.Go(func() {
			frame, err := client.Send(PingPong{Nonce: 1}, 0)
			frames <- frame
			errs <- err
		})
	}
	wg.Wait()
	close(frames)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	seen := make(map[uint64]bool, count)
	for frame := range frames {
		if seen[frame.Header.Sequence] {
			t.Fatalf("duplicate sequence %d", frame.Header.Sequence)
		}
		seen[frame.Header.Sequence] = true
	}
	for sequence := uint64(1); sequence <= count; sequence++ {
		if !seen[sequence] {
			t.Fatalf("missing sequence %d", sequence)
		}
	}
}

func TestSessionReceiveRejections(t *testing.T) {
	client, server := testSessions(t)
	frame, err := client.Send(PingPong{Nonce: 1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.Receive(frame); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Receive(frame); !errors.Is(err, ErrReplayDuplicate) {
		t.Fatalf("replay error = %v", err)
	}

	wrong := frame
	wrong.Header.SessionID[0] ^= 1
	if _, err := server.Receive(wrong); !errors.Is(err, ErrWrongSession) {
		t.Fatalf("wrong session error = %v", err)
	}

	client2, server2 := testSessions(t)
	for i := 0; i <= ReplayWindowSize; i++ {
		frame, err = client2.Send(PingPong{Nonce: uint64(i)}, 0)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			wrong = frame
		}
		if _, err := server2.Receive(frame); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := server2.Receive(wrong); !errors.Is(err, ErrReplayTooOld) {
		t.Fatalf("too-old error = %v", err)
	}
}

func TestSessionFailedAuthenticationDoesNotCommit(t *testing.T) {
	client, server := testSessions(t)
	frame, err := client.Send(PingPong{Nonce: 7}, 0)
	if err != nil {
		t.Fatal(err)
	}
	tampered := frame
	tampered.Payload = append([]byte(nil), frame.Payload...)
	tampered.Payload[0] ^= 1
	if _, err := server.Receive(tampered); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tamper error = %v", err)
	}
	got, err := server.Receive(frame)
	if err != nil {
		t.Fatalf("retry error = %v", err)
	}
	if got.(*PingPong).Nonce != 7 {
		t.Fatalf("message = %#v", got)
	}
}

func TestSessionCloseAndValidation(t *testing.T) {
	client, server := testSessions(t)
	if _, err := client.Send(HandshakeInit{}, 0); !errors.Is(err, ErrMessageType) {
		t.Fatalf("invalid message error = %v", err)
	}
	if _, err := client.SendPayload(MessageTypeHandshakeInit, nil, 0); !errors.Is(err, ErrMessageType) {
		t.Fatalf("invalid type error = %v", err)
	}
	if _, err := client.Send(RekeyInit{Epoch: 2}, 0); !errors.Is(err, ErrMessageType) {
		t.Fatalf("manual rekey error = %v", err)
	}
	if _, err := client.SendPayload(MessageTypeRekeyInit, make([]byte, RekeyInitSize), 0); !errors.Is(err, ErrMessageType) {
		t.Fatalf("manual rekey payload error = %v", err)
	}
	frame, err := client.Send(PingPong{Nonce: 1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if !client.Closed() {
		t.Fatal("session remains open")
	}
	if _, err := client.Send(PingPong{}, 0); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("send after close = %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Receive(frame); !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("receive after close = %v", err)
	}
}

func TestSessionSequenceExhaustion(t *testing.T) {
	client, _ := testSessions(t)
	client.nextSequence = math.MaxUint64
	frame, err := client.Send(PingPong{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if frame.Header.Sequence != math.MaxUint64 {
		t.Fatalf("sequence = %d", frame.Header.Sequence)
	}
	if _, err := client.Send(PingPong{}, 0); !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("exhaustion error = %v", err)
	}
}

func TestSessionOwnership(t *testing.T) {
	client, server := testSessions(t)
	payload := []byte{1, 2, 3, 4}
	frame, err := client.SendPayload(MessageTypeEncryptedData, payload, 0)
	if err != nil {
		t.Fatal(err)
	}
	payload[0] = 9
	plaintext, err := server.ReceivePayload(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(plaintext, []byte{1, 2, 3, 4}) {
		t.Fatalf("plaintext = %v", plaintext)
	}

	id := [16]byte{9}
	secrets := HandshakeSecrets{SessionID: id, SendKey: [KeySize]byte{3}, ReceiveKey: [KeySize]byte{4}}
	session, err := NewSession(CipherChaCha20Poly1305, secrets)
	if err != nil {
		t.Fatal(err)
	}
	secrets.SessionID[0] = 0
	secrets.SendKey[0] = 0
	if session.SessionID() != id {
		t.Fatal("session aliases secrets")
	}
}

func TestSessionRejectsZeroID(t *testing.T) {
	if _, err := NewSession(CipherChaCha20Poly1305, HandshakeSecrets{}); !errors.Is(err, ErrInvalidSessionID) {
		t.Fatalf("error = %v", err)
	}
}

func TestNewSessionRejectsNonMVPCiphers(t *testing.T) {
	secrets := HandshakeSecrets{SessionID: [16]byte{1}}
	for _, suite := range []CipherSuite{CipherAES256GCM, 99} {
		if _, err := NewSession(suite, secrets); !errors.Is(err, ErrUnsupportedCipher) {
			t.Fatalf("suite %d error = %v", suite, err)
		}
	}
}
