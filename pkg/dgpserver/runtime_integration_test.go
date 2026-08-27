package dgpserver

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/datagram-messenger/dgproto-go"
)

const runtimeTimeout = 2 * time.Second

func fixedKey(t *testing.T, value byte) dgproto.StaticKey {
	t.Helper()
	key, err := dgproto.LoadStaticKey(bytesOf(value, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func bytesOf(value byte, n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = value
	}
	return b
}

func connectRuntimeClient(t *testing.T, address string, clientKey, serverKey dgproto.StaticKey) (*dgproto.TCPTransport, *dgproto.Session) {
	t.Helper()
	nc, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	tr := dgproto.NewTCPTransport(nc)
	hs, err := dgproto.NewInitiatorHandshake(clientKey, serverKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), runtimeTimeout)
	defer cancel()
	flight, _ := hs.WriteFlight()
	frame, _ := dgproto.NewFrame(dgproto.MessageTypeHandshakeInit, [16]byte{}, 0, flight, make([]byte, dgproto.AEADTagSize), nil)
	if err := tr.WriteFrame(ctx, frame); err != nil {
		t.Fatal(err)
	}
	response, err := tr.ReadFrame(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := hs.ReadFlight(response.Payload); err != nil {
		t.Fatal(err)
	}
	flight, _ = hs.WriteFlight()
	frame, _ = dgproto.NewFrame(dgproto.MessageTypeHandshakeResponse, [16]byte{}, 0, flight, make([]byte, dgproto.AEADTagSize), nil)
	if err := tr.WriteFrame(ctx, frame); err != nil {
		t.Fatal(err)
	}
	result, err := hs.Result()
	if err != nil {
		t.Fatal(err)
	}
	session, err := dgproto.NewSessionFromHandshake(dgproto.CipherChaCha20Poly1305, result)
	if err != nil {
		t.Fatal(err)
	}
	return tr, session
}

func sendClientMessage(t *testing.T, tr *dgproto.TCPTransport, session *dgproto.Session, message any) {
	t.Helper()
	frame, err := session.Send(message, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), runtimeTimeout)
	defer cancel()
	if err := tr.WriteFrame(ctx, frame); err != nil {
		t.Fatal(err)
	}
}

func TestServerRealTCPAuthDispatchResponseAndLifecycle(t *testing.T) {
	serverKey, clientKey := fixedKey(t, 1), fixedKey(t, 2)
	var clientPublic [32]byte
	copy(clientPublic[:], clientKey.Public())
	var mu sync.Mutex
	var events []string
	disconnected := make(chan struct{}, 1)

	srv, err := New(Config{
		DGP: dgproto.ServerConfig{StaticKey: serverKey, HandshakeTimeout: runtimeTimeout, WriteTimeout: runtimeTimeout},
		Authenticator: AuthenticatorFunc(func(_ context.Context, credentials Credentials) (Principal, error) {
			mu.Lock()
			events = append(events, "auth")
			mu.Unlock()
			if credentials.PeerStatic != clientPublic {
				return nil, ErrUnauthenticated
			}
			return "alice", nil
		}),
		OnConnect: func(_ context.Context, info ConnectionInfo) error {
			mu.Lock()
			events = append(events, "connect")
			mu.Unlock()
			if info.Principal != "alice" {
				t.Errorf("principal = %v", info.Principal)
			}
			return nil
		},
		OnDisconnect: func(context.Context, ConnectionInfo, error) {
			mu.Lock()
			events = append(events, "disconnect")
			mu.Unlock()
			disconnected <- struct{}{}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterTyped[dgproto.EncryptedData](srv.Router(), func(ctx *Context, message *dgproto.EncryptedData) error {
		mu.Lock()
		events = append(events, "handler")
		mu.Unlock()
		if ctx.Metadata().MessageType() != dgproto.MessageTypeEncryptedData || ctx.Metadata().ReceivedAt().IsZero() {
			t.Error("metadata missing")
		}
		return ctx.SendAndWait(dgproto.Ack{Sequences: []uint64{uint64(message.StreamID)}})
	}); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(context.Background(), listener) }()
	tr, session := connectRuntimeClient(t, listener.Addr().String(), clientKey, serverKey)
	sendClientMessage(t, tr, session, dgproto.EncryptedData{StreamID: 9})
	ctx, cancel := context.WithTimeout(context.Background(), runtimeTimeout)
	frame, err := tr.ReadFrame(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	message, err := session.Receive(frame)
	ack, ok := message.(*dgproto.Ack)
	if err != nil || !ok || len(ack.Sequences) != 1 || ack.Sequences[0] != 9 {
		t.Fatalf("response = %#v, err=%v", message, err)
	}
	_ = tr.Close()
	select {
	case <-disconnected:
	case <-time.After(runtimeTimeout):
		t.Fatal("disconnect hook not called")
	}
	ctx, cancel = context.WithTimeout(context.Background(), runtimeTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-serveDone; err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	got := append([]string(nil), events...)
	mu.Unlock()
	if !reflect.DeepEqual(got, []string{"auth", "connect", "handler", "disconnect"}) {
		t.Fatalf("events = %v", got)
	}
	select {
	case <-disconnected:
		t.Fatal("disconnect called more than once")
	default:
	}
}

func TestServerConnectRejectAndPanicDisconnectExactlyOnce(t *testing.T) {
	for _, test := range []struct {
		name string
		hook func(context.Context, ConnectionInfo) error
	}{
		{"reject", func(context.Context, ConnectionInfo) error { return errors.New("reject") }},
		{"panic", func(context.Context, ConnectionInfo) error { panic("boom") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			serverKey, clientKey := fixedKey(t, 3), fixedKey(t, 4)
			var handlers, disconnects int
			srv, _ := New(Config{DGP: dgproto.ServerConfig{StaticKey: serverKey, HandshakeTimeout: runtimeTimeout}, OnConnect: test.hook, OnDisconnect: func(context.Context, ConnectionInfo, error) { disconnects++ }})
			_ = RegisterTyped[dgproto.EncryptedData](srv.Router(), func(*Context, *dgproto.EncryptedData) error { handlers++; return nil })
			ln, _ := net.Listen("tcp", "127.0.0.1:0")
			done := make(chan error, 1)
			go func() { done <- srv.Serve(context.Background(), ln) }()
			tr, session := connectRuntimeClient(t, ln.Addr().String(), clientKey, serverKey)
			frame, _ := session.Send(dgproto.EncryptedData{}, 0)
			ctx, cancel := context.WithTimeout(context.Background(), runtimeTimeout)
			_ = tr.WriteFrame(ctx, frame)
			_, readErr := tr.ReadFrame(ctx)
			cancel()
			if readErr == nil {
				t.Fatal("rejected connection remained open")
			}
			_ = tr.Close()
			_ = srv.Close()
			<-done
			if handlers != 0 || disconnects != 1 {
				t.Fatalf("handlers=%d disconnects=%d", handlers, disconnects)
			}
		})
	}
}

func TestShutdownDeadlineEscalatesNetworkCancellation(t *testing.T) {
	serverKey, clientKey := fixedKey(t, 5), fixedKey(t, 6)
	started, release := make(chan struct{}), make(chan struct{})
	srv, _ := New(Config{DGP: dgproto.ServerConfig{StaticKey: serverKey, HandshakeTimeout: runtimeTimeout, WriteTimeout: time.Second}})
	_ = RegisterTyped[dgproto.EncryptedData](srv.Router(), func(*Context, *dgproto.EncryptedData) error { close(started); <-release; return nil })
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), ln) }()
	tr, session := connectRuntimeClient(t, ln.Addr().String(), clientKey, serverKey)
	sendClientMessage(t, tr, session, dgproto.EncryptedData{})
	select {
	case <-started:
	case <-time.After(runtimeTimeout):
		t.Fatal("handler not started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := srv.Shutdown(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("Shutdown = %v", err)
	}
	readCtx, readCancel := context.WithTimeout(context.Background(), runtimeTimeout)
	frame, err := tr.ReadFrame(readCtx)
	if err == nil && frame.Header.MessageType == dgproto.MessageTypeSessionClose {
		_, err = tr.ReadFrame(readCtx)
	}
	readCancel()
	if err == nil {
		t.Fatal("client network was not canceled")
	}
	close(release)
	select {
	case <-done:
	case <-time.After(runtimeTimeout):
		t.Fatal("Serve did not finish after handler release")
	}
}
