package dgpserver

import (
	"context"
	"errors"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/datagram-messenger/protocol"
)

const runtimeTimeout = 2 * time.Second

func fixedKey(t *testing.T, value byte) dgpv1.StaticKey {
	t.Helper()
	key, err := dgpv1.LoadStaticKey(bytesOf(value, 32))
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

func connectRuntimeClient(t *testing.T, address string, clientKey, serverKey dgpv1.StaticKey) (*dgpv1.TCPTransport, *dgpv1.Session) {
	t.Helper()
	nc, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	tr := dgpv1.NewTCPTransport(nc)
	hs, err := dgpv1.NewInitiatorHandshake(clientKey, serverKey.Public())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), runtimeTimeout)
	defer cancel()
	flight, _ := hs.WriteFlight()
	frame, _ := dgpv1.NewFrame(dgpv1.MessageTypeHandshakeInit, [16]byte{}, 0, flight, make([]byte, dgpv1.AEADTagSize), nil)
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
	frame, _ = dgpv1.NewFrame(dgpv1.MessageTypeHandshakeResponse, [16]byte{}, 0, flight, make([]byte, dgpv1.AEADTagSize), nil)
	if err := tr.WriteFrame(ctx, frame); err != nil {
		t.Fatal(err)
	}
	result, err := hs.Result()
	if err != nil {
		t.Fatal(err)
	}
	session, err := dgpv1.NewSessionFromHandshake(dgpv1.CipherChaCha20Poly1305, result)
	if err != nil {
		t.Fatal(err)
	}
	return tr, session
}

func sendClientMessage(t *testing.T, tr *dgpv1.TCPTransport, session *dgpv1.Session, message any) {
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
		DGP: dgpv1.ServerConfig{StaticKey: serverKey, HandshakeTimeout: runtimeTimeout, WriteTimeout: runtimeTimeout},
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
	if err := RegisterTyped[dgpv1.EncryptedData](srv.Router(), func(ctx *Context, message *dgpv1.EncryptedData) error {
		mu.Lock()
		events = append(events, "handler")
		mu.Unlock()
		if ctx.Metadata().MessageType() != dgpv1.MessageTypeEncryptedData || ctx.Metadata().ReceivedAt().IsZero() {
			t.Error("metadata missing")
		}
		return ctx.SendAndWait(dgpv1.Ack{Sequences: []uint64{uint64(message.StreamID)}})
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
	sendClientMessage(t, tr, session, dgpv1.EncryptedData{StreamID: 9})
	ctx, cancel := context.WithTimeout(context.Background(), runtimeTimeout)
	frame, err := tr.ReadFrame(ctx)
	cancel()
	if err != nil {
		t.Fatal(err)
	}
	message, err := session.Receive(frame)
	ack, ok := message.(*dgpv1.Ack)
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
			srv, _ := New(Config{DGP: dgpv1.ServerConfig{StaticKey: serverKey, HandshakeTimeout: runtimeTimeout}, OnConnect: test.hook, OnDisconnect: func(context.Context, ConnectionInfo, error) { disconnects++ }})
			_ = RegisterTyped[dgpv1.EncryptedData](srv.Router(), func(*Context, *dgpv1.EncryptedData) error { handlers++; return nil })
			ln, _ := net.Listen("tcp", "127.0.0.1:0")
			done := make(chan error, 1)
			go func() { done <- srv.Serve(context.Background(), ln) }()
			tr, session := connectRuntimeClient(t, ln.Addr().String(), clientKey, serverKey)
			frame, _ := session.Send(dgpv1.EncryptedData{}, 0)
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
	srv, _ := New(Config{DGP: dgpv1.ServerConfig{StaticKey: serverKey, HandshakeTimeout: runtimeTimeout, WriteTimeout: time.Second}})
	_ = RegisterTyped[dgpv1.EncryptedData](srv.Router(), func(*Context, *dgpv1.EncryptedData) error { close(started); <-release; return nil })
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	done := make(chan error, 1)
	go func() { done <- srv.Serve(context.Background(), ln) }()
	tr, session := connectRuntimeClient(t, ln.Addr().String(), clientKey, serverKey)
	sendClientMessage(t, tr, session, dgpv1.EncryptedData{})
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
	if err == nil && frame.Header.MessageType == dgpv1.MessageTypeSessionClose {
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
