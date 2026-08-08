package dgpv1

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

const connectionTestTimeout = time.Second

func testConnectionPair(t *testing.T, config ConnectionConfig) (*Connection, *Session, *TCPTransport, func()) {
	t.Helper()
	localConn, peerConn := net.Pipe()
	localSession, peerSession := testSessions(t)
	connection := NewConnection(NewTCPTransport(localConn), localSession, config)
	peerTransport := NewTCPTransport(peerConn)
	cleanup := func() {
		_ = peerTransport.Close()
		_ = connection.Close()
		select {
		case <-connection.Done():
		case <-time.After(connectionTestTimeout):
			t.Fatal("connection did not stop")
		}
	}
	return connection, peerSession, peerTransport, cleanup
}

func writeConnectionMessage(t *testing.T, transport *TCPTransport, session *Session, message any) {
	t.Helper()
	frame, err := session.Send(message, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), connectionTestTimeout)
	defer cancel()
	if err := transport.WriteFrame(ctx, frame); err != nil {
		t.Fatal(err)
	}
}

func readConnectionMessage(t *testing.T, transport *TCPTransport, session *Session) any {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), connectionTestTimeout)
	defer cancel()
	frame, err := transport.ReadFrame(ctx)
	if err != nil {
		t.Fatal(err)
	}
	message, err := session.Receive(frame)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func waitConnection(t *testing.T, connection *Connection) {
	t.Helper()
	select {
	case <-connection.Done():
	case <-time.After(connectionTestTimeout):
		t.Fatal("connection did not stop")
	}
}

func TestConnectionEncryptedMessageDispatch(t *testing.T) {
	received := make(chan *EncryptedData, 1)
	connection, peerSession, peerTransport, cleanup := testConnectionPair(t, ConnectionConfig{
		Handler: func(_ context.Context, _ *Connection, message any) error {
			data, ok := message.(*EncryptedData)
			if !ok {
				t.Fatalf("message type = %T", message)
			}
			received <- data
			return nil
		},
	})
	defer cleanup()
	connection.Start(context.Background())

	writeConnectionMessage(t, peerTransport, peerSession, EncryptedData{StreamID: 7, AppMessageType: 3})
	select {
	case got := <-received:
		if got.StreamID != 7 || got.AppMessageType != 3 {
			t.Fatalf("message = %#v", got)
		}
	case <-time.After(connectionTestTimeout):
		t.Fatal("handler was not called")
	}
}

func TestConnectionPingPong(t *testing.T) {
	connection, peerSession, peerTransport, cleanup := testConnectionPair(t, ConnectionConfig{})
	defer cleanup()
	connection.Start(context.Background())

	writeConnectionMessage(t, peerTransport, peerSession, PingPong{Nonce: 42})
	got, ok := readConnectionMessage(t, peerTransport, peerSession).(*PingPong)
	if !ok || !got.IsResponse || got.Nonce != 42 {
		t.Fatalf("response = %#v", got)
	}
}

func TestConnectionRekeyContinues(t *testing.T) {
	received := make(chan any, 2)
	connection, peerSession, peerTransport, cleanup := testConnectionPair(t, ConnectionConfig{
		Handler: func(_ context.Context, _ *Connection, message any) error {
			received <- message
			return nil
		},
	})
	defer cleanup()
	connection.Start(context.Background())

	peerSession.sendMu.Lock()
	peerSession.rekeyFrameLimit = 1
	peerSession.sendMu.Unlock()
	writeConnectionMessage(t, peerTransport, peerSession, PingPong{IsResponse: true, Nonce: 1})
	writeConnectionMessage(t, peerTransport, peerSession, PingPong{IsResponse: true, Nonce: 2})
	writeConnectionMessage(t, peerTransport, peerSession, PingPong{IsResponse: true, Nonce: 3})

	for i := 0; i < 2; i++ {
		select {
		case <-received:
		case <-time.After(connectionTestTimeout):
			t.Fatal("connection stopped dispatching after rekey")
		}
	}
	select {
	case <-connection.Done():
		t.Fatalf("connection stopped after valid rekey: %v", connection.Err())
	default:
	}
}

func TestConnectionRemoteSessionClose(t *testing.T) {
	connection, peerSession, peerTransport, cleanup := testConnectionPair(t, ConnectionConfig{})
	defer cleanup()
	connection.Start(context.Background())

	writeConnectionMessage(t, peerTransport, peerSession, SessionClose{Code: 1, Reason: "done"})
	waitConnection(t, connection)
	if !errors.Is(connection.Err(), ErrConnectionClosed) {
		t.Fatalf("error = %v", connection.Err())
	}
}

func TestConnectionContextCancellation(t *testing.T) {
	connection, _, _, cleanup := testConnectionPair(t, ConnectionConfig{})
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	connection.Start(ctx)
	cancel()
	waitConnection(t, connection)
	if !errors.Is(connection.Err(), context.Canceled) {
		t.Fatalf("error = %v", connection.Err())
	}
}

func TestConnectionOutboundQueueBackpressure(t *testing.T) {
	localConn, peerConn := net.Pipe()
	defer peerConn.Close()
	localSession, _ := testSessions(t)
	connection := NewConnection(NewTCPTransport(localConn), localSession, ConnectionConfig{OutboundQueue: 2})
	defer connection.Close()

	if err := connection.Send(PingPong{Nonce: 1}); err != nil {
		t.Fatal(err)
	}
	if err := connection.Send(PingPong{Nonce: 2}); err != nil {
		t.Fatal(err)
	}
	if err := connection.Send(PingPong{Nonce: 3}); !errors.Is(err, ErrOutboundQueueFull) {
		t.Fatalf("error = %v, want %v", err, ErrOutboundQueueFull)
	}
}

func TestConnectionHandlerFailureContainment(t *testing.T) {
	handlerErr := errors.New("handler failed")
	for _, test := range []struct {
		name    string
		handler MessageHandler
		want    error
	}{
		{
			name: "error",
			handler: func(context.Context, *Connection, any) error {
				return handlerErr
			},
			want: handlerErr,
		},
		{
			name: "panic",
			handler: func(context.Context, *Connection, any) error {
				panic("boom")
			},
			want: ErrHandlerPanic,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			connection, peerSession, peerTransport, cleanup := testConnectionPair(t, ConnectionConfig{Handler: test.handler})
			defer cleanup()
			connection.Start(context.Background())
			writeConnectionMessage(t, peerTransport, peerSession, EncryptedData{})
			waitConnection(t, connection)
			if !errors.Is(connection.Err(), test.want) {
				t.Fatalf("error = %v, want %v", connection.Err(), test.want)
			}
		})
	}
}

func TestConnectionIdleTimeoutSendsSessionClose(t *testing.T) {
	connection, peerSession, peerTransport, cleanup := testConnectionPair(t, ConnectionConfig{
		IdleTimeout:  20 * time.Millisecond,
		WriteTimeout: connectionTestTimeout,
	})
	defer cleanup()
	connection.Start(context.Background())

	got, ok := readConnectionMessage(t, peerTransport, peerSession).(*SessionClose)
	if !ok || got.Code != 3 {
		t.Fatalf("close = %#v", got)
	}
	waitConnection(t, connection)
	if !errors.Is(connection.Err(), ErrIdleTimeout) {
		t.Fatalf("error = %v", connection.Err())
	}
}

func TestConnectionPeriodicKeepaliveAndPong(t *testing.T) {
	connection, peerSession, peerTransport, cleanup := testConnectionPair(t, ConnectionConfig{
		KeepaliveInterval: 20 * time.Millisecond,
	})
	defer cleanup()
	connection.Start(context.Background())

	ping, ok := readConnectionMessage(t, peerTransport, peerSession).(*PingPong)
	if !ok || ping.IsResponse || ping.Nonce == 0 {
		t.Fatalf("ping = %#v", ping)
	}
	writeConnectionMessage(t, peerTransport, peerSession, PingPong{IsResponse: true, Nonce: ping.Nonce})
	select {
	case <-connection.Done():
		t.Fatalf("connection stopped after valid pong: %v", connection.Err())
	default:
	}
}

func TestConnectionLocalCloseSendsSessionClose(t *testing.T) {
	connection, peerSession, peerTransport, cleanup := testConnectionPair(t, ConnectionConfig{
		WriteTimeout: connectionTestTimeout,
	})
	defer cleanup()
	connection.Start(context.Background())

	closed := make(chan error, 1)
	go func() { closed <- connection.Close() }()
	got, ok := readConnectionMessage(t, peerTransport, peerSession).(*SessionClose)
	if !ok || got.Code != 0 {
		t.Fatalf("close = %#v", got)
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	waitConnection(t, connection)
}

func TestConnectionCloseIdempotent(t *testing.T) {
	connection, peerSession, peerTransport, cleanup := testConnectionPair(t, ConnectionConfig{WriteTimeout: connectionTestTimeout})
	defer cleanup()
	connection.Start(context.Background())

	closed := make(chan error, 1)
	go func() { closed <- connection.Close() }()
	if _, ok := readConnectionMessage(t, peerTransport, peerSession).(*SessionClose); !ok {
		t.Fatal("expected SessionClose")
	}
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	waitConnection(t, connection)
	if !errors.Is(connection.Err(), ErrConnectionClosed) {
		t.Fatalf("error = %v", connection.Err())
	}
	if err := connection.Send(PingPong{}); !errors.Is(err, ErrConnectionClosed) {
		t.Fatalf("send error = %v", err)
	}
}
