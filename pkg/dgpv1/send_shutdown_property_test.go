package dgpv1

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func TestSendShutdownStateMachineProperties(t *testing.T) {
	type sendCase struct {
		name string
		send func(*Connection, context.Context, uint64) error
	}
	sends := []sendCase{
		{name: "TrySend", send: func(c *Connection, _ context.Context, nonce uint64) error {
			return c.TrySend(PingPong{Nonce: nonce})
		}},
		{name: "SendContext", send: func(c *Connection, ctx context.Context, nonce uint64) error {
			return c.SendContext(ctx, PingPong{Nonce: nonce})
		}},
		{name: "SendAndWait", send: func(c *Connection, ctx context.Context, nonce uint64) error {
			return c.SendAndWait(ctx, PingPong{Nonce: nonce})
		}},
	}

	for _, send := range sends {
		for _, closeFirst := range []bool{false, true} {
			name := send.name + "/send-first"
			if closeFirst {
				name = send.name + "/close-first"
			}
			t.Run(name, func(t *testing.T) {
				connection, peerSession, peerTransport, cleanup := testConnectionPair(t, ConnectionConfig{
					OutboundQueue: 2,
					WriteTimeout:  connectionTestTimeout,
				})
				defer cleanup()
				connection.Start(context.Background())

				sendResult := make(chan error, 1)
				closeResult := make(chan error, 1)
				peerDone := make(chan struct{})
				go func() {
					defer close(peerDone)
					for {
						if _, ok := readConnectionMessage(t, peerTransport, peerSession).(*SessionClose); ok {
							return
						}
					}
				}()

				if closeFirst {
					go func() { closeResult <- connection.Close() }()
					<-connection.ctx.Done()
					go func() { sendResult <- send.send(connection, context.Background(), 1) }()
				} else {
					start := make(chan struct{})
					go func() {
						<-start
						sendResult <- send.send(connection, context.Background(), 1)
					}()
					go func() {
						<-start
						closeResult <- connection.Close()
					}()
					close(start)
				}

				if err := receiveBounded(t, sendResult); closeFirst && !errors.Is(err, ErrConnectionClosed) {
					t.Fatalf("send after close started = %v, want %v", err, ErrConnectionClosed)
				} else if !closeFirst && err != nil && !errors.Is(err, ErrConnectionClosed) {
					t.Fatalf("send racing with close = %v", err)
				}
				if err := receiveBounded(t, closeResult); err != nil {
					t.Fatalf("close = %v", err)
				}
				receiveBounded(t, peerDone)
				waitConnection(t, connection)
				assertTerminalSendRejection(t, connection, send.send)
			})
		}
	}
}

func TestFullQueueWaitersAndControlCloseProperties(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	session, _ := testSessions(t)
	connection := NewConnection(NewTCPTransport(local), session, ConnectionConfig{OutboundQueue: 1})
	if err := connection.TrySend(PingPong{Nonce: 1}); err != nil {
		t.Fatal(err)
	}

	const waiters = 16
	start := make(chan struct{})
	results := make(chan error, waiters)
	for i := 0; i < waiters; i++ {
		go func(n int) {
			<-start
			if n%2 == 0 {
				results <- connection.SendContext(context.Background(), PingPong{Nonce: uint64(n + 2)})
				return
			}
			results <- connection.SendAndWait(context.Background(), PingPong{Nonce: uint64(n + 2)})
		}(i)
	}
	close(start)

	closed := make(chan error, 1)
	go func() { closed <- connection.Close() }()
	if err := receiveBounded(t, closed); err != nil {
		t.Fatalf("Close behind full application queue = %v", err)
	}
	for i := 0; i < waiters; i++ {
		if err := receiveBounded(t, results); !errors.Is(err, ErrConnectionClosed) {
			t.Fatalf("waiter %d = %v, want %v", i, err, ErrConnectionClosed)
		}
	}
	assertTerminalSendRejection(t, connection, func(c *Connection, ctx context.Context, nonce uint64) error {
		return c.SendAndWait(ctx, PingPong{Nonce: nonce})
	})
}

func TestConcurrentCloseIsIdempotentAndTerminalCauseStable(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	session, _ := testSessions(t)
	connection := NewConnection(NewTCPTransport(local), session, ConnectionConfig{})

	const callers = 32
	start := make(chan struct{})
	results := make(chan error, callers)
	var callersWG sync.WaitGroup
	for range callers {
		callersWG.Add(1)
		go func() {
			defer callersWG.Done()
			<-start
			results <- connection.Close()
		}()
	}
	close(start)
	callersWG.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent Close = %v", err)
		}
	}
	if !errors.Is(connection.Err(), ErrConnectionClosed) {
		t.Fatalf("terminal cause = %v", connection.Err())
	}
	connection.recordTerminal(context.Canceled)
	if !errors.Is(connection.Err(), ErrConnectionClosed) {
		t.Fatalf("equal-rank terminal cause changed = %v", connection.Err())
	}
}

func TestSendCancellationPrecedenceBeforeTerminalState(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	session, _ := testSessions(t)
	connection := NewConnection(NewTCPTransport(local), session, ConnectionConfig{OutboundQueue: 1})
	defer connection.Close()
	if err := connection.TrySend(PingPong{Nonce: 1}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := connection.SendContext(ctx, PingPong{Nonce: 2}); !errors.Is(err, context.Canceled) {
		t.Fatalf("SendContext canceled before terminal state = %v", err)
	}
	if err := connection.SendAndWait(ctx, PingPong{Nonce: 3}); !errors.Is(err, context.Canceled) {
		t.Fatalf("SendAndWait canceled before terminal state = %v", err)
	}
}

func assertTerminalSendRejection(t *testing.T, connection *Connection, send func(*Connection, context.Context, uint64) error) {
	t.Helper()
	for i := 0; i < 8; i++ {
		if err := send(connection, context.Background(), uint64(i+100)); !errors.Is(err, ErrConnectionClosed) {
			t.Fatalf("post-terminal send %d = %v, want %v", i, err, ErrConnectionClosed)
		}
	}
}

func readSessionClose(t *testing.T, transport *TCPTransport, session *Session) {
	t.Helper()
	message := readConnectionMessage(t, transport, session)
	if _, ok := message.(*SessionClose); !ok {
		t.Fatalf("control close = %T, want *SessionClose", message)
	}
}

func receiveBounded[T any](t *testing.T, result <-chan T) T {
	t.Helper()
	select {
	case value := <-result:
		return value
	case <-time.After(connectionTestTimeout):
		t.Fatal("operation did not complete")
		var zero T
		return zero
	}
}
