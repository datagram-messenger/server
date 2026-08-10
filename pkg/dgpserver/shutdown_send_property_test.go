package dgpserver

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/tr1xdev/datagram-server/pkg/dgpv1"
)

func TestContextSendCancellationAndDisconnectProperties(t *testing.T) {
	for _, test := range []struct {
		name string
		call func(*Context) error
	}{
		{name: "Send", call: func(ctx *Context) error { return ctx.Send(dgpv1.PingPong{}) }},
		{name: "SendAndWait", call: func(ctx *Context) error { return ctx.SendAndWait(dgpv1.PingPong{}) }},
	} {
		t.Run(test.name+"/handler-cancellation", func(t *testing.T) {
			parent, cancel := context.WithCancel(context.Background())
			sender := &blockingSendCapability{started: make(chan struct{}), release: make(chan struct{})}
			ctx := newContext(parent, Peer{}, Metadata{}, Params{}, sender)
			result := make(chan error, 1)
			go func() { result <- test.call(ctx) }()
			<-sender.started
			cancel()
			close(sender.release)
			if err := <-result; !errors.Is(err, context.Canceled) {
				t.Fatalf("send after handler cancellation = %v", err)
			}
		})
	}

	for _, test := range []struct {
		name string
		call func(*Context) error
	}{
		{name: "TrySend", call: func(ctx *Context) error { return ctx.TrySend(dgpv1.PingPong{}) }},
		{name: "Send", call: func(ctx *Context) error { return ctx.Send(dgpv1.PingPong{}) }},
		{name: "SendAndWait", call: func(ctx *Context) error { return ctx.SendAndWait(dgpv1.PingPong{}) }},
	} {
		t.Run(test.name+"/disconnect-rejection", func(t *testing.T) {
			ctx := NewContext(context.Background(), Peer{}, Metadata{}, Params{})
			if err := test.call(ctx); !errors.Is(err, ErrRecorderClosed) {
				t.Fatalf("receive-only/disconnect context send = %v", err)
			}
		})
	}
}

func TestConcurrentServerShutdownAndCloseBeforeServe(t *testing.T) {
	server, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	const callers = 32
	start := make(chan struct{})
	results := make(chan error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		closeServer := i%2 == 0
		wg.Go(func() {
			<-start
			if closeServer {
				results <- server.Close()
				return
			}
			results <- server.Shutdown(context.Background())
		})
	}
	close(start)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("concurrent shutdown/close = %v", err)
		}
	}
	if err := server.Serve(context.Background(), nil); err == nil {
		t.Fatal("Serve after terminal state accepted nil listener")
	}
}

type blockingSendCapability struct {
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingSendCapability) trySend(any) error { return nil }

func (s *blockingSendCapability) send(ctx context.Context, _ any, _ bool) error {
	s.once.Do(func() { close(s.started) })
	<-s.release
	return ctx.Err()
}

func (s *blockingSendCapability) close() error { return nil }
