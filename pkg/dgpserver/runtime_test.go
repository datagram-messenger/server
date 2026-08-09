package dgpserver

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tr1xdev/datagram-server/pkg/dgpv1"
)

func TestStaticKeyAllowlist(t *testing.T) {
	key := [32]byte{1}
	auth := NewStaticKeyAllowlist(map[[32]byte]Principal{key: "alice"})
	principal, err := auth.Authenticate(context.Background(), Credentials{PeerStatic: key})
	if err != nil || principal != "alice" {
		t.Fatalf("allow: principal=%v err=%v", principal, err)
	}
	if _, err := auth.Authenticate(context.Background(), Credentials{}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("reject: %v", err)
	}
}

func TestAuthenticatorPanicIsRejected(t *testing.T) {
	auth := AuthenticatorFunc(func(context.Context, Credentials) (Principal, error) { panic("boom") })
	if _, err := callAuthenticator(auth, context.Background(), Credentials{}); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("panic: %v", err)
	}
}

func TestHandlerErrorDoesNotExposeCause(t *testing.T) {
	secret := errors.New("secret peer text")
	err := &HandlerError{Kind: ErrorKindHandler, Err: secret}
	if err.Error() == secret.Error() || !errors.Is(err, secret) {
		t.Fatalf("error policy: %v", err)
	}
}

func TestOpErrorWrapsShutdownCauseWithoutFormattingIt(t *testing.T) {
	cause := errors.New("sensitive cause")
	err := &OpError{Op: "shutdown", Err: cause}
	if !errors.Is(err, cause) {
		t.Fatal("OpError does not unwrap its cause")
	}
	if err.Error() == cause.Error() {
		t.Fatal("OpError exposed its cause")
	}
}

func TestServeInitializationFailureCompletesShutdown(t *testing.T) {
	server, err := New(Config{DGP: dgpv1.ServerConfig{CipherSuite: dgpv1.CipherSuite(255)}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Serve(context.Background(), listener); err == nil {
		t.Fatal("Serve succeeded with an unsupported cipher")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown after Serve initialization failure: %v", err)
	}
}

func TestCloseAndShutdownBeforeServeAreIdempotent(t *testing.T) {
	server, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDisconnectedConsumesStateExactlyOnce(t *testing.T) {
	var calls atomic.Int32
	got := make(chan error, 1)
	server, err := New(Config{OnDisconnect: func(_ context.Context, _ ConnectionInfo, cause error) {
		calls.Add(1)
		got <- cause
	}})
	if err != nil {
		t.Fatal(err)
	}
	conn := new(dgpv1.Connection)
	server.states.Store(conn, connectionState{})
	cause := errors.New("terminal")
	start := make(chan struct{})
	var callers sync.WaitGroup
	for range 16 {
		callers.Add(1)
		go func() {
			defer callers.Done()
			<-start
			server.disconnected(context.Background(), conn, dgpv1.AdmissionInfo{}, cause)
		}()
	}
	close(start)
	callers.Wait()
	if calls.Load() != 1 || !errors.Is(<-got, cause) {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestServeIsOneShotUnderConcurrentCalls(t *testing.T) {
	server, err := New(Config{DGP: dgpv1.ServerConfig{StaticKey: fixedKey(t, 11)}})
	if err != nil {
		t.Fatal(err)
	}

	const callers = 16
	listeners := make([]net.Listener, callers)
	for i := range listeners {
		listeners[i], err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listeners[i].Close()
	}

	start := make(chan struct{})
	results := make(chan error, callers)
	for _, listener := range listeners {
		go func() {
			<-start
			results <- server.Serve(context.Background(), listener)
		}()
	}
	close(start)

	started := 0
	for range callers - 1 {
		select {
		case err := <-results:
			if !errors.Is(err, ErrServerStarted) {
				t.Fatalf("competing Serve returned %v", err)
			}
			started++
		case <-time.After(time.Second):
			t.Fatal("competing Serve did not return")
		}
	}
	if started != callers-1 {
		t.Fatalf("rejected Serve calls = %d", started)
	}

	_ = server.Close()
	select {
	case err := <-results:
		if err != nil {
			t.Fatalf("winning Serve returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("winning Serve did not stop")
	}
	if err := server.Serve(context.Background(), listeners[0]); !errors.Is(err, ErrServerStarted) {
		t.Fatalf("Serve after stop returned %v", err)
	}
}

func TestServeRootCancellationStopsServerAndFreezesRouter(t *testing.T) {
	server, err := New(Config{DGP: dgpv1.ServerConfig{StaticKey: fixedKey(t, 12)}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()

	deadline := time.Now().Add(time.Second)
	for !server.Router().Frozen() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !server.Router().Frozen() {
		t.Fatal("router was not frozen before serving")
	}
	if err := server.Router().Use(func(next Handler) Handler { return next }); !errors.Is(err, ErrServerStarted) {
		t.Fatalf("middleware mutation after start returned %v", err)
	}
	if err := server.Router().HandleAck(func(*Context, *dgpv1.Ack) error { return nil }); !errors.Is(err, ErrServerStarted) {
		t.Fatalf("route mutation after start returned %v", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve after root cancellation returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop after root cancellation")
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown after root cancellation returned %v", err)
	}
}

func TestServeWithCanceledRootContextReturnsNil(t *testing.T) {
	server, err := New(Config{DGP: dgpv1.ServerConfig{StaticKey: fixedKey(t, 13)}})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not observe an already-canceled root context")
	}
}
