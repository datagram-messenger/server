package dgpserver

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/tr1xdev/datagram-server.git/pkg/dgpv1"
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
