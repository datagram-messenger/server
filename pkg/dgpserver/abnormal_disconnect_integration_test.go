package dgpserver

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/tr1xdev/datagram-server/pkg/dgpv1"
)

func TestServerRealTCPAbnormalDisconnectCauseExactlyOnce(t *testing.T) {
	handlerFailure := errors.New("handler failure")
	tests := []struct {
		name      string
		handler   TypedHandlerFunc[dgpv1.EncryptedData]
		wantCause error
	}{
		{
			name: "handler error",
			handler: func(*Context, *dgpv1.EncryptedData) error {
				return handlerFailure
			},
			wantCause: handlerFailure,
		},
		{
			name: "handler panic",
			handler: func(*Context, *dgpv1.EncryptedData) error {
				panic("handler panic")
			},
			wantCause: ErrHandlerPanic,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			serverKey, clientKey := fixedKey(t, 11), fixedKey(t, 12)
			causes := make(chan error, 2)
			srv, err := New(Config{
				DGP: dgpv1.ServerConfig{
					StaticKey:        serverKey,
					HandshakeTimeout: runtimeTimeout,
					WriteTimeout:     runtimeTimeout,
				},
				OnDisconnect: func(_ context.Context, _ ConnectionInfo, cause error) {
					causes <- cause
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if err := RegisterTyped[dgpv1.EncryptedData](srv.Router(), test.handler); err != nil {
				t.Fatal(err)
			}

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			serveDone := make(chan error, 1)
			go func() { serveDone <- srv.Serve(context.Background(), listener) }()

			transport, session := connectRuntimeClient(t, listener.Addr().String(), clientKey, serverKey)
			sendClientMessage(t, transport, session, dgpv1.EncryptedData{})
			assertDisconnectCauseExactlyOnce(t, causes, test.wantCause)
			_ = transport.Close()
			stopRuntimeServer(t, srv, serveDone)
		})
	}
}

func TestServerRealTCPReplayRejectionDisconnectCauseExactlyOnce(t *testing.T) {
	serverKey, clientKey := fixedKey(t, 13), fixedKey(t, 14)
	causes := make(chan error, 2)
	srv, err := New(Config{
		DGP: dgpv1.ServerConfig{
			StaticKey:        serverKey,
			HandshakeTimeout: runtimeTimeout,
			WriteTimeout:     runtimeTimeout,
		},
		OnDisconnect: func(_ context.Context, _ ConnectionInfo, cause error) {
			causes <- cause
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterTyped[dgpv1.EncryptedData](srv.Router(), func(*Context, *dgpv1.EncryptedData) error {
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- srv.Serve(context.Background(), listener) }()

	transport, session := connectRuntimeClient(t, listener.Addr().String(), clientKey, serverKey)
	frame, err := session.Send(dgpv1.EncryptedData{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), runtimeTimeout)
	if err := transport.WriteFrame(ctx, frame); err != nil {
		cancel()
		t.Fatal(err)
	}
	if err := transport.WriteFrame(ctx, frame); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()

	assertDisconnectCauseExactlyOnce(t, causes, dgpv1.ErrReplayDuplicate)
	_ = transport.Close()
	stopRuntimeServer(t, srv, serveDone)
}

func assertDisconnectCauseExactlyOnce(t *testing.T, causes <-chan error, want error) {
	t.Helper()
	select {
	case cause := <-causes:
		if !errors.Is(cause, want) {
			t.Fatalf("disconnect cause = %v, want errors.Is(_, %v)", cause, want)
		}
	case <-time.After(runtimeTimeout):
		t.Fatal("disconnect hook not called")
	}
	select {
	case cause := <-causes:
		t.Fatalf("disconnect hook called more than once; second cause = %v", cause)
	case <-time.After(20 * time.Millisecond):
	}
}

func stopRuntimeServer(t *testing.T, srv *Server, serveDone <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), runtimeTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("Serve did not stop")
	}
}
