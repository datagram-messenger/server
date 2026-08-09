package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/tr1xdev/datagram-server.git/internal/buildinfo"
	"github.com/tr1xdev/datagram-server.git/internal/config"
	"github.com/tr1xdev/datagram-server.git/pkg/dgpserver"
	"github.com/tr1xdev/datagram-server.git/pkg/dgpv1"
)

func TestVersionMetadata(t *testing.T) {
	got := buildinfo.String()
	if got == "" {
		t.Fatal("version metadata is empty")
	}
}

func TestCommandRouterRegistration(t *testing.T) {
	router, err := newCommandRouter()
	if err != nil {
		t.Fatal(err)
	}
	if router == nil || router.Handler() == nil {
		t.Fatal("command router was not configured")
	}
}

func TestCommandHandlers(t *testing.T) {
	tests := []struct {
		name    string
		request *dgpv1.EncryptedData
		want    *dgpv1.EncryptedData
	}{
		{
			name: "echo",
			request: &dgpv1.EncryptedData{
				StreamID: 42, AppMessageType: appMessageTypeEcho,
				Fields: []dgpv1.TLV{{Type: 3, Value: []byte{1, 2, 3}}},
			},
			want: &dgpv1.EncryptedData{
				StreamID: 42, AppMessageType: appMessageTypeEcho,
				Fields: []dgpv1.TLV{{Type: 3, Value: []byte{1, 2, 3}}},
			},
		},
		{
			name:    "info",
			request: &dgpv1.EncryptedData{StreamID: 84, AppMessageType: appMessageTypeInfo},
			want: &dgpv1.EncryptedData{
				StreamID: 84, AppMessageType: appMessageTypeInfo,
				Fields: []dgpv1.TLV{
					{Type: infoTLVProtocol, Value: []byte("dgpv1")},
					{Type: infoTLVService, Value: []byte("api_datagram")},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router, err := newCommandRouter()
			if err != nil {
				t.Fatal(err)
			}
			recorder := dgpserver.NewRecorder(1)
			ctx := recorder.NewContext(context.Background(), dgpserver.Peer{}, dgpserver.Metadata{}, dgpserver.Params{})
			if err := router.Handler()(ctx, tt.request); err != nil {
				t.Fatal(err)
			}
			items := recorder.Snapshot()
			if len(items) != 1 {
				t.Fatalf("sent %d messages, want 1", len(items))
			}
			got, ok := items[0].Message.(*dgpv1.EncryptedData)
			if !ok {
				t.Fatalf("response type = %T", items[0].Message)
			}
			assertEncryptedDataEqual(t, got, tt.want)

			if tt.name == "echo" {
				tt.request.Fields[0].Value[0] = 9
				if got.Fields[0].Value[0] != 1 {
					t.Fatal("echo response aliases request fields")
				}
			}
		})
	}
}

func TestCommandRouterUnknownCommand(t *testing.T) {
	router, err := newCommandRouter()
	if err != nil {
		t.Fatal(err)
	}
	recorder := dgpserver.NewRecorder(1)
	ctx := recorder.NewContext(context.Background(), dgpserver.Peer{}, dgpserver.Metadata{}, dgpserver.Params{})
	err = router.Handler()(ctx, &dgpv1.EncryptedData{AppMessageType: 0xff})
	if !errors.Is(err, dgpserver.ErrNotHandled) {
		t.Fatalf("dispatch error = %v, want %v", err, dgpserver.ErrNotHandled)
	}
	if recorder.Len() != 0 {
		t.Fatal("unknown command sent a response")
	}
}

func TestNewServerConfigurationErrors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	tests := []struct {
		name   string
		cfg    config.Config
		logger *slog.Logger
	}{
		{name: "nil logger", logger: nil},
		{name: "negative disconnect-independent DGP timeout", cfg: config.Config{HandshakeTimeout: -1}, logger: logger},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server, err := newServer(tt.cfg, tt.logger)
			if err == nil || server != nil {
				t.Fatalf("newServer() = (%v, %v), want (nil, error)", server, err)
			}
		})
	}
}

func TestRunRejectsMissingStaticKey(t *testing.T) {
	t.Setenv("DGP_STATIC_KEY", "")
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := run(context.Background(), logger, ""); !errors.Is(err, config.ErrStaticKeyRequired) {
		t.Fatalf("run error = %v, want %v", err, config.ErrStaticKeyRequired)
	}
}

func TestServerLifecycleBeforeServe(t *testing.T) {
	var cfg config.Config
	cfg.StaticKey[0] = 1
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	server, err := newServer(cfg, logger)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown() = %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close() = %v", err)
	}
}

func assertEncryptedDataEqual(t *testing.T, got, want *dgpv1.EncryptedData) {
	t.Helper()
	if got.StreamID != want.StreamID || got.AppMessageType != want.AppMessageType || len(got.Fields) != len(want.Fields) {
		t.Fatalf("response = %#v, want %#v", got, want)
	}
	for i := range want.Fields {
		if got.Fields[i].Type != want.Fields[i].Type || !bytes.Equal(got.Fields[i].Value, want.Fields[i].Value) {
			t.Fatalf("response fields = %#v, want %#v", got.Fields, want.Fields)
		}
	}
}

func TestProductionAuthenticator(t *testing.T) {
	var allowed, unknown [32]byte
	allowed[0], unknown[0] = 1, 2
	auth := newAuthenticator(map[[32]byte]string{allowed: "alice"})
	principal, err := auth.Authenticate(context.Background(), dgpserver.Credentials{PeerStatic: allowed})
	if err != nil || principal != "alice" {
		t.Fatalf("allowed principal=%v err=%v", principal, err)
	}
	if _, err := auth.Authenticate(context.Background(), dgpserver.Credentials{PeerStatic: unknown}); !errors.Is(err, dgpserver.ErrUnauthenticated) {
		t.Fatalf("unknown error=%v", err)
	}
}
