package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tr1xdev/datagram-server.git/internal/buildinfo"
	"github.com/tr1xdev/datagram-server.git/internal/config"
	"github.com/tr1xdev/datagram-server.git/pkg/dgpserver"
	"github.com/tr1xdev/datagram-server.git/pkg/dgpv1"
)

const (
	appMessageTypeEcho uint8 = 0x01
	appMessageTypeInfo uint8 = 0x02

	infoTLVProtocol uint8 = 0x01
	infoTLVService  uint8 = 0x02

	shutdownTimeout = 10 * time.Second
)

func main() {
	configPath := flag.String("config", "", "path to YAML configuration file")
	showVersion := flag.Bool("version", false, "print version metadata and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(buildinfo.String())
		return
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, logger, *configPath); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func newCommandRouter() (*dgpserver.CommandRouter, error) {
	commands := dgpserver.NewCommandRouter(dgpserver.CommandDecoderFunc(func(message *dgpv1.EncryptedData) (dgpserver.Command, any, error) {
		return dgpserver.Command(message.AppMessageType), message, nil
	}))
	for _, route := range []struct {
		command dgpserver.Command
		handler dgpserver.TypedHandlerFunc[dgpv1.EncryptedData]
	}{
		{dgpserver.Command(appMessageTypeEcho), handleEcho},
		{dgpserver.Command(appMessageTypeInfo), handleInfo},
	} {
		handler := route.handler
		err := commands.Handle(route.command, dgpserver.HandlerFunc(func(ctx *dgpserver.Context, payload any) error {
			message, ok := payload.(*dgpv1.EncryptedData)
			if !ok {
				return dgpserver.ErrInvalidMessageForm
			}
			return handler(ctx, message)
		}))
		if err != nil {
			return nil, err
		}
	}
	return commands, nil
}

func handleEcho(ctx *dgpserver.Context, message *dgpv1.EncryptedData) error {
	response := &dgpv1.EncryptedData{
		StreamID:       message.StreamID,
		AppMessageType: message.AppMessageType,
		Fields:         make([]dgpv1.TLV, len(message.Fields)),
	}
	for i, field := range message.Fields {
		response.Fields[i] = dgpv1.TLV{Type: field.Type, Value: append([]byte(nil), field.Value...)}
	}
	return ctx.Send(response)
}

func handleInfo(ctx *dgpserver.Context, message *dgpv1.EncryptedData) error {
	return ctx.Send(&dgpv1.EncryptedData{
		StreamID:       message.StreamID,
		AppMessageType: message.AppMessageType,
		Fields: []dgpv1.TLV{
			{Type: infoTLVProtocol, Value: []byte("dgpv1")},
			{Type: infoTLVService, Value: []byte("api_datagram")},
		},
	})
}

func newAuthenticator(identities map[[32]byte]string) dgpserver.Authenticator {
	entries := make(map[[32]byte]dgpserver.Principal, len(identities))
	for key, principal := range identities {
		entries[key] = principal
	}
	return dgpserver.NewStaticKeyAllowlist(entries)
}

func newServer(cfg config.Config, logger *slog.Logger) (*dgpserver.Server, error) {
	if logger == nil {
		return nil, errors.New("api_datagram: nil logger")
	}
	if cfg.HandshakeTimeout < 0 {
		return nil, errors.New("api_datagram: handshake timeout must not be negative")
	}
	staticKey, err := dgpv1.LoadStaticKey(cfg.StaticKey[:])
	if err != nil {
		return nil, fmt.Errorf("load static key: %w", err)
	}
	commands, err := newCommandRouter()
	if err != nil {
		return nil, err
	}

	server, err := dgpserver.New(dgpserver.Config{
		DGP: dgpv1.ServerConfig{
			StaticKey:               staticKey,
			CipherSuite:             dgpv1.CipherChaCha20Poly1305,
			HandshakeTimeout:        cfg.HandshakeTimeout,
			ReadTimeout:             cfg.ReadTimeout,
			WriteTimeout:            cfg.WriteTimeout,
			IdleTimeout:             cfg.IdleTimeout,
			KeepaliveInterval:       cfg.KeepaliveInterval,
			KeepaliveTimeout:        cfg.KeepaliveTimeout,
			OutboundQueue:           cfg.OutboundQueue,
			HandlerQueue:            cfg.HandlerQueue,
			MaxConcurrentHandshakes: cfg.MaxConcurrentHandshakes,
			MaxActiveConnections:    cfg.MaxActiveConnections,
		},
		Authenticator: newAuthenticator(cfg.PeerIdentities),
		ErrorHandler: func(_ *dgpserver.Context, err error) error {
			if errors.Is(err, dgpserver.ErrNotHandled) {
				logger.Warn("application message not handled")
				return nil
			}
			logger.Error("application handler failed")
			return err
		},
		OnConnect: func(_ context.Context, info dgpserver.ConnectionInfo) error {
			logger.Info("peer connected", "remote_addr", info.Peer.Address())
			return nil
		},
		OnDisconnect: func(_ context.Context, info dgpserver.ConnectionInfo, _ error) {
			logger.Info("peer disconnected", "remote_addr", info.Peer.Address())
		},
		DisconnectTimeout: 5 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("create server: %w", err)
	}
	if err := dgpserver.RegisterTyped[dgpv1.EncryptedData](server.Router(), commands.Handler()); err != nil {
		return nil, fmt.Errorf("register application routes: %w", err)
	}
	return server, nil
}

func run(ctx context.Context, logger *slog.Logger, configPath string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	server, err := newServer(cfg, logger)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	logger.Info("DGPv1 server listening", "address", listener.Addr().String())

	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(context.Background(), listener) }()
	select {
	case err := <-serveDone:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			return err
		}
		return <-serveDone
	}
}
