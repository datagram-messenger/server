package main

import (
	"context"
	"errors"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/tr1xdev/datagram-server.git/internal/config"
	"github.com/tr1xdev/datagram-server.git/pkg/dgpv1"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

const (
	// appMessageTypeEcho identifies an application echo request and response.
	appMessageTypeEcho uint8 = 0x01
	// appMessageTypeInfo identifies an application information request and response.
	appMessageTypeInfo uint8 = 0x02
	// infoTLVProtocol identifies the protocol name in an information response.
	infoTLVProtocol uint8 = 0x01
	// infoTLVService identifies the service name in an information response.
	infoTLVService uint8 = 0x02
)

func responseFor(message any) (*dgpv1.EncryptedData, bool) {
	data, ok := message.(*dgpv1.EncryptedData)
	if !ok || data == nil {
		return nil, false
	}

	response := &dgpv1.EncryptedData{
		StreamID:       data.StreamID,
		AppMessageType: data.AppMessageType,
	}

	switch data.AppMessageType {
	case appMessageTypeEcho:
		response.Fields = make([]dgpv1.TLV, len(data.Fields))
		for i, field := range data.Fields {
			response.Fields[i] = dgpv1.TLV{
				Type:  field.Type,
				Value: append([]byte(nil), field.Value...),
			}
		}
	case appMessageTypeInfo:
		response.Fields = []dgpv1.TLV{
			{Type: infoTLVProtocol, Value: []byte("dgpv1")},
			{Type: infoTLVService, Value: []byte("api_datagram")},
		}
	default:
		return nil, false
	}

	return response, true
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	staticKey, err := dgpv1.LoadStaticKey(cfg.StaticKey[:])
	if err != nil {
		return err
	}
	server, err := dgpv1.NewServer(dgpv1.ServerConfig{
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
		Handler: func(_ context.Context, conn *dgpv1.Connection, message any) error {
			response, ok := responseFor(message)
			if !ok {
				return nil
			}
			return conn.Send(response)
		},
	})
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", cfg.Address)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		_ = server.Close()
	}()

	log.Printf("DGPv1 server listening on %s", listener.Addr())
	if err := server.Serve(listener); err != nil && !errors.Is(err, dgpv1.ErrServerClosed) {
		return err
	}
	return nil
}
