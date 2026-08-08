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
		StaticKey:         staticKey,
		CipherSuite:       dgpv1.CipherChaCha20Poly1305,
		HandshakeTimeout:  cfg.HandshakeTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		KeepaliveInterval: cfg.KeepaliveInterval,
		OutboundQueue:     cfg.OutboundQueue,
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
