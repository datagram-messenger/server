package dgpserver_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/tr1xdev/datagram-server/pkg/dgpserver"
	"github.com/tr1xdev/datagram-server/pkg/dgpv1"
)

func ExampleRouter_HandleEncryptedData() {
	var router dgpserver.Router
	if err := router.HandleEncryptedData(func(_ *dgpserver.Context, message *dgpv1.EncryptedData) error {
		fmt.Println(message.StreamID)
		return nil
	}); err != nil {
		panic(err)
	}
	ctx := dgpserver.NewContext(context.Background(), dgpserver.Peer{}, dgpserver.Metadata{}, dgpserver.Params{})
	if err := router.Dispatch(ctx, &dgpv1.EncryptedData{StreamID: 7}); err != nil {
		panic(err)
	}
	// Output: 7
}

func ExampleCommandRouter() {
	commands := dgpserver.NewCommandRouter(dgpserver.CommandDecoderFunc(
		func(message *dgpv1.EncryptedData) (dgpserver.Command, any, error) {
			return dgpserver.Command(message.AppMessageType), message, nil
		},
	))
	if err := commands.Handle(1, dgpserver.HandlerFunc(func(_ *dgpserver.Context, payload any) error {
		fmt.Println(payload.(*dgpv1.EncryptedData).StreamID)
		return nil
	})); err != nil {
		panic(err)
	}
	var router dgpserver.Router
	if err := router.HandleEncryptedData(commands.Handler()); err != nil {
		panic(err)
	}
	ctx := dgpserver.NewContext(context.Background(), dgpserver.Peer{}, dgpserver.Metadata{}, dgpserver.Params{})
	if err := router.Dispatch(ctx, &dgpv1.EncryptedData{AppMessageType: 1, StreamID: 9}); err != nil {
		panic(err)
	}
	// Output: 9
}

func ExampleCommandRouter_Group() {
	commands := dgpserver.NewCommandRouter(dgpserver.CommandDecoderFunc(
		func(message *dgpv1.EncryptedData) (dgpserver.Command, any, error) {
			return dgpserver.Command(message.AppMessageType), message, nil
		},
	))
	requirePrincipal := func(next dgpserver.Handler) dgpserver.Handler {
		return dgpserver.HandlerFunc(func(ctx *dgpserver.Context, message any) error {
			if ctx.Principal() == nil {
				return dgpserver.ErrUnauthenticated
			}
			return next.Handle(ctx, message)
		})
	}
	if err := commands.Group(func(group *dgpserver.CommandGroup) error {
		if err := group.Use(requirePrincipal); err != nil {
			return err
		}
		return group.Handle(2, dgpserver.HandlerFunc(func(_ *dgpserver.Context, _ any) error {
			fmt.Println("authorized")
			return nil
		}))
	}); err != nil {
		panic(err)
	}
	var router dgpserver.Router
	if err := router.HandleEncryptedData(commands.Handler()); err != nil {
		panic(err)
	}
	peer := dgpserver.NewPeer("example", [16]byte{}, nil)
	if err := dgpserver.Dispatch(context.Background(), dgpserver.HandlerFunc(router.Dispatch), peer, "alice", &dgpv1.EncryptedData{AppMessageType: 2}); err != nil {
		panic(err)
	}
	// Output: authorized
}

func ExampleNewStaticKeyAllowlist() {
	clientKey := [32]byte{1}
	authenticator := dgpserver.NewStaticKeyAllowlist(map[[32]byte]dgpserver.Principal{
		clientKey: "alice",
	})
	principal, err := authenticator.Authenticate(context.Background(), dgpserver.Credentials{PeerStatic: clientKey})
	fmt.Println(principal, err)
	// Output: alice <nil>
}

func ExampleServer_Shutdown() {
	configure := func(listener net.Listener, serverKey dgpv1.StaticKey, clientKey [32]byte) error {
		server, err := dgpserver.New(dgpserver.Config{
			DGP: dgpv1.ServerConfig{
				StaticKey:        serverKey,
				HandshakeTimeout: 10 * time.Second,
				WriteTimeout:     10 * time.Second,
				OutboundQueue:    64,
				HandlerQueue:     64,
			},
			Authenticator: dgpserver.NewStaticKeyAllowlist(map[[32]byte]dgpserver.Principal{clientKey: "alice"}),
		})
		if err != nil {
			return err
		}
		serveDone := make(chan error, 1)
		go func() { serveDone <- server.Serve(context.Background(), listener) }()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			return err
		}
		return <-serveDone
	}
	_ = configure
	_ = errors.Is
}
