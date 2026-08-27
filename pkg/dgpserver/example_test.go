package dgpserver_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/datagram-messenger/dgproto-go"
	"github.com/tr1xdev/datagram-server/pkg/dgpserver"
)

func Example() {
	recorder := dgpserver.NewRecorder(1)
	ctx := recorder.NewContext(context.Background(), dgpserver.Peer{}, dgpserver.Metadata{}, dgpserver.Params{})

	var router dgpserver.Router
	if err := router.HandleEncryptedData(func(ctx *dgpserver.Context, message *dgproto.EncryptedData) error {
		return ctx.TrySend(&dgproto.EncryptedData{
			StreamID:       message.StreamID,
			AppMessageType: message.AppMessageType,
			Fields:         message.Fields,
		})
	}); err != nil {
		panic(err)
	}
	if err := router.Dispatch(ctx, &dgproto.EncryptedData{StreamID: 7, AppMessageType: 1}); err != nil {
		panic(err)
	}

	reply := recorder.Snapshot()[0].Message.(*dgproto.EncryptedData)
	fmt.Println(reply.StreamID, reply.AppMessageType)
	// Output: 7 1
}

func ExampleRouter_HandleEncryptedData() {
	var router dgpserver.Router
	if err := router.HandleEncryptedData(func(_ *dgpserver.Context, message *dgproto.EncryptedData) error {
		fmt.Println(message.StreamID)
		return nil
	}); err != nil {
		panic(err)
	}
	ctx := dgpserver.NewContext(context.Background(), dgpserver.Peer{}, dgpserver.Metadata{}, dgpserver.Params{})
	if err := router.Dispatch(ctx, &dgproto.EncryptedData{StreamID: 7}); err != nil {
		panic(err)
	}
	// Output: 7
}

func ExampleCommandRouter() {
	commands := dgpserver.NewCommandRouter(dgpserver.CommandDecoderFunc(
		func(message *dgproto.EncryptedData) (dgpserver.Command, any, error) {
			return dgpserver.Command(message.AppMessageType), message, nil
		},
	))
	if err := commands.Handle(1, dgpserver.HandlerFunc(func(_ *dgpserver.Context, payload any) error {
		fmt.Println(payload.(*dgproto.EncryptedData).StreamID)
		return nil
	})); err != nil {
		panic(err)
	}
	var router dgpserver.Router
	if err := router.HandleEncryptedData(commands.Handler()); err != nil {
		panic(err)
	}
	ctx := dgpserver.NewContext(context.Background(), dgpserver.Peer{}, dgpserver.Metadata{}, dgpserver.Params{})
	if err := router.Dispatch(ctx, &dgproto.EncryptedData{AppMessageType: 1, StreamID: 9}); err != nil {
		panic(err)
	}
	// Output: 9
}

func ExampleCommandRouter_Group() {
	commands := dgpserver.NewCommandRouter(dgpserver.CommandDecoderFunc(
		func(message *dgproto.EncryptedData) (dgpserver.Command, any, error) {
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
	if err := dgpserver.Dispatch(context.Background(), dgpserver.HandlerFunc(router.Dispatch), peer, "alice", &dgproto.EncryptedData{AppMessageType: 2}); err != nil {
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
	contextCapabilities := func(ctx *dgpserver.Context, message any) error {
		var embedded context.Context = ctx
		_ = embedded
		if err := ctx.Send(message); err != nil {
			return err
		}
		if err := ctx.SendAndWait(message); err != nil {
			return err
		}
		return ctx.Close()
	}
	configure := func(listener net.Listener, serverKey dgproto.StaticKey, clientKey [32]byte) error {
		server, err := dgpserver.New(dgpserver.Config{
			DGP: dgproto.ServerConfig{
				StaticKey:        serverKey,
				HandshakeTimeout: 10 * time.Second,
				WriteTimeout:     10 * time.Second,
				OutboundQueue:    64,
				HandlerQueue:     64,
			},
			Authenticator: dgpserver.NewStaticKeyAllowlist(map[[32]byte]dgpserver.Principal{clientKey: "alice"}),
			ErrorHandler: func(_ *dgpserver.Context, err error) error {
				return err
			},
			OnConnect: func(_ context.Context, info dgpserver.ConnectionInfo) error {
				_ = info.Peer
				return nil
			},
			OnDisconnect: func(_ context.Context, info dgpserver.ConnectionInfo, err error) {
				_, _ = info.Principal, err
			},
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
	_ = contextCapabilities
	_ = configure
	_ = errors.Is
}
