package dgpserver_test

import (
	"context"
	"fmt"

	"github.com/tr1xdev/datagram-server.git/pkg/dgpserver"
	"github.com/tr1xdev/datagram-server.git/pkg/dgpv1"
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
