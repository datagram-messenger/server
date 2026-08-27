package dgpserver

import (
	"context"
	"testing"
	"time"

	"github.com/datagram-messenger/dgproto-go"
)

func BenchmarkDispatchOverhead(b *testing.B) {
	message := &dgproto.EncryptedData{AppMessageType: 7, StreamID: 9}
	handler := HandlerFunc(func(*Context, any) error { return nil })
	handlerContext := NewContext(
		context.Background(),
		Peer{},
		NewMetadata(dgproto.MessageTypeEncryptedData, time.Unix(0, 0)),
		Params{},
	)

	b.Run("Handler", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := handler.Handle(handlerContext, message); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("DispatchHelper", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if err := Dispatch(context.Background(), handler, Peer{}, nil, message); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("FrozenTypedRouter", func(b *testing.B) {
		var router Router
		if err := router.HandleEncryptedData(func(*Context, *dgproto.EncryptedData) error { return nil }); err != nil {
			b.Fatal(err)
		}
		if err := router.Freeze(); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if err := router.Dispatch(handlerContext, message); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("FrozenTypedRouterWithMiddleware", func(b *testing.B) {
		var router Router
		if err := router.Use(
			benchmarkMiddleware,
			benchmarkMiddleware,
			benchmarkMiddleware,
		); err != nil {
			b.Fatal(err)
		}
		if err := router.HandleEncryptedData(func(*Context, *dgproto.EncryptedData) error { return nil }); err != nil {
			b.Fatal(err)
		}
		if err := router.Freeze(); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if err := router.Dispatch(handlerContext, message); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("FrozenCommandRouter", func(b *testing.B) {
		commands := NewCommandRouter(CommandDecoderFunc(
			func(message *dgproto.EncryptedData) (Command, any, error) {
				return Command(message.AppMessageType), message, nil
			},
		))
		if err := commands.Handle(7, handler); err != nil {
			b.Fatal(err)
		}
		commandHandler := commands.Handler()
		if err := commandHandler(handlerContext, message); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for b.Loop() {
			if err := commandHandler(handlerContext, message); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func benchmarkMiddleware(next Handler) Handler {
	return HandlerFunc(func(ctx *Context, message any) error {
		return next.Handle(ctx, message)
	})
}
