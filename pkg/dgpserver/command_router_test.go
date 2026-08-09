package dgpserver

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/tr1xdev/datagram-server/pkg/dgpv1"
)

func TestCommandRouterDispatchAndGroups(t *testing.T) {
	decoder := CommandDecoderFunc(func(message *dgpv1.EncryptedData) (Command, any, error) {
		return Command(message.AppMessageType), message, nil
	})
	router := NewCommandRouter(decoder)
	var order []string
	middleware := func(name string) Middleware {
		return func(next Handler) Handler {
			return HandlerFunc(func(ctx *Context, message any) error {
				order = append(order, name+" before")
				err := next.Handle(ctx, message)
				order = append(order, name+" after")
				return err
			})
		}
	}
	if err := router.Use(middleware("global")); err != nil {
		t.Fatal(err)
	}
	if err := router.Group(func(group *CommandGroup) error {
		if err := group.Use(middleware("group")); err != nil {
			return err
		}
		return group.Handle(7, HandlerFunc(func(_ *Context, payload any) error {
			message, ok := payload.(*dgpv1.EncryptedData)
			if !ok || message.StreamID != 9 {
				t.Fatalf("payload = %#v", payload)
			}
			order = append(order, "handler")
			return nil
		}))
	}); err != nil {
		t.Fatal(err)
	}

	var dgp Router
	if err := RegisterTyped[dgpv1.EncryptedData](&dgp, router.Handler()); err != nil {
		t.Fatal(err)
	}
	if err := dgp.Dispatch(NewContext(context.Background(), Peer{}, Metadata{}, Params{}), &dgpv1.EncryptedData{AppMessageType: 7, StreamID: 9}); err != nil {
		t.Fatal(err)
	}
	if got, want := fmt.Sprint(order), fmt.Sprint([]string{"global before", "group before", "handler", "group after", "global after"}); got != want {
		t.Fatalf("order = %s, want %s", got, want)
	}
	if err := router.Handle(8, HandlerFunc(func(*Context, any) error { return nil })); !errors.Is(err, ErrServerStarted) {
		t.Fatalf("mutation after dispatch = %v", err)
	}
}

func TestCommandRouterErrors(t *testing.T) {
	decodeError := errors.New("decode")
	router := NewCommandRouter(CommandDecoderFunc(func(*dgpv1.EncryptedData) (Command, any, error) {
		return 0, nil, decodeError
	}))
	if err := router.dispatch(nil, &dgpv1.EncryptedData{}); !errors.Is(err, decodeError) {
		t.Fatalf("decoder error = %v", err)
	}

	router = NewCommandRouter(CommandDecoderFunc(func(message *dgpv1.EncryptedData) (Command, any, error) {
		return Command(message.AppMessageType), message, nil
	}))
	handler := HandlerFunc(func(*Context, any) error { return nil })
	if err := router.Handle(1, handler); err != nil {
		t.Fatal(err)
	}
	if err := router.Handle(1, handler); !errors.Is(err, ErrDuplicateHandler) {
		t.Fatalf("duplicate = %v", err)
	}
	if err := router.dispatch(nil, &dgpv1.EncryptedData{AppMessageType: 2}); !errors.Is(err, ErrNotHandled) {
		t.Fatalf("unknown command = %v", err)
	}
}

func TestCommandRouterRejectsNilConfiguration(t *testing.T) {
	var nilRouter *CommandRouter
	if err := nilRouter.Handle(1, HandlerFunc(func(*Context, any) error { return nil })); !errors.Is(err, ErrNilHandler) {
		t.Fatalf("nil router = %v", err)
	}
	router := NewCommandRouter(nil)
	if err := router.Handle(1, nil); !errors.Is(err, ErrNilHandler) {
		t.Fatalf("nil handler = %v", err)
	}
	if err := router.Use(nil); !errors.Is(err, ErrNilHandler) {
		t.Fatalf("nil middleware = %v", err)
	}
	if err := router.Group(nil); !errors.Is(err, ErrNilHandler) {
		t.Fatalf("nil group callback = %v", err)
	}
	if err := router.dispatch(nil, &dgpv1.EncryptedData{}); !errors.Is(err, ErrNilHandler) {
		t.Fatalf("nil decoder = %v", err)
	}
}
