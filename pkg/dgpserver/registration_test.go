package dgpserver

import (
	"context"
	"errors"
	"testing"

	"github.com/datagram-messenger/protocol"
)

func TestContractRegistrationHelpers(t *testing.T) {
	tests := []struct {
		name     string
		register func(*Router, *bool) error
		message  any
	}{
		{
			name: "generic",
			register: func(router *Router, called *bool) error {
				return Handle(router, func(_ *Context, message *dgpv1.Ack) error {
					*called = len(message.Sequences) == 1 && message.Sequences[0] == 1
					return nil
				})
			},
			message: &dgpv1.Ack{Sequences: []uint64{1}},
		},
		{
			name: "encrypted data method",
			register: func(router *Router, called *bool) error {
				return router.HandleEncryptedData(func(_ *Context, message *dgpv1.EncryptedData) error {
					*called = message.StreamID == 2
					return nil
				})
			},
			message: &dgpv1.EncryptedData{StreamID: 2},
		},
		{
			name: "ack method",
			register: func(router *Router, called *bool) error {
				return router.HandleAck(func(_ *Context, message *dgpv1.Ack) error {
					*called = len(message.Sequences) == 1 && message.Sequences[0] == 3
					return nil
				})
			},
			message: &dgpv1.Ack{Sequences: []uint64{3}},
		},
		{
			name: "error method",
			register: func(router *Router, called *bool) error {
				return router.HandleError(func(_ *Context, message *dgpv1.ErrorMessage) error {
					*called = message.Code == 4
					return nil
				})
			},
			message: &dgpv1.ErrorMessage{Code: 4},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var router Router
			called := false
			if err := test.register(&router, &called); err != nil {
				t.Fatal(err)
			}
			if err := router.Dispatch(NewContext(context.Background(), Peer{}, Metadata{}, Params{}), test.message); err != nil {
				t.Fatal(err)
			}
			if !called {
				t.Fatal("handler was not called with the expected message")
			}
		})
	}
}

func TestContractRegistrationHelpersRejectNilAndDuplicates(t *testing.T) {
	var nilRouter *Router
	if err := nilRouter.HandleAck(func(*Context, *dgpv1.Ack) error { return nil }); !errors.Is(err, ErrNilHandler) {
		t.Fatalf("nil router: %v", err)
	}

	var router Router
	if err := router.HandleAck(nil); !errors.Is(err, ErrNilHandler) {
		t.Fatalf("nil handler: %v", err)
	}
	if err := router.HandleAck(func(*Context, *dgpv1.Ack) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if err := Handle(&router, func(*Context, *dgpv1.Ack) error { return nil }); !errors.Is(err, ErrDuplicateHandler) {
		t.Fatalf("duplicate across APIs: %v", err)
	}
}
