package dgpserver

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tr1xdev/datagram-server.git/pkg/dgpv1"
)

func TestDispatchHelper(t *testing.T) {
	peer := NewPeer("remote", [16]byte{7}, []byte{1, 2})
	principal := struct{ name string }{name: "alice"}
	message := &dgpv1.Ack{Sequences: []uint64{9}}
	var receivedAt time.Time
	err := Dispatch(context.Background(), HandlerFunc(func(ctx *Context, got any) error {
		if got != message {
			t.Fatalf("message = %p, want %p", got, message)
		}
		if ctx.Principal() != principal {
			t.Fatalf("principal = %#v", ctx.Principal())
		}
		if ctx.Peer().Address() != "remote" || ctx.Metadata().MessageType() != dgpv1.MessageTypeAck {
			t.Fatal("context snapshots are incomplete")
		}
		receivedAt = ctx.Metadata().ReceivedAt()
		if err := ctx.TrySend(&dgpv1.Ack{}); !errors.Is(err, ErrRecorderClosed) {
			t.Fatalf("send capability = %v", err)
		}
		return nil
	}), peer, principal, message)
	if err != nil {
		t.Fatal(err)
	}
	if receivedAt.IsZero() {
		t.Fatal("received time was not populated")
	}
}

func TestDispatchHelperRejectsInvalidInputAndRecoversPanic(t *testing.T) {
	handler := HandlerFunc(func(*Context, any) error { panic("boom") })
	tests := []struct {
		name    string
		handler Handler
		message any
		want    error
	}{
		{name: "nil handler", message: &dgpv1.Ack{}, want: ErrNilHandler},
		{name: "value message", handler: handler, message: dgpv1.Ack{}, want: ErrInvalidMessageForm},
		{name: "unsupported message", handler: handler, message: &dgpv1.PingPong{}, want: ErrUnsupportedMessage},
		{name: "panic", handler: handler, message: &dgpv1.Ack{}, want: ErrHandlerPanic},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := Dispatch(context.TODO(), test.handler, Peer{}, nil, test.message); !errors.Is(err, test.want) {
				t.Fatalf("Dispatch() = %v, want %v", err, test.want)
			}
		})
	}
}
