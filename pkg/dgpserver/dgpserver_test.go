package dgpserver

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/datagram-messenger/protocol"
)

func TestZeroRouterAndRegistrationErrors(t *testing.T) {
	var router Router
	ctx := NewContext(context.Background(), Peer{}, Metadata{}, Params{})
	if err := router.Dispatch(ctx, &dgpv1.Ack{Sequences: []uint64{1}}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("zero router: %v", err)
	}
	if !router.Frozen() {
		t.Fatal("dispatch must freeze zero router")
	}
	if err := router.Handle(dgpv1.MessageTypeAck, HandlerFunc(func(*Context, any) error { return nil })); !errors.Is(err, ErrServerStarted) {
		t.Fatalf("mutation after freeze: %v", err)
	}

	tests := []struct {
		name string
		call func(*Router) error
		want error
	}{
		{"nil handler", func(r *Router) error { return r.Handle(dgpv1.MessageTypeAck, nil) }, ErrNilHandler},
		{"typed nil handler", func(r *Router) error { return RegisterTyped[dgpv1.Ack](r, nil) }, ErrNilHandler},
		{"unsupported type", func(r *Router) error {
			return r.Handle(dgpv1.MessageTypePingPong, HandlerFunc(func(*Context, any) error { return nil }))
		}, ErrUnsupportedMessage},
		{"nil middleware", func(r *Router) error { return r.Use(nil) }, ErrNilHandler},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var r Router
			if err := test.call(&r); !errors.Is(err, test.want) {
				t.Fatalf("got %v, want %v", err, test.want)
			}
		})
	}

	var duplicate Router
	h := HandlerFunc(func(*Context, any) error { return nil })
	if err := duplicate.Handle(dgpv1.MessageTypeAck, h); err != nil {
		t.Fatal(err)
	}
	if err := duplicate.Handle(dgpv1.MessageTypeAck, h); !errors.Is(err, ErrDuplicateHandler) {
		t.Fatalf("duplicate: %v", err)
	}
}

func TestTypedDispatch(t *testing.T) {
	tests := []struct {
		name     string
		register func(*Router, *bool) error
		message  any
	}{
		{"encrypted", func(r *Router, called *bool) error {
			return RegisterTyped[dgpv1.EncryptedData](r, func(_ *Context, got *dgpv1.EncryptedData) error { *called = got.StreamID == 7; return nil })
		}, &dgpv1.EncryptedData{StreamID: 7}},
		{"ack", func(r *Router, called *bool) error {
			return RegisterTyped[dgpv1.Ack](r, func(_ *Context, got *dgpv1.Ack) error { *called = got.Sequences[0] == 9; return nil })
		}, &dgpv1.Ack{Sequences: []uint64{9}}},
		{"error", func(r *Router, called *bool) error {
			return RegisterTyped[dgpv1.ErrorMessage](r, func(_ *Context, got *dgpv1.ErrorMessage) error { *called = got.Code == 3; return nil })
		}, &dgpv1.ErrorMessage{Code: 3}},
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
				t.Fatal("typed handler not called")
			}
		})
	}
}

func TestDispatchPointerPolicyAndUnsupported(t *testing.T) {
	var router Router
	for _, message := range []any{dgpv1.EncryptedData{}, dgpv1.Ack{}, dgpv1.ErrorMessage{}} {
		if err := router.Dispatch(nil, message); !errors.Is(err, ErrInvalidMessageForm) {
			t.Errorf("%T: %v", message, err)
		}
	}
	for _, message := range []any{nil, &dgpv1.PingPong{}, (*dgpv1.Ack)(nil)} {
		err := router.Dispatch(nil, message)
		if !errors.Is(err, ErrUnsupportedMessage) && !errors.Is(err, ErrInvalidMessageForm) {
			t.Errorf("%T: %v", message, err)
		}
	}
}

func TestMiddlewareOrderShortCircuitAndSingleCompilation(t *testing.T) {
	var router Router
	var order []string
	var compiled atomic.Int32
	makeMiddleware := func(name string) Middleware {
		return func(next Handler) Handler {
			compiled.Add(1)
			return HandlerFunc(func(ctx *Context, message any) error {
				order = append(order, name+" before")
				err := next.Handle(ctx, message)
				order = append(order, name+" after")
				return err
			})
		}
	}
	if err := router.Use(makeMiddleware("one"), makeMiddleware("two")); err != nil {
		t.Fatal(err)
	}
	if err := RegisterTyped[dgpv1.Ack](&router, func(*Context, *dgpv1.Ack) error { order = append(order, "handler"); return nil }); err != nil {
		t.Fatal(err)
	}
	if err := router.Freeze(); err != nil {
		t.Fatal(err)
	}
	if err := router.Freeze(); err != nil {
		t.Fatal(err)
	}
	if got := compiled.Load(); got != 2 {
		t.Fatalf("compiled %d times", got)
	}
	if err := router.Dispatch(nil, &dgpv1.Ack{}); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprint([]string{"one before", "two before", "handler", "two after", "one after"})
	if fmt.Sprint(order) != want {
		t.Fatalf("order %v, want %s", order, want)
	}

	var short Router
	called := false
	stop := errors.New("stop")
	if err := short.Use(func(Handler) Handler { return HandlerFunc(func(*Context, any) error { return stop }) }); err != nil {
		t.Fatal(err)
	}
	if err := RegisterTyped[dgpv1.Ack](&short, func(*Context, *dgpv1.Ack) error { called = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := short.Dispatch(nil, &dgpv1.Ack{}); !errors.Is(err, stop) {
		t.Fatalf("short circuit: %v", err)
	}
	if called {
		t.Fatal("short-circuited handler called")
	}
}

func TestMiddlewareMayCallNextMoreThanOnce(t *testing.T) {
	var router Router
	var calls int
	if err := router.Use(func(next Handler) Handler {
		return HandlerFunc(func(ctx *Context, message any) error {
			if err := next.Handle(ctx, message); err != nil {
				return err
			}
			return next.Handle(ctx, message)
		})
	}); err != nil {
		t.Fatal(err)
	}
	if err := RegisterTyped[dgpv1.Ack](&router, func(*Context, *dgpv1.Ack) error {
		calls++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := router.Dispatch(nil, &dgpv1.Ack{}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("handler calls = %d, want 2", calls)
	}
}

func TestPanicConversion(t *testing.T) {
	var router Router
	if err := RegisterTyped[dgpv1.Ack](&router, func(*Context, *dgpv1.Ack) error { panic("boom") }); err != nil {
		t.Fatal(err)
	}
	err := router.Dispatch(nil, &dgpv1.Ack{})
	if !errors.Is(err, ErrHandlerPanic) {
		t.Fatalf("panic: %v", err)
	}
	var panicError *PanicError
	if !errors.As(err, &panicError) || panicError.Value != "boom" {
		t.Fatalf("panic detail: %#v", err)
	}
}

func TestContextSnapshotsAndOwnership(t *testing.T) {
	identity := []byte{1, 2}
	values := map[string]string{"id": "old"}
	peer := NewPeer("remote", [16]byte{7}, identity)
	params := NewParams(values)
	metadata := NewMetadata(dgpv1.MessageTypeAck, time.Unix(5, 0))
	ctx := NewContext(context.Background(), peer, metadata, params)
	identity[0] = 9
	values["id"] = "new"
	gotIdentity := ctx.Peer().Identity()
	gotIdentity[0] = 8
	if ctx.Peer().Identity()[0] != 1 {
		t.Fatal("peer identity aliases caller")
	}
	if got, _ := ctx.Params().Get("id"); got != "old" {
		t.Fatalf("params = %q", got)
	}
	all := ctx.Params().All()
	all["id"] = "changed"
	if got, _ := ctx.Params().Get("id"); got != "old" {
		t.Fatal("params map aliases snapshot")
	}
	if ctx.Metadata().MessageType() != dgpv1.MessageTypeAck || !ctx.Metadata().ReceivedAt().Equal(time.Unix(5, 0)) {
		t.Fatal("metadata mismatch")
	}
	if ctx.Peer().Address() != "remote" || ctx.Peer().SessionID()[0] != 7 {
		t.Fatal("peer mismatch")
	}
}

func TestRecorderBoundsCopiesDrainCancelAndClose(t *testing.T) {
	recorder := NewRecorder(1)
	value := []byte{1, 2}
	message := &dgpv1.EncryptedData{Fields: []dgpv1.TLV{{Type: 1, Value: value}}}
	if err := recorder.TrySend(message); err != nil {
		t.Fatal(err)
	}
	value[0] = 9
	message.Fields[0].Value[1] = 8
	if err := recorder.TrySend(&dgpv1.Ack{}); !errors.Is(err, ErrRecorderFull) {
		t.Fatalf("full: %v", err)
	}
	snapshot := recorder.Snapshot()
	got := snapshot[0].Message.(*dgpv1.EncryptedData)
	if fmt.Sprint(got.Fields[0].Value) != "[1 2]" {
		t.Fatalf("record aliases source: %v", got.Fields[0].Value)
	}
	got.Fields[0].Value[0] = 7
	if recorder.Snapshot()[0].Message.(*dgpv1.EncryptedData).Fields[0].Value[0] != 1 {
		t.Fatal("snapshot aliases recorder")
	}
	if drained := recorder.Drain(); len(drained) != 1 || recorder.Len() != 0 {
		t.Fatalf("drain len %d/%d", len(drained), recorder.Len())
	}

	if err := recorder.SendAndWait(context.Background(), &dgpv1.Ack{Sequences: []uint64{4}}); err != nil {
		t.Fatal(err)
	}
	if !recorder.Snapshot()[0].Wait {
		t.Fatal("SendAndWait not marked complete")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := recorder.Send(cancelled, &dgpv1.Ack{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}

	blocked := make(chan error, 1)
	go func() { blocked <- recorder.Send(context.Background(), &dgpv1.Ack{}) }()
	time.Sleep(10 * time.Millisecond)
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-blocked:
		if !errors.Is(err, ErrRecorderClosed) {
			t.Fatalf("blocked close: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("blocked sender not released")
	}
	if err := recorder.TrySend(nil); !errors.Is(err, ErrRecorderClosed) {
		t.Fatalf("send after close: %v", err)
	}
	if err := recorder.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRecorderContextAndConcurrency(t *testing.T) {
	const count = 64
	recorder := NewRecorder(count)
	ctx := recorder.NewContext(context.Background(), Peer{}, Metadata{}, Params{})
	var wait sync.WaitGroup
	for index := range count {
		wait.Go(func() {
			var err error
			if index%2 == 0 {
				err = ctx.TrySend(&dgpv1.Ack{Sequences: []uint64{uint64(index)}})
			} else {
				err = ctx.SendAndWait(&dgpv1.Ack{Sequences: []uint64{uint64(index)}})
			}
			if err != nil {
				t.Errorf("send %d: %v", index, err)
			}
		})
	}
	wait.Wait()
	if recorder.Len() != count {
		t.Fatalf("len = %d", recorder.Len())
	}
	items := recorder.Snapshot()
	seen := make(map[uint64]bool, count)
	for _, item := range items {
		seen[item.Message.(*dgpv1.Ack).Sequences[0]] = true
	}
	if len(seen) != count {
		t.Fatalf("unique = %d", len(seen))
	}
	if err := ctx.Close(); err != nil {
		t.Fatal(err)
	}
}
