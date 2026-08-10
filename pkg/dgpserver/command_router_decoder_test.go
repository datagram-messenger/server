package dgpserver

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tr1xdev/datagram-server/pkg/dgpv1"
)

var errDecoderRejected = errors.New("decoder rejected application payload")

type decoderPathError struct {
	kind int
	err  error
}

func (e *decoderPathError) Error() string { return "decoder path rejected" }
func (e *decoderPathError) Unwrap() error { return e.err }

func TestCommandRouterDecoderFailureContract(t *testing.T) {
	tests := []struct {
		name       string
		message    *dgpv1.EncryptedData
		decode     func(*dgpv1.EncryptedData) (Command, any, error)
		want       error
		wantAsKind int
	}{
		{
			name:    "sentinel",
			message: &dgpv1.EncryptedData{AppMessageType: 1},
			decode: func(*dgpv1.EncryptedData) (Command, any, error) {
				return 1, nil, errDecoderRejected
			},
			want: errDecoderRejected,
		},
		{
			name:    "wrapped typed error",
			message: &dgpv1.EncryptedData{AppMessageType: 1},
			decode: func(*dgpv1.EncryptedData) (Command, any, error) {
				return 1, nil, fmt.Errorf("codec boundary: %w", &decoderPathError{kind: 7, err: errDecoderRejected})
			},
			want:       errDecoderRejected,
			wantAsKind: 7,
		},
		{
			name:    "codec-defined malformed payload",
			message: &dgpv1.EncryptedData{AppMessageType: 1, Fields: []dgpv1.TLV{{Type: 0x80}}},
			decode: func(message *dgpv1.EncryptedData) (Command, any, error) {
				if len(message.Fields) != 0 {
					return 0, nil, errDecoderRejected
				}
				return Command(message.AppMessageType), message, nil
			},
			want: errDecoderRejected,
		},
		{
			name:    "unknown command",
			message: &dgpv1.EncryptedData{AppMessageType: 2},
			decode: func(message *dgpv1.EncryptedData) (Command, any, error) {
				return Command(message.AppMessageType), message, nil
			},
			want: ErrNotHandled,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var decoderCalls, handlerCalls atomic.Int32
			commands := NewCommandRouter(CommandDecoderFunc(func(message *dgpv1.EncryptedData) (Command, any, error) {
				decoderCalls.Add(1)
				return test.decode(message)
			}))
			if err := commands.Handle(1, HandlerFunc(func(*Context, any) error {
				handlerCalls.Add(1)
				return nil
			})); err != nil {
				t.Fatal(err)
			}

			err := Dispatch(context.Background(), HandlerFunc(func(ctx *Context, message any) error {
				return commands.Handler()(ctx, message.(*dgpv1.EncryptedData))
			}), Peer{}, nil, test.message)
			if !errors.Is(err, test.want) {
				t.Fatalf("Dispatch() = %v, want match for %v", err, test.want)
			}
			if test.wantAsKind != 0 {
				var typed *decoderPathError
				if !errors.As(err, &typed) || typed.kind != test.wantAsKind {
					t.Fatalf("Dispatch() typed error = %#v", typed)
				}
			}
			if decoderCalls.Load() != 1 {
				t.Fatalf("decoder calls = %d, want 1", decoderCalls.Load())
			}
			if handlerCalls.Load() != 0 {
				t.Fatalf("handler calls = %d, want 0", handlerCalls.Load())
			}
		})
	}
}

func TestCommandRouterNilMessageRejectedBeforeDecoder(t *testing.T) {
	var decoderCalls atomic.Int32
	commands := NewCommandRouter(CommandDecoderFunc(func(message *dgpv1.EncryptedData) (Command, any, error) {
		decoderCalls.Add(1)
		return 1, message, nil
	}))

	err := Dispatch(context.Background(), HandlerFunc(func(ctx *Context, message any) error {
		return commands.Handler()(ctx, message.(*dgpv1.EncryptedData))
	}), Peer{}, nil, (*dgpv1.EncryptedData)(nil))
	if !errors.Is(err, ErrInvalidMessageForm) {
		t.Fatalf("Dispatch() = %v, want %v", err, ErrInvalidMessageForm)
	}
	if decoderCalls.Load() != 0 {
		t.Fatalf("decoder calls = %d, want 0", decoderCalls.Load())
	}
}

func TestCommandRouterDecoderPanicUsesDispatchSafetyBoundary(t *testing.T) {
	var handlerCalls atomic.Int32
	commands := NewCommandRouter(CommandDecoderFunc(func(*dgpv1.EncryptedData) (Command, any, error) {
		panic("decoder panic")
	}))
	if err := commands.Handle(1, HandlerFunc(func(*Context, any) error {
		handlerCalls.Add(1)
		return nil
	})); err != nil {
		t.Fatal(err)
	}

	err := Dispatch(context.Background(), HandlerFunc(func(ctx *Context, message any) error {
		return commands.Handler()(ctx, message.(*dgpv1.EncryptedData))
	}), Peer{}, nil, &dgpv1.EncryptedData{AppMessageType: 1})
	if !errors.Is(err, ErrHandlerPanic) {
		t.Fatalf("Dispatch() = %v, want %v", err, ErrHandlerPanic)
	}
	var panicError *PanicError
	if !errors.As(err, &panicError) || panicError.Value != "decoder panic" {
		t.Fatalf("Dispatch() panic = %#v", panicError)
	}
	if handlerCalls.Load() != 0 {
		t.Fatalf("handler calls = %d, want 0", handlerCalls.Load())
	}
}

func TestServerHandlePropagatesDecoderErrorToErrorHandlerExactlyOnce(t *testing.T) {
	secret := "application-payload-secret"
	decodeErr := &decoderPathError{kind: 9, err: errDecoderRejected}
	var decoderCalls, handlerCalls, errorHandlerCalls atomic.Int32
	commands := NewCommandRouter(CommandDecoderFunc(func(*dgpv1.EncryptedData) (Command, any, error) {
		decoderCalls.Add(1)
		return 1, nil, decodeErr
	}))
	if err := commands.Handle(1, HandlerFunc(func(*Context, any) error {
		handlerCalls.Add(1)
		return nil
	})); err != nil {
		t.Fatal(err)
	}
	var router Router
	if err := router.HandleEncryptedData(commands.Handler()); err != nil {
		t.Fatal(err)
	}
	server, err := New(Config{
		Router: &router,
		ErrorHandler: func(_ *Context, err error) error {
			errorHandlerCalls.Add(1)
			if !errors.Is(err, errDecoderRejected) {
				t.Errorf("ErrorHandler error = %v", err)
			}
			var typed *decoderPathError
			if !errors.As(err, &typed) || typed != decodeErr {
				t.Errorf("ErrorHandler typed error = %#v", typed)
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	conn := new(dgpv1.Connection)
	server.states.Store(conn, connectionState{})
	if err := server.handle(context.Background(), conn, &dgpv1.EncryptedData{Fields: []dgpv1.TLV{{Type: 1, Value: []byte(secret)}}}); err != nil {
		t.Fatalf("handle() = %v", err)
	}
	if decoderCalls.Load() != 1 || errorHandlerCalls.Load() != 1 || handlerCalls.Load() != 0 {
		t.Fatalf("calls: decoder=%d error-handler=%d handler=%d", decoderCalls.Load(), errorHandlerCalls.Load(), handlerCalls.Load())
	}

	server.config.ErrorHandler = nil
	err = server.handle(context.Background(), conn, &dgpv1.EncryptedData{Fields: []dgpv1.TLV{{Type: 1, Value: []byte(secret)}}})
	var handlerError *HandlerError
	if !errors.As(err, &handlerError) || !errors.Is(err, errDecoderRejected) {
		t.Fatalf("default handle error = %v", err)
	}
	if strings.Contains(err.Error(), secret) || strings.Contains(err.Error(), decodeErr.Error()) {
		t.Fatalf("formatted SDK error exposed decoder or payload detail: %q", err)
	}
}

func FuzzCommandRouterDecoderPaths(f *testing.F) {
	for _, seed := range []struct {
		mode, command uint8
		payload       []byte
	}{
		{0, 1, nil},
		{1, 1, []byte("malformed")},
		{2, 1, []byte{0xff}},
		{3, 2, nil},
		{4, 1, []byte("panic")},
	} {
		f.Add(seed.mode, seed.command, seed.payload)
	}

	f.Fuzz(func(t *testing.T, mode, command uint8, payload []byte) {
		mode %= 5
		var decoderCalls, handlerCalls atomic.Int32
		commands := NewCommandRouter(CommandDecoderFunc(func(message *dgpv1.EncryptedData) (Command, any, error) {
			decoderCalls.Add(1)
			switch mode {
			case 1:
				return 0, nil, errDecoderRejected
			case 2:
				return 0, nil, fmt.Errorf("decode: %w", &decoderPathError{kind: len(payload), err: errDecoderRejected})
			case 4:
				panic("decoder panic")
			default:
				return Command(message.AppMessageType), message, nil
			}
		}))
		if err := commands.Handle(1, HandlerFunc(func(*Context, any) error {
			handlerCalls.Add(1)
			return nil
		})); err != nil {
			t.Fatal(err)
		}
		message := &dgpv1.EncryptedData{AppMessageType: command}
		if len(payload) != 0 {
			message.Fields = []dgpv1.TLV{{Type: 1, Value: payload}}
		}
		err := Dispatch(context.Background(), HandlerFunc(func(ctx *Context, message any) error {
			return commands.Handler()(ctx, message.(*dgpv1.EncryptedData))
		}), Peer{}, nil, message)

		if decoderCalls.Load() != 1 {
			t.Fatalf("decoder calls = %d, want 1", decoderCalls.Load())
		}
		wantHandler := int32(0)
		switch mode {
		case 1, 2:
			if !errors.Is(err, errDecoderRejected) {
				t.Fatalf("decoder error = %v", err)
			}
		case 4:
			if !errors.Is(err, ErrHandlerPanic) {
				t.Fatalf("panic error = %v", err)
			}
		default:
			if command == 1 {
				if err != nil {
					t.Fatalf("registered command error = %v", err)
				}
				wantHandler = 1
			} else if !errors.Is(err, ErrNotHandled) {
				t.Fatalf("unknown command error = %v", err)
			}
		}
		if handlerCalls.Load() != wantHandler {
			t.Fatalf("handler calls = %d, want %d", handlerCalls.Load(), wantHandler)
		}
	})
}
