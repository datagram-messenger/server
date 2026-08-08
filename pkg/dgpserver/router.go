package dgpserver

import (
	"fmt"
	"reflect"
	"sync"

	"github.com/tr1xdev/datagram-server.git/pkg/dgpv1"
)

// Handler handles one application-visible DGP message.
type Handler interface {
	Handle(*Context, any) error
}

// HandlerFunc adapts a function to Handler.
type HandlerFunc func(*Context, any) error

// Handle calls f(ctx, message).
func (f HandlerFunc) Handle(ctx *Context, message any) error { return f(ctx, message) }

// Middleware wraps a Handler. Middleware is applied in registration order,
// so the first registered middleware is the outermost wrapper.
type Middleware func(Handler) Handler

// ApplicationMessage is the set accepted by RegisterTyped. T is always a
// non-pointer value type; TypedHandlerFunc receives *T. This prevents accidental
// **T signatures and matches the pointer values returned by dgpv1 decoding.
type ApplicationMessage interface {
	dgpv1.EncryptedData | dgpv1.Ack | dgpv1.ErrorMessage
}

// TypedHandlerFunc is a type-safe application handler adapter.
type TypedHandlerFunc[T ApplicationMessage] func(*Context, *T) error

// RegisterTyped registers a typed handler. Pointer T arguments do not satisfy
// ApplicationMessage; use RegisterTyped[dgpv1.Ack], not RegisterTyped[*dgpv1.Ack].
func RegisterTyped[T ApplicationMessage](router *Router, handler TypedHandlerFunc[T]) error {
	if router == nil {
		return ErrNilHandler
	}
	if handler == nil {
		return ErrNilHandler
	}
	messageType, err := typeFor[T]()
	if err != nil {
		return err
	}
	return router.Handle(messageType, HandlerFunc(func(ctx *Context, message any) error {
		typed, ok := message.(*T)
		if !ok {
			return fmt.Errorf("%w: got %T", ErrInvalidMessageForm, message)
		}
		return handler(ctx, typed)
	}))
}

func typeFor[T ApplicationMessage]() (dgpv1.MessageType, error) {
	var zero T
	switch any(zero).(type) {
	case dgpv1.EncryptedData:
		return dgpv1.MessageTypeEncryptedData, nil
	case dgpv1.Ack:
		return dgpv1.MessageTypeAck, nil
	case dgpv1.ErrorMessage:
		return dgpv1.MessageTypeError, nil
	default:
		return 0, ErrUnsupportedMessage
	}
}

// Router registers, freezes, and dispatches application-visible messages.
// Its zero value is ready for use.
type Router struct {
	mu         sync.RWMutex
	handlers   map[dgpv1.MessageType]Handler
	middleware []Middleware
	compiled   map[dgpv1.MessageType]Handler
	frozen     bool
}

// Handle registers a handler for an application-visible message type.
func (r *Router) Handle(messageType dgpv1.MessageType, handler Handler) error {
	if !supportedType(messageType) {
		return fmt.Errorf("%w: 0x%02x", ErrUnsupportedMessage, messageType)
	}
	if nilInterface(handler) {
		return ErrNilHandler
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frozen {
		return ErrServerStarted
	}
	if r.handlers == nil {
		r.handlers = make(map[dgpv1.MessageType]Handler)
	}
	if _, exists := r.handlers[messageType]; exists {
		return fmt.Errorf("%w: 0x%02x", ErrDuplicateHandler, messageType)
	}
	r.handlers[messageType] = handler
	return nil
}

// Use appends middleware before the router is frozen.
func (r *Router) Use(middleware ...Middleware) error {
	for _, item := range middleware {
		if item == nil {
			return ErrNilHandler
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frozen {
		return ErrServerStarted
	}
	r.middleware = append(r.middleware, middleware...)
	return nil
}

// Freeze prevents mutation and compiles every middleware chain exactly once.
func (r *Router) Freeze() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frozen {
		return nil
	}
	r.compiled = make(map[dgpv1.MessageType]Handler, len(r.handlers))
	for messageType, base := range r.handlers {
		chain := base
		for index := len(r.middleware) - 1; index >= 0; index-- {
			chain = r.middleware[index](chain)
			if nilInterface(chain) {
				return fmt.Errorf("%w: middleware returned nil", ErrNilHandler)
			}
		}
		r.compiled[messageType] = chain
	}
	r.frozen = true
	return nil
}

// Frozen reports whether the router has been frozen.
func (r *Router) Frozen() bool { r.mu.RLock(); defer r.mu.RUnlock(); return r.frozen }

// Dispatch invokes the compiled chain for a supported pointer-form message.
// It freezes the router on first use and converts handler panics to PanicError.
func (r *Router) Dispatch(ctx *Context, message any) (err error) {
	messageType, err := inboundType(message)
	if err != nil {
		return err
	}
	if err := r.Freeze(); err != nil {
		return err
	}
	r.mu.RLock()
	handler := r.compiled[messageType]
	r.mu.RUnlock()
	if handler == nil {
		return fmt.Errorf("%w: 0x%02x", ErrNotFound, messageType)
	}
	defer func() {
		if value := recover(); value != nil {
			err = &PanicError{Value: value}
		}
	}()
	return handler.Handle(ctx, message)
}

func supportedType(messageType dgpv1.MessageType) bool {
	return messageType == dgpv1.MessageTypeEncryptedData || messageType == dgpv1.MessageTypeAck || messageType == dgpv1.MessageTypeError
}

func inboundType(message any) (dgpv1.MessageType, error) {
	switch value := message.(type) {
	case *dgpv1.EncryptedData:
		if value == nil {
			return 0, ErrInvalidMessageForm
		}
		return dgpv1.MessageTypeEncryptedData, nil
	case *dgpv1.Ack:
		if value == nil {
			return 0, ErrInvalidMessageForm
		}
		return dgpv1.MessageTypeAck, nil
	case *dgpv1.ErrorMessage:
		if value == nil {
			return 0, ErrInvalidMessageForm
		}
		return dgpv1.MessageTypeError, nil
	case dgpv1.EncryptedData, dgpv1.Ack, dgpv1.ErrorMessage:
		return 0, fmt.Errorf("%w: got %T", ErrInvalidMessageForm, message)
	default:
		return 0, fmt.Errorf("%w: %T", ErrUnsupportedMessage, message)
	}
}

func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	default:
		return false
	}
}
