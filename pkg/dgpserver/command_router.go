package dgpserver

import (
	"fmt"
	"sync"

	"github.com/tr1xdev/datagram-server/pkg/dgpv1"
)

// Command identifies an application command carried by EncryptedData.
type Command uint8

// CommandDecoder extracts a command and codec-specific payload from EncryptedData.
type CommandDecoder interface {
	DecodeCommand(*dgpv1.EncryptedData) (Command, any, error)
}

// CommandDecoderFunc adapts a function to CommandDecoder.
type CommandDecoderFunc func(*dgpv1.EncryptedData) (Command, any, error)

// DecodeCommand calls f.
func (f CommandDecoderFunc) DecodeCommand(message *dgpv1.EncryptedData) (Command, any, error) {
	return f(message)
}

// CommandRouter routes decoded application commands. Registration is safe only
// before the first dispatch; dispatch freezes the router.
type CommandRouter struct {
	mu         sync.Mutex
	decoder    CommandDecoder
	handlers   map[Command]Handler
	middleware []Middleware
	compiled   map[Command]Handler
	frozen     bool
}

// CommandGroup is a registration-time middleware scope within a CommandRouter.
type CommandGroup struct {
	router     *CommandRouter
	middleware []Middleware
}

// NewCommandRouter constructs a command router using decoder.
func NewCommandRouter(decoder CommandDecoder) *CommandRouter {
	return &CommandRouter{decoder: decoder, handlers: make(map[Command]Handler)}
}

// Use appends command-router-wide middleware.
func (r *CommandRouter) Use(middleware ...Middleware) error {
	if r == nil {
		return ErrNilHandler
	}
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

// Handle registers a command handler.
func (r *CommandRouter) Handle(command Command, handler Handler) error {
	if r == nil || nilInterface(handler) {
		return ErrNilHandler
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.handleLocked(command, handler, nil)
}

// Group registers handlers in a middleware scope. The callback is executed
// synchronously and must not retain the group.
func (r *CommandRouter) Group(register func(*CommandGroup) error) error {
	if r == nil || register == nil {
		return ErrNilHandler
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.frozen {
		return ErrServerStarted
	}
	return register(&CommandGroup{router: r})
}

// Use appends middleware to this group.
func (g *CommandGroup) Use(middleware ...Middleware) error {
	if g == nil || g.router == nil {
		return ErrNilHandler
	}
	for _, item := range middleware {
		if item == nil {
			return ErrNilHandler
		}
	}
	if g.router.frozen {
		return ErrServerStarted
	}
	g.middleware = append(g.middleware, middleware...)
	return nil
}

// Handle registers a command with this group's middleware.
func (g *CommandGroup) Handle(command Command, handler Handler) error {
	if g == nil || g.router == nil || nilInterface(handler) {
		return ErrNilHandler
	}
	return g.router.handleLocked(command, handler, g.middleware)
}

func (r *CommandRouter) handleLocked(command Command, handler Handler, groupMiddleware []Middleware) error {
	if r.frozen {
		return ErrServerStarted
	}
	if _, exists := r.handlers[command]; exists {
		return fmt.Errorf("%w: command 0x%02x", ErrDuplicateHandler, command)
	}
	chain := handler
	for index := len(groupMiddleware) - 1; index >= 0; index-- {
		chain = groupMiddleware[index](chain)
		if nilInterface(chain) {
			return fmt.Errorf("%w: middleware returned nil", ErrNilHandler)
		}
	}
	r.handlers[command] = chain
	return nil
}

// Handler returns a typed EncryptedData handler suitable for RegisterTyped.
func (r *CommandRouter) Handler() TypedHandlerFunc[dgpv1.EncryptedData] {
	return func(ctx *Context, message *dgpv1.EncryptedData) error {
		return r.dispatch(ctx, message)
	}
}

func (r *CommandRouter) dispatch(ctx *Context, message *dgpv1.EncryptedData) error {
	if r == nil || r.decoder == nil {
		return ErrNilHandler
	}
	command, payload, err := r.decoder.DecodeCommand(message)
	if err != nil {
		return err
	}
	r.mu.Lock()
	if !r.frozen {
		r.compiled = make(map[Command]Handler, len(r.handlers))
		for registered, base := range r.handlers {
			chain := base
			for index := len(r.middleware) - 1; index >= 0; index-- {
				chain = r.middleware[index](chain)
				if nilInterface(chain) {
					r.mu.Unlock()
					return fmt.Errorf("%w: middleware returned nil", ErrNilHandler)
				}
			}
			r.compiled[registered] = chain
		}
		r.frozen = true
	}
	handler := r.compiled[command]
	r.mu.Unlock()
	if handler == nil {
		return fmt.Errorf("%w: command 0x%02x", ErrNotHandled, command)
	}
	return handler.Handle(ctx, payload)
}
