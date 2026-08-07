package dgpv1

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrConnectionClosed  = errors.New("dgpv1: connection closed")
	ErrOutboundQueueFull = errors.New("dgpv1: outbound queue full")
	ErrHandlerPanic      = errors.New("dgpv1: handler panic")
)

// MessageHandler handles one authenticated inbound message.
type MessageHandler func(context.Context, *Connection, any) error

// ConnectionConfig controls an established connection runtime.
type ConnectionConfig struct {
	OutboundQueue    int
	HandshakeTimeout time.Duration
	ReadTimeout      time.Duration
	WriteTimeout     time.Duration
	IdleTimeout      time.Duration
	Handler          MessageHandler
}

type queuedMessage struct {
	message   any
	padLength uint8
}

// Connection runs an already-established Session over a TCPTransport.
type Connection struct {
	transport *TCPTransport
	session   *Session
	config    ConnectionConfig

	ctx      context.Context
	cancel   context.CancelCauseFunc
	outbound chan queuedMessage
	done     chan struct{}

	startOnce sync.Once
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// NewConnection constructs a stopped established-session runtime.
func NewConnection(transport *TCPTransport, session *Session, config ConnectionConfig) *Connection {
	if transport == nil || session == nil {
		panic("dgpv1: nil connection dependency")
	}
	if config.OutboundQueue <= 0 {
		config.OutboundQueue = 16
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	return &Connection{
		transport: transport,
		session:   session,
		config:    config,
		ctx:       ctx,
		cancel:    cancel,
		outbound:  make(chan queuedMessage, config.OutboundQueue),
		done:      make(chan struct{}),
	}
}

// Start begins the read and writer loops until ctx or the connection ends.
func (c *Connection) Start(ctx context.Context) {
	c.startOnce.Do(func() {
		c.wg.Add(2)
		go c.readLoop()
		go c.writeLoop()
		go func() {
			select {
			case <-ctx.Done():
				c.shutdown(ctx.Err())
			case <-c.ctx.Done():
			}
		}()
		go func() {
			c.wg.Wait()
			c.shutdown(context.Cause(c.ctx))
			close(c.done)
		}()
	})
}

// Send queues a message without waiting for network I/O.
func (c *Connection) Send(message any) error { return c.SendPadded(message, 0) }

// SendPadded queues a message with encrypted padding.
func (c *Connection) SendPadded(message any, padLength uint8) error {
	select {
	case <-c.ctx.Done():
		return ErrConnectionClosed
	default:
	}
	select {
	case c.outbound <- queuedMessage{message: message, padLength: padLength}:
		return nil
	default:
		return ErrOutboundQueueFull
	}
}

// Close stops the runtime and closes its transport and session once.
func (c *Connection) Close() error {
	c.shutdown(ErrConnectionClosed)
	return nil
}

// Done closes after both runtime loops exit.
func (c *Connection) Done() <-chan struct{} { return c.done }

// Err returns the terminal cause, or nil while running.
func (c *Connection) Err() error { return context.Cause(c.ctx) }

func (c *Connection) shutdown(cause error) {
	if cause == nil {
		cause = ErrConnectionClosed
	}
	c.closeOnce.Do(func() {
		c.cancel(cause)
		_ = c.session.Close()
		_ = c.transport.Close()
	})
}

func (c *Connection) readLoop() {
	defer c.wg.Done()
	for {
		ctx, cancel := c.operationContext(c.config.ReadTimeout)
		frame, err := c.transport.ReadFrame(ctx)
		cancel()
		if err != nil {
			c.shutdown(err)
			return
		}
		message, err := c.session.Receive(frame)
		if err != nil {
			c.shutdown(err)
			return
		}
		switch m := message.(type) {
		case *PingPong:
			if !m.IsResponse {
				if err := c.Send(PingPong{IsResponse: true, Nonce: m.Nonce}); err != nil {
					c.shutdown(err)
					return
				}
			}
		case *SessionClose:
			c.shutdown(ErrConnectionClosed)
			return
		case *RekeyInit:
			c.shutdown(fmt.Errorf("%w: rekey unsupported", ErrMessageType))
			return
		}
		if c.config.Handler != nil {
			if err := c.callHandler(message); err != nil {
				c.shutdown(err)
				return
			}
		}
	}
}

func (c *Connection) writeLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		case item := <-c.outbound:
			frame, err := c.session.Send(item.message, item.padLength)
			if err != nil {
				c.shutdown(err)
				return
			}
			ctx, cancel := c.operationContext(c.config.WriteTimeout)
			err = c.transport.WriteFrame(ctx, frame)
			cancel()
			if err != nil {
				c.shutdown(err)
				return
			}
		}
	}
}

func (c *Connection) operationContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		return context.WithCancel(c.ctx)
	}
	return context.WithTimeout(c.ctx, timeout)
}

func (c *Connection) callHandler(message any) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			err = fmt.Errorf("%w: %v", ErrHandlerPanic, recovered)
		}
	}()
	return c.config.Handler(c.ctx, c, message)
}
