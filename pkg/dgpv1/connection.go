package dgpv1

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrConnectionClosed indicates that the connection runtime has terminated.
	ErrConnectionClosed = errors.New("dgpv1: connection closed")
	// ErrIdleTimeout indicates that inbound activity did not occur before the idle timeout.
	ErrIdleTimeout = errors.New("dgpv1: connection idle timeout")
	// ErrKeepaliveTimeout indicates that an outstanding ping was not acknowledged in time.
	ErrKeepaliveTimeout = errors.New("dgpv1: keepalive timeout")
	// ErrOutboundQueueFull indicates that a nonblocking send found the outbound queue full.
	ErrOutboundQueueFull = errors.New("dgpv1: outbound queue full")
	// ErrHandlerQueueFull indicates that pending handler work exceeded its bound.
	ErrHandlerQueueFull = errors.New("dgpv1: handler queue full")
	// ErrHandlerPanic wraps a panic recovered from a MessageHandler.
	ErrHandlerPanic = errors.New("dgpv1: handler panic")
)

// MessageHandler handles one authenticated inbound message. The runtime calls
// handlers serially on a dedicated worker; returning an error or panicking
// closes the connection. The context is canceled when the connection terminates.
type MessageHandler func(context.Context, *Connection, any) error

// ConnectionConfig controls an established connection runtime.
type ConnectionConfig struct {
	OutboundQueue     int
	HandlerQueue      int
	HandshakeTimeout  time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	KeepaliveInterval time.Duration
	KeepaliveTimeout  time.Duration
	Handler           MessageHandler
}

type queuedMessage struct {
	message    any
	padLength  uint8
	completion chan error
}

type closeRequest struct {
	message SessionClose
	cause   error
	result  chan error
}

// Connection runs an already-established Session over a TCPTransport. Its
// exported methods are safe for concurrent use.
type Connection struct {
	transport *TCPTransport
	session   *Session
	config    ConnectionConfig

	ctx          context.Context
	cancel       context.CancelCauseFunc
	outbound     chan queuedMessage
	closeRequest chan closeRequest
	activity     chan struct{}
	pong         chan uint64
	handlerQueue chan any
	done         chan struct{}

	startOnce    sync.Once
	shutdownOnce sync.Once
	closeOnce    sync.Once
	causeMu      sync.Mutex
	terminal     error
	terminalRank uint8
	started      atomic.Bool
	closing      atomic.Bool
	pingNonce    atomic.Uint64
	wg           sync.WaitGroup
}

// NewConnection constructs a stopped established-session runtime.
func NewConnection(transport *TCPTransport, session *Session, config ConnectionConfig) *Connection {
	if transport == nil || session == nil {
		panic("dgpv1: nil connection dependency")
	}
	if config.OutboundQueue <= 0 {
		config.OutboundQueue = 16
	}
	if config.HandlerQueue <= 0 {
		config.HandlerQueue = 16
	}
	if config.KeepaliveInterval > 0 && config.KeepaliveTimeout <= 0 {
		config.KeepaliveTimeout = 2 * config.KeepaliveInterval
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	return &Connection{
		transport:    transport,
		session:      session,
		config:       config,
		ctx:          ctx,
		cancel:       cancel,
		outbound:     make(chan queuedMessage, config.OutboundQueue),
		closeRequest: make(chan closeRequest, 1),
		activity:     make(chan struct{}, 1),
		pong:         make(chan uint64, 1),
		handlerQueue: make(chan any, config.HandlerQueue),
		done:         make(chan struct{}),
	}
}

// Start begins the connection runtime until ctx or the connection ends.
func (c *Connection) Start(ctx context.Context) {
	c.startOnce.Do(func() {
		c.started.Store(true)
		loops := 3
		if c.config.Handler != nil {
			loops++
		}
		c.wg.Add(loops)
		go c.readLoop()
		go c.writeLoop()
		go c.maintenanceLoop()
		if c.config.Handler != nil {
			go c.handlerLoop()
		}
		go func() {
			select {
			case <-ctx.Done():
				_ = c.closeGracefully(SessionClose{Code: 0, Reason: "context canceled"}, ctx.Err())
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

// Send queues a message without waiting for network I/O. It returns
// ErrOutboundQueueFull rather than blocking when the queue is full.
func (c *Connection) Send(message any) error { return c.SendPadded(message, 0) }

// TrySend is the explicit nonblocking form of Send.
func (c *Connection) TrySend(message any) error { return c.Send(message) }

// SendContext waits for outbound queue capacity or context cancellation. It
// returns after enqueueing and does not wait for the local transport write.
func (c *Connection) SendContext(ctx context.Context, message any) error {
	return c.enqueue(ctx, queuedMessage{message: message}, true)
}

// SendAndWait waits for queue capacity and for the local transport write to
// complete. Completion does not imply that the peer processed the message.
func (c *Connection) SendAndWait(ctx context.Context, message any) error {
	completion := make(chan error, 1)
	if err := c.enqueue(ctx, queuedMessage{message: message, completion: completion}, true); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case err := <-completion:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		select {
		case err := <-completion:
			return err
		default:
			return context.Cause(c.ctx)
		}
	}
}

func (c *Connection) enqueue(ctx context.Context, item queuedMessage, wait bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if c.closing.Load() {
		return ErrConnectionClosed
	}
	if !wait {
		select {
		case c.outbound <- item:
			return nil
		default:
			return ErrOutboundQueueFull
		}
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.ctx.Done():
		return ErrConnectionClosed
	case c.outbound <- item:
		return nil
	}
}

// SendPadded queues a message with the requested encrypted-frame padding. It
// does not wait for network I/O and returns ErrOutboundQueueFull on backpressure.
func (c *Connection) SendPadded(message any, padLength uint8) error {
	if c.closing.Load() {
		return ErrConnectionClosed
	}
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

// Close sends a normal SessionClose when the runtime is active, then stops it.
func (c *Connection) Close() error {
	return c.closeGracefully(SessionClose{Code: 0, Reason: "local shutdown"}, ErrConnectionClosed)
}

// Done closes after all runtime loops exit.
func (c *Connection) Done() <-chan struct{} { return c.done }

// Err returns the terminal cause, or nil while running. When termination signals
// race, handler panics take precedence over handler errors, transport/protocol
// errors, local or context cancellation, and ordinary EOF, in that order.
func (c *Connection) Err() error {
	c.causeMu.Lock()
	defer c.causeMu.Unlock()
	return c.terminal
}

func (c *Connection) closeGracefully(message SessionClose, cause error) error {
	var result error
	c.closeOnce.Do(func() {
		c.closing.Store(true)
		if !c.started.Load() {
			c.shutdown(cause)
			return
		}
		request := closeRequest{message: message, cause: cause, result: make(chan error, 1)}
		gracePeriod := c.config.WriteTimeout
		if gracePeriod <= 0 {
			gracePeriod = 100 * time.Millisecond
		}
		timer := time.NewTimer(gracePeriod)
		defer timer.Stop()
		select {
		case c.closeRequest <- request:
			select {
			case result = <-request.result:
			case <-c.ctx.Done():
				result = context.Cause(c.ctx)
			case <-timer.C:
				result = context.DeadlineExceeded
			}
		case <-c.ctx.Done():
			result = context.Cause(c.ctx)
		case <-timer.C:
			result = context.DeadlineExceeded
		}
		c.shutdown(cause)
	})
	return result
}

func (c *Connection) shutdown(cause error) {
	if cause == nil {
		cause = ErrConnectionClosed
	}
	c.recordTerminal(cause)
	c.shutdownOnce.Do(func() {
		c.closing.Store(true)
		c.cancel(cause)
		_ = c.session.Close()
		_ = c.transport.Close()
	})
}

func (c *Connection) recordTerminal(cause error) {
	c.recordTerminalWithRank(cause, terminalCauseRank(cause))
}

func (c *Connection) recordTerminalWithRank(cause error, rank uint8) {
	if errors.Is(cause, ErrHandlerPanic) {
		rank = 5
	}
	c.causeMu.Lock()
	if rank > c.terminalRank {
		c.terminal, c.terminalRank = cause, rank
	}
	c.causeMu.Unlock()
}

func terminalCauseRank(cause error) uint8 {
	switch {
	case errors.Is(cause, ErrHandlerPanic):
		return 5
	case cause != nil && !errors.Is(cause, io.EOF) && !errors.Is(cause, context.Canceled) && !errors.Is(cause, context.DeadlineExceeded) && !errors.Is(cause, ErrConnectionClosed):
		return 3
	case errors.Is(cause, ErrConnectionClosed), errors.Is(cause, context.Canceled), errors.Is(cause, context.DeadlineExceeded):
		return 2
	default:
		return 1
	}
}

func handlerCauseRank(cause error) uint8 {
	if errors.Is(cause, ErrHandlerPanic) {
		return 5
	}
	return 4
}

// abort force-closes network I/O without waiting for the graceful close path.
func (c *Connection) abort(cause error) { c.shutdown(cause) }

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
		c.noteActivity()
		dispatch := true
		switch m := message.(type) {
		case *PingPong:
			dispatch = false
			if m.IsResponse {
				select {
				case c.pong <- m.Nonce:
				default:
				}
			} else if err := c.Send(PingPong{IsResponse: true, Nonce: m.Nonce}); err != nil {
				c.shutdown(err)
				return
			}
		case *SessionClose:
			c.shutdown(ErrConnectionClosed)
			return
		}
		if dispatch && c.config.Handler != nil {
			select {
			case c.handlerQueue <- message:
			case <-c.ctx.Done():
				return
			default:
				c.shutdown(ErrHandlerQueueFull)
				return
			}
		}
	}
}

func (c *Connection) writeLoop() {
	defer c.wg.Done()
	defer c.failPending()
	for {
		select {
		case request := <-c.closeRequest:
			err := c.writeMessage(queuedMessage{message: request.message})
			request.result <- err
			c.shutdown(request.cause)
			return
		default:
		}

		select {
		case <-c.ctx.Done():
			return
		case request := <-c.closeRequest:
			err := c.writeMessage(queuedMessage{message: request.message})
			request.result <- err
			c.shutdown(request.cause)
			return
		case item := <-c.outbound:
			err := c.writeMessage(item)
			complete(item, err)
			if err != nil {
				c.shutdown(err)
				return
			}
		}
	}
}

func complete(item queuedMessage, err error) {
	if item.completion != nil {
		item.completion <- err
	}
}

func (c *Connection) failPending() {
	err := context.Cause(c.ctx)
	if err == nil {
		err = ErrConnectionClosed
	}
	for {
		select {
		case item := <-c.outbound:
			complete(item, err)
		default:
			return
		}
	}
}

// writeMessage retries the original message after any automatically generated
// RekeyInit frame so rekeying never drops the caller's message.
func (c *Connection) writeMessage(item queuedMessage) error {
	for {
		frame, err := c.session.Send(item.message, item.padLength)
		if err != nil {
			return err
		}
		ctx, cancel := c.operationContext(c.config.WriteTimeout)
		err = c.transport.WriteFrame(ctx, frame)
		cancel()
		if err != nil {
			return err
		}
		if frame.Header.MessageType != MessageTypeRekeyInit {
			return nil
		}
		if err := c.session.MarkRekeySent(frame); err != nil {
			return err
		}
	}
}

func (c *Connection) maintenanceLoop() {
	defer c.wg.Done()
	var idleTimer, keepaliveTimer, pongTimer *time.Timer
	var idle, keepalive, pongDeadline <-chan time.Time
	if c.config.IdleTimeout > 0 {
		idleTimer = time.NewTimer(c.config.IdleTimeout)
		idle = idleTimer.C
		defer idleTimer.Stop()
	}
	if c.config.KeepaliveInterval > 0 {
		keepaliveTimer = time.NewTimer(c.config.KeepaliveInterval)
		keepalive = keepaliveTimer.C
		defer keepaliveTimer.Stop()
	}
	var outstanding uint64

	for {
		select {
		case <-c.ctx.Done():
			if pongTimer != nil {
				pongTimer.Stop()
			}
			return
		case <-c.activity:
			resetTimer(idleTimer, c.config.IdleTimeout)
		case nonce := <-c.pong:
			if outstanding != 0 && nonce == outstanding {
				outstanding = 0
				if pongTimer != nil {
					if !pongTimer.Stop() {
						select {
						case <-pongTimer.C:
						default:
						}
					}
					pongDeadline = nil
				}
				resetTimer(keepaliveTimer, c.config.KeepaliveInterval)
				keepalive = keepaliveTimer.C
			}
		case <-keepalive:
			if outstanding != 0 {
				continue
			}
			outstanding = c.pingNonce.Add(1)
			if err := c.Send(PingPong{Nonce: outstanding}); err != nil {
				c.shutdown(err)
				return
			}
			pongTimer = time.NewTimer(c.config.KeepaliveTimeout)
			pongDeadline = pongTimer.C
			keepalive = nil
		case <-pongDeadline:
			c.shutdown(ErrKeepaliveTimeout)
			return
		case <-idle:
			_ = c.closeGracefully(SessionClose{Code: 3, Reason: "idle timeout"}, ErrIdleTimeout)
			return
		}
	}
}

func (c *Connection) handlerLoop() {
	defer c.wg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		select {
		case <-c.ctx.Done():
			return
		case message := <-c.handlerQueue:
			// Cancellation may race with the receive. Recheck before starting
			// user code; queued callbacks are never begun after shutdown.
			select {
			case <-c.ctx.Done():
				return
			default:
			}
			if err := c.callHandler(message); err != nil {
				c.recordTerminalWithRank(err, handlerCauseRank(err))
				c.shutdown(err)
				return
			}
		}
	}
}

func (c *Connection) noteActivity() {
	select {
	case c.activity <- struct{}{}:
	default:
	}
}

func resetTimer(timer *time.Timer, duration time.Duration) {
	if timer == nil {
		return
	}
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(duration)
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
