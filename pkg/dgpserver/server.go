package dgpserver

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/datagram-messenger/protocol"
)

// ConnectionInfo is an immutable snapshot supplied to lifecycle hooks.
type ConnectionInfo struct {
	Peer      Peer
	Principal Principal
}

// ErrorKind classifies an operation failure.
type ErrorKind uint8

const (
	// ErrorKindHandler identifies an application handler failure.
	ErrorKindHandler ErrorKind = iota + 1
	// ErrorKindPanic identifies a recovered application panic.
	ErrorKindPanic
)

// HandlerError describes a handler failure without defining a wire response.
type HandlerError struct {
	Kind ErrorKind
	Err  error
}

// Error implements error.
func (e *HandlerError) Error() string { return "dgpserver: handler failed" }

// Unwrap returns the underlying application error for local observation.
func (e *HandlerError) Unwrap() error { return e.Err }

// OpError adds an operation name to an error.
type OpError struct {
	Op  string
	Err error
}

// Error implements error.
func (e *OpError) Error() string { return "dgpserver: " + e.Op + " failed" }

// Unwrap returns the operation error.
func (e *OpError) Unwrap() error { return e.Err }

// ErrorHandler observes a handler error and decides whether the connection closes.
type ErrorHandler func(*Context, error) error

// Config configures a production high-level server.
type Config struct {
	DGP           dgpv1.ServerConfig
	Router        *Router
	Authenticator Authenticator
	ErrorHandler  ErrorHandler
	OnConnect     func(context.Context, ConnectionInfo) error
	// OnDisconnect runs exactly once for every connection that reaches active
	// registration. Its cause follows dgpv1 terminal-cause precedence.
	OnDisconnect      func(context.Context, ConnectionInfo, error)
	DisconnectTimeout time.Duration
}

// Server owns one dgpv1 server runtime and its listener.
type Server struct {
	config Config
	router *Router

	mu               sync.Mutex
	core             *dgpv1.Server
	listener         net.Listener
	started          bool
	stopping         bool
	closed           bool
	serveDone        chan struct{}
	serveError       error
	coreCloseDone    chan struct{}
	coreCloseStarted bool
	coreCloseError   error
	states           sync.Map
}

type connectionState struct {
	peer      Peer
	principal Principal
}

type connectionSender struct{ connection *dgpv1.Connection }

func (s connectionSender) trySend(message any) error { return s.connection.TrySend(message) }
func (s connectionSender) send(ctx context.Context, message any, wait bool) error {
	if wait {
		return s.connection.SendAndWait(ctx, message)
	}
	return s.connection.SendContext(ctx, message)
}
func (s connectionSender) close() error { return s.connection.Close() }

// New validates config and constructs a stopped server.
func New(config Config) (*Server, error) {
	router := config.Router
	if router == nil {
		router = &Router{}
	}
	if config.DisconnectTimeout < 0 {
		return nil, errors.New("dgpserver: DisconnectTimeout must not be negative")
	}
	if config.DisconnectTimeout == 0 {
		config.DisconnectTimeout = 5 * time.Second
	}
	return &Server{
		config:        config,
		router:        router,
		serveDone:     make(chan struct{}),
		coreCloseDone: make(chan struct{}),
	}, nil
}

// Router returns the server router for configuration before Serve.
func (s *Server) Router() *Router { return s.router }

// Serve freezes routing, takes ownership of listener, and serves until stopped.
// Exactly one call is permitted.
func (s *Server) Serve(ctx context.Context, listener net.Listener) error {
	if listener == nil {
		return errors.New("dgpserver: nil listener")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return ErrServerStarted
	}
	s.started = true
	s.listener = listener
	s.mu.Unlock()
	if err := s.router.Freeze(); err != nil {
		_ = listener.Close()
		s.finishServe(err)
		return err
	}

	coreConfig := s.config.DGP
	coreConfig.Admission = s.admit
	coreConfig.OnDisconnect = s.disconnected
	coreConfig.Handler = s.handle
	core, err := dgpv1.NewServer(coreConfig)
	if err != nil {
		_ = listener.Close()
		s.finishServe(err)
		return err
	}
	s.mu.Lock()
	s.core = core
	stopping := s.stopping
	if stopping {
		s.startCoreCloseLocked()
	}
	s.mu.Unlock()
	go func() {
		select {
		case <-ctx.Done():
			s.startCoreClose()
		case <-s.serveDone:
		}
	}()
	err = core.Serve(listener)
	s.finishServe(err)
	if errors.Is(err, dgpv1.ErrServerClosed) || (s.wasStopping() && errors.Is(err, net.ErrClosed)) {
		return nil
	}
	return err
}

func (s *Server) wasStopping() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stopping
}

func (s *Server) finishServe(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serveError = err
	if s.core == nil && !s.coreCloseStarted {
		s.coreCloseStarted = true
		close(s.coreCloseDone)
	}
	if !s.closed {
		s.closed = true
		close(s.serveDone)
	}
}

// Shutdown starts graceful shutdown and waits for both Serve and the single
// underlying core Close operation. At ctx expiration it force-closes network I/O
// and returns an OpError wrapping ctx.Err.
func (s *Server) Shutdown(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	s.mu.Lock()
	s.stopping = true
	if !s.started {
		s.finishWithoutCoreLocked()
		s.mu.Unlock()
		return nil
	}
	s.startCoreCloseLocked()
	core, listener := s.core, s.listener
	serveDone, closeDone := s.serveDone, s.coreCloseDone
	s.mu.Unlock()

	if core == nil && listener != nil {
		_ = listener.Close()
	}
	if err := waitForLifecycle(ctx, serveDone, closeDone); err != nil {
		if core != nil {
			_ = core.Abort()
		} else if listener != nil {
			_ = listener.Close()
		}
		return &OpError{Op: "shutdown", Err: err}
	}
	return s.coreCloseResult()
}

// Close immediately starts the same idempotent core closure as Shutdown and
// waits for it to complete.
func (s *Server) Close() error {
	s.mu.Lock()
	s.stopping = true
	if !s.started {
		s.finishWithoutCoreLocked()
		s.mu.Unlock()
		return nil
	}
	s.startCoreCloseLocked()
	listener, closeDone := s.listener, s.coreCloseDone
	if s.core == nil && listener != nil {
		_ = listener.Close()
	}
	s.mu.Unlock()

	<-closeDone
	return s.coreCloseResult()
}

func (s *Server) startCoreClose() {
	s.mu.Lock()
	s.stopping = true
	s.startCoreCloseLocked()
	s.mu.Unlock()
}

// startCoreCloseLocked starts exactly one core.Close call once the core exists.
// The caller must hold s.mu.
func (s *Server) startCoreCloseLocked() {
	if s.core == nil || s.coreCloseStarted {
		return
	}
	s.coreCloseStarted = true
	core := s.core
	go func() {
		err := core.Close()
		s.mu.Lock()
		s.coreCloseError = err
		close(s.coreCloseDone)
		s.mu.Unlock()
	}()
}

// finishWithoutCoreLocked completes both barriers when serving never acquired a
// core. The caller must hold s.mu.
func (s *Server) finishWithoutCoreLocked() {
	if !s.closed {
		s.closed = true
		close(s.serveDone)
	}
	if !s.coreCloseStarted {
		s.coreCloseStarted = true
		close(s.coreCloseDone)
	}
}

func (s *Server) coreCloseResult() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.coreCloseError
}

func waitForLifecycle(ctx context.Context, serveDone, closeDone <-chan struct{}) error {
	for serveDone != nil || closeDone != nil {
		select {
		case <-serveDone:
			serveDone = nil
		case <-closeDone:
			closeDone = nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func (s *Server) admit(ctx context.Context, conn *dgpv1.Connection, info dgpv1.AdmissionInfo) (err error) {
	address := ""
	if info.RemoteAddr != nil {
		address = info.RemoteAddr.String()
	}
	credentials := Credentials{PeerStatic: info.PeerStatic, SessionID: info.SessionID, RemoteAddr: address}
	var principal Principal
	if s.config.Authenticator != nil {
		principal, err = callAuthenticator(s.config.Authenticator, ctx, credentials)
		if err != nil {
			return err
		}
	}
	state := connectionState{peer: NewPeer(address, info.SessionID, info.PeerStatic[:]), principal: principal}
	s.states.Store(conn, state)
	if s.config.OnConnect != nil {
		if err := callConnect(s.config.OnConnect, ctx, ConnectionInfo{Peer: state.peer, Principal: principal}); err != nil {
			s.states.Delete(conn)
			s.callDisconnect(state, err)
			return err
		}
	}
	return nil
}

func (s *Server) handle(ctx context.Context, conn *dgpv1.Connection, message any) error {
	value, ok := s.states.Load(conn)
	if !ok {
		return ErrUnauthenticated
	}
	state := value.(connectionState)
	messageType, err := inboundType(message)
	if err != nil {
		return err
	}
	handlerContext := newContextWithPrincipal(ctx, state.peer, state.principal, NewMetadata(messageType, time.Now()), Params{}, connectionSender{conn})
	err = s.router.Dispatch(handlerContext, message)
	if err == nil {
		return nil
	}
	if s.config.ErrorHandler != nil {
		return callErrorHandler(s.config.ErrorHandler, handlerContext, err)
	}
	if errors.Is(err, ErrNotHandled) {
		return nil
	}
	return &HandlerError{Kind: ErrorKindHandler, Err: err}
}

func (s *Server) disconnected(_ context.Context, conn *dgpv1.Connection, _ dgpv1.AdmissionInfo, cause error) {
	value, ok := s.states.LoadAndDelete(conn)
	if !ok || s.config.OnDisconnect == nil {
		return
	}
	state := value.(connectionState)
	s.callDisconnect(state, cause)
}

func (s *Server) callDisconnect(state connectionState, cause error) {
	if s.config.OnDisconnect == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), s.config.DisconnectTimeout)
	defer cancel()

	// The hook invocation is isolated so user code that ignores ctx cannot retain
	// the protocol core's connection accounting forever. After the timeout this
	// goroutine is intentionally no longer server-owned and may outlive Server.
	done := make(chan struct{})
	go func() {
		defer close(done)
		callDisconnectHook(s.config.OnDisconnect, ctx, ConnectionInfo{Peer: state.peer, Principal: state.principal}, cause)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func callAuthenticator(auth Authenticator, ctx context.Context, credentials Credentials) (principal Principal, err error) {
	defer func() {
		if recover() != nil {
			err = ErrUnauthenticated
		}
	}()
	return auth.Authenticate(ctx, credentials)
}

func callConnect(hook func(context.Context, ConnectionInfo) error, ctx context.Context, info ConnectionInfo) (err error) {
	defer func() {
		if recover() != nil {
			err = errors.New("dgpserver: connect hook panic")
		}
	}()
	return hook(ctx, info)
}

func callDisconnectHook(hook func(context.Context, ConnectionInfo, error), ctx context.Context, info ConnectionInfo, cause error) {
	defer func() { _ = recover() }()
	hook(ctx, info, cause)
}

func callErrorHandler(handler ErrorHandler, ctx *Context, cause error) (err error) {
	defer func() {
		if recover() != nil {
			err = &HandlerError{Kind: ErrorKindPanic, Err: ErrHandlerPanic}
		}
	}()
	return handler(ctx, cause)
}
