package dgpv1

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

var (
	// ErrServerClosed is returned when operating on a server that has been shut down.
	ErrServerClosed = errors.New("dgpv1: server closed")

	// ErrHandshakeFailed is returned when a Noise XX handshake cannot be completed.
	ErrHandshakeFailed = errors.New("dgpv1: handshake failed")

	// ErrClientNotPermitted is returned when an authenticated client static key is not in AllowedClients.
	ErrClientNotPermitted = errors.New("dgpv1: client static key not permitted")
)

// ServerConfig configures the runtime parameters and cryptographic settings for a Server.
type ServerConfig struct {
	// StaticKey is the server's long-term Noise static key pair.
	StaticKey StaticKey

	// AllowedClients is an optional whitelist of 32-byte client static public keys.
	// If empty, any client presenting a valid Noise handshake is permitted.
	AllowedClients [][]byte

	// CipherSuite sets the symmetric encryption algorithm used after handshake.
	CipherSuite CipherSuite

	// HandshakeTimeout controls the maximum duration allowed to complete the Noise XX exchange.
	HandshakeTimeout time.Duration

	// ReadTimeout sets the network read deadline per frame.
	ReadTimeout time.Duration

	// WriteTimeout sets the network write deadline per frame.
	WriteTimeout time.Duration

	// IdleTimeout controls the maximum time a connection may remain idle.
	IdleTimeout time.Duration

	// KeepaliveInterval controls how often an encrypted Ping is sent.
	KeepaliveInterval time.Duration

	// OutboundQueue sets the channel capacity for buffered outbound messages.
	OutboundQueue int

	// Handler processes authenticated inbound messages received on active connections.
	Handler MessageHandler
}

// Server accepts incoming TCP connections, completes Noise XX handshakes,
// and manages connection lifecycles.
type Server struct {
	config     ServerConfig
	listener   net.Listener
	mu         sync.Mutex
	conns      map[*Connection]struct{}
	closed     chan struct{}
	inShutdown atomic.Bool
	wg         sync.WaitGroup
}

// NewServer constructs a Server instance with applied defaults for unconfigured timeouts.
func NewServer(config ServerConfig) (*Server, error) {
	if config.CipherSuite == 0 {
		config.CipherSuite = CipherChaCha20Poly1305
	}
	if config.HandshakeTimeout <= 0 {
		config.HandshakeTimeout = 10 * time.Second
	}
	if config.OutboundQueue <= 0 {
		config.OutboundQueue = 16
	}
	return &Server{
		config: config,
		conns:  make(map[*Connection]struct{}),
		closed: make(chan struct{}),
	}, nil
}

// Serve binds listener and processes incoming connections until Close or listener failure.
func (s *Server) Serve(listener net.Listener) error {
	if listener == nil {
		return errors.New("dgpv1: nil listener")
	}
	s.mu.Lock()
	if s.inShutdown.Load() {
		s.mu.Unlock()
		return ErrServerClosed
	}
	s.listener = listener
	s.mu.Unlock()

	for {
		netConn, err := listener.Accept()
		if err != nil {
			if s.inShutdown.Load() {
				return ErrServerClosed
			}
			return err
		}

		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(c)
		}(netConn)
	}
}

// Close stops accepting new connections and closes all active connections.
func (s *Server) Close() error {
	if s.inShutdown.Swap(true) {
		return nil
	}
	close(s.closed)

	s.mu.Lock()
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	for conn := range s.conns {
		_ = conn.Close()
	}
	s.mu.Unlock()

	s.wg.Wait()
	return err
}

func (s *Server) handleConn(netConn net.Conn) {
	transport := NewTCPTransport(netConn)

	ctx, cancel := context.WithTimeout(context.Background(), s.config.HandshakeTimeout)
	session, err := s.performHandshake(ctx, transport)
	cancel()
	if err != nil {
		_ = transport.Close()
		return
	}

	connConfig := ConnectionConfig{
		OutboundQueue:     s.config.OutboundQueue,
		HandshakeTimeout:  s.config.HandshakeTimeout,
		ReadTimeout:       s.config.ReadTimeout,
		WriteTimeout:      s.config.WriteTimeout,
		IdleTimeout:       s.config.IdleTimeout,
		KeepaliveInterval: s.config.KeepaliveInterval,
		Handler:           s.config.Handler,
	}

	conn := NewConnection(transport, session, connConfig)
	if !s.registerConn(conn) {
		_ = conn.Close()
		return
	}
	defer s.unregisterConn(conn)

	connCtx, connCancel := context.WithCancel(context.Background())
	go func() {
		select {
		case <-s.closed:
			_ = conn.Close()
		case <-connCtx.Done():
		}
	}()
	defer connCancel()

	conn.Start(connCtx)
	<-conn.Done()
}

func (s *Server) performHandshake(ctx context.Context, transport *TCPTransport) (*Session, error) {
	responder, err := NewResponderHandshake(s.config.StaticKey, nil)
	if err != nil {
		return nil, err
	}

	frame1, err := transport.ReadFrame(ctx)
	if err != nil {
		return nil, err
	}
	if frame1.Header.MessageType != MessageTypeHandshakeInit {
		return nil, fmt.Errorf("%w: expected handshake init, got 0x%02x", ErrHandshakeFailed, frame1.Header.MessageType)
	}
	if err := responder.ReadFlight(frame1.Payload); err != nil {
		return nil, err
	}

	flight2Payload, err := responder.WriteFlight()
	if err != nil {
		return nil, err
	}
	frame2, err := NewFrame(MessageTypeHandshakeResponse, [16]byte{}, 0, flight2Payload, make([]byte, AEADTagSize), nil)
	if err != nil {
		return nil, err
	}
	if err := transport.WriteFrame(ctx, frame2); err != nil {
		return nil, err
	}

	frame3, err := transport.ReadFrame(ctx)
	if err != nil {
		return nil, err
	}
	if frame3.Header.MessageType != MessageTypeHandshakeResponse {
		return nil, fmt.Errorf("%w: expected handshake response, got 0x%02x", ErrHandshakeFailed, frame3.Header.MessageType)
	}
	if err := responder.ReadFlight(frame3.Payload); err != nil {
		return nil, err
	}

	if !responder.Complete() {
		return nil, ErrHandshakeFailed
	}

	result, err := responder.Result()
	if err != nil {
		return nil, err
	}

	if len(s.config.AllowedClients) > 0 {
		if !isClientAllowed(result.PeerStatic, s.config.AllowedClients) {
			return nil, ErrClientNotPermitted
		}
	}

	return NewSessionFromHandshake(s.config.CipherSuite, result)
}

func (s *Server) registerConn(conn *Connection) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inShutdown.Load() {
		return false
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *Server) unregisterConn(conn *Connection) {
	s.mu.Lock()
	delete(s.conns, conn)
	s.mu.Unlock()
}

func isClientAllowed(clientStatic [32]byte, allowedList [][]byte) bool {
	for _, allowed := range allowedList {
		if len(allowed) == 32 && hmacEqual(clientStatic[:], allowed) {
			return true
		}
	}
	return false
}

func hmacEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
