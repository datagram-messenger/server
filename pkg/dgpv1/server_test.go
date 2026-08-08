package dgpv1

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

func generateTestStaticKey(t *testing.T) StaticKey {
	t.Helper()
	key, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("failed to generate static key: %v", err)
	}
	return key
}

func TestServerHandshakeAndDataTransfer(t *testing.T) {
	serverKey := generateTestStaticKey(t)
	clientKey := generateTestStaticKey(t)

	clientStaticPublic := clientKey.Public()

	receivedData := make(chan []byte, 1)

	handler := MessageHandler(func(ctx context.Context, conn *Connection, msg any) error {
		if data, ok := msg.(*EncryptedData); ok {
			if len(data.Fields) > 0 {
				receivedData <- data.Fields[0].Value
			}
		}
		return nil
	})

	server, err := NewServer(ServerConfig{
		StaticKey:        serverKey,
		AllowedClients:   [][]byte{clientStaticPublic},
		CipherSuite:      CipherChaCha20Poly1305,
		HandshakeTimeout: 2 * time.Second,
		ReadTimeout:      2 * time.Second,
		WriteTimeout:     2 * time.Second,
		Handler:          handler,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- server.Serve(listener)
	}()
	defer func() {
		_ = server.Close()
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial server: %v", err)
	}
	defer clientConn.Close()

	clientTransport := NewTCPTransport(clientConn)

	initiator, err := NewInitiatorHandshake(clientKey, serverKey.Public())
	if err != nil {
		t.Fatalf("failed to create initiator handshake: %v", err)
	}

	ctx := context.Background()

	flight1, err := initiator.WriteFlight()
	if err != nil {
		t.Fatalf("failed to write flight 1: %v", err)
	}

	frame1, err := NewFrame(MessageTypeHandshakeInit, [16]byte{}, 0, flight1, make([]byte, AEADTagSize), nil)
	if err != nil {
		t.Fatalf("failed to create frame 1: %v", err)
	}
	if err := clientTransport.WriteFrame(ctx, frame1); err != nil {
		t.Fatalf("failed to send frame 1: %v", err)
	}

	frame2, err := clientTransport.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("failed to read frame 2: %v", err)
	}
	if frame2.Header.MessageType != MessageTypeHandshakeResponse {
		t.Fatalf("expected message type 0x02, got 0x%02x", frame2.Header.MessageType)
	}
	if err := initiator.ReadFlight(frame2.Payload); err != nil {
		t.Fatalf("failed to read flight 2: %v", err)
	}

	flight3, err := initiator.WriteFlight()
	if err != nil {
		t.Fatalf("failed to write flight 3: %v", err)
	}

	frame3, err := NewFrame(MessageTypeHandshakeResponse, [16]byte{}, 0, flight3, make([]byte, AEADTagSize), nil)
	if err != nil {
		t.Fatalf("failed to create frame 3: %v", err)
	}
	if err := clientTransport.WriteFrame(ctx, frame3); err != nil {
		t.Fatalf("failed to send frame 3: %v", err)
	}

	if !initiator.Complete() {
		t.Fatal("initiator handshake incomplete")
	}

	hsResult, err := initiator.Result()
	if err != nil {
		t.Fatalf("failed to get handshake result: %v", err)
	}

	clientSession, err := NewSessionFromHandshake(CipherChaCha20Poly1305, hsResult)
	if err != nil {
		t.Fatalf("failed to create client session: %v", err)
	}

	testPayload := []byte("hello server")
	tlv, err := NewTLV(1, testPayload)
	if err != nil {
		t.Fatalf("failed to create TLV: %v", err)
	}

	encryptedData := EncryptedData{
		StreamID:       1,
		AppMessageType: 10,
		Fields:         []TLV{tlv},
	}

	dataframe, err := clientSession.Send(encryptedData, 0)
	if err != nil {
		t.Fatalf("failed to encrypt data frame: %v", err)
	}

	if err := clientTransport.WriteFrame(ctx, dataframe); err != nil {
		t.Fatalf("failed to send data frame: %v", err)
	}

	select {
	case payload := <-receivedData:
		if string(payload) != string(testPayload) {
			t.Fatalf("expected %q, got %q", testPayload, payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for server to handle encrypted data")
	}

	_ = clientSession.Close()
}

func TestNewServerAdmissionDefaults(t *testing.T) {
	server, err := NewServer(ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if server.config.HandlerQueue != 16 {
		t.Fatalf("HandlerQueue = %d", server.config.HandlerQueue)
	}
	if server.config.MaxConcurrentHandshakes != 64 {
		t.Fatalf("MaxConcurrentHandshakes = %d", server.config.MaxConcurrentHandshakes)
	}
	if server.config.MaxActiveConnections != 1024 {
		t.Fatalf("MaxActiveConnections = %d", server.config.MaxActiveConnections)
	}
}

func TestNewServerRejectsNegativeAdmissionLimits(t *testing.T) {
	tests := []ServerConfig{
		{MaxConcurrentHandshakes: -1},
		{MaxActiveConnections: -1},
	}
	for _, config := range tests {
		if _, err := NewServer(config); err == nil {
			t.Fatalf("expected error for config %#v", config)
		}
	}
}

func TestServerHandshakeAdmissionSaturationAndRelease(t *testing.T) {
	server, err := NewServer(ServerConfig{MaxConcurrentHandshakes: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !server.tryAcquire(server.handshakes) {
		t.Fatal("failed to acquire first handshake slot")
	}
	if server.tryAcquire(server.handshakes) {
		t.Fatal("acquired saturated handshake slot")
	}
	server.release(server.handshakes)
	if !server.tryAcquire(server.handshakes) {
		t.Fatal("handshake slot was not released")
	}
	server.release(server.handshakes)
}

func TestServerConnectionAdmissionSaturationAndRelease(t *testing.T) {
	server, err := NewServer(ServerConfig{MaxActiveConnections: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !server.tryAcquire(server.connSlots) {
		t.Fatal("failed to acquire first connection slot")
	}
	if server.tryAcquire(server.connSlots) {
		t.Fatal("acquired saturated connection slot")
	}
	server.release(server.connSlots)
	if !server.tryAcquire(server.connSlots) {
		t.Fatal("connection slot was not released")
	}
	server.release(server.connSlots)
}

func TestServerReleasesHandshakeSlotAfterFailure(t *testing.T) {
	server, err := NewServer(ServerConfig{MaxConcurrentHandshakes: 1, HandshakeTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	serverConn, clientConn := net.Pipe()
	if !server.tryAcquire(server.handshakes) || !server.registerHandshake(serverConn) {
		t.Fatal("failed to admit handshake")
	}
	done := make(chan struct{})
	go func() {
		server.handleConn(serverConn)
		close(done)
	}()
	_ = clientConn.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("failed handshake did not finish")
	}
	if !server.tryAcquire(server.handshakes) {
		t.Fatal("failed handshake did not release slot")
	}
	server.release(server.handshakes)
}

func TestServerReleasesConnectionSlotAfterClose(t *testing.T) {
	server, err := NewServer(ServerConfig{MaxActiveConnections: 1})
	if err != nil {
		t.Fatal(err)
	}
	if !server.tryAcquire(server.connSlots) {
		t.Fatal("failed to acquire connection slot")
	}
	server.release(server.connSlots)
	if !server.tryAcquire(server.connSlots) {
		t.Fatal("closed connection did not release slot")
	}
	server.release(server.connSlots)
}

func TestServerCloseInterruptsStalledHandshake(t *testing.T) {
	server, err := NewServer(ServerConfig{HandshakeTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(listener) }()
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	deadline := time.Now().Add(time.Second)
	for {
		server.mu.Lock()
		tracked := len(server.handshakeConns)
		server.mu.Unlock()
		if tracked == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("handshake was not tracked")
		}
		time.Sleep(time.Millisecond)
	}

	closed := make(chan error, 1)
	go func() { closed <- server.Close() }()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("Close waited for HandshakeTimeout")
	}
	select {
	case err := <-serveDone:
		if !errors.Is(err, ErrServerClosed) {
			t.Fatalf("Serve error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Serve did not stop")
	}
}

func TestServerCloseIsIdempotent(t *testing.T) {
	server, err := NewServer(ServerConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNewServerRejectsNonMVPCiphers(t *testing.T) {
	for _, suite := range []CipherSuite{CipherAES256GCM, 99} {
		if _, err := NewServer(ServerConfig{CipherSuite: suite}); !errors.Is(err, ErrUnsupportedCipher) {
			t.Fatalf("suite %d error = %v", suite, err)
		}
	}
}

func TestValidateHandshakeFrame(t *testing.T) {
	valid, err := NewFrame(MessageTypeHandshakeInit, [16]byte{}, 0, make([]byte, HandshakeInitFixedSize), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Frame)
	}{
		{"message type", func(f *Frame) { f.Header.MessageType = MessageTypeHandshakeResponse }},
		{"session ID", func(f *Frame) { f.Header.SessionID[0] = 1 }},
		{"sequence", func(f *Frame) { f.Header.Sequence = 1 }},
		{"padding flag mismatch", func(f *Frame) { f.Header.Flags = FlagPadding }},
		{"payload length mismatch", func(f *Frame) { f.Header.PayloadLength++ }},
	}
	if err := validateHandshakeFrame(valid, MessageTypeHandshakeInit); err != nil {
		t.Fatalf("valid frame rejected: %v", err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frame := valid
			tt.mutate(&frame)
			if err := validateHandshakeFrame(frame, MessageTypeHandshakeInit); !errors.Is(err, ErrHandshakeFailed) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestServerDisallowedClient(t *testing.T) {
	serverKey := generateTestStaticKey(t)
	clientKey := generateTestStaticKey(t)
	allowedKey := generateTestStaticKey(t)

	allowedPublic := allowedKey.Public()

	server, err := NewServer(ServerConfig{
		StaticKey:        serverKey,
		AllowedClients:   [][]byte{allowedPublic},
		CipherSuite:      CipherChaCha20Poly1305,
		HandshakeTimeout: 1 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		_ = server.Serve(listener)
	})
	defer func() {
		_ = server.Close()
		wg.Wait()
	}()

	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientConn.Close()

	clientTransport := NewTCPTransport(clientConn)

	initiator, err := NewInitiatorHandshake(clientKey, serverKey.Public())
	if err != nil {
		t.Fatalf("failed to create initiator handshake: %v", err)
	}

	ctx := context.Background()

	flight1, _ := initiator.WriteFlight()
	frame1, _ := NewFrame(MessageTypeHandshakeInit, [16]byte{}, 0, flight1, make([]byte, AEADTagSize), nil)
	_ = clientTransport.WriteFrame(ctx, frame1)

	frame2, err := clientTransport.ReadFrame(ctx)
	if err != nil {
		t.Fatalf("server dropped connection early: %v", err)
	}
	_ = initiator.ReadFlight(frame2.Payload)

	flight3, _ := initiator.WriteFlight()
	frame3, _ := NewFrame(MessageTypeHandshakeResponse, [16]byte{}, 0, flight3, make([]byte, AEADTagSize), nil)
	_ = clientTransport.WriteFrame(ctx, frame3)

	_, err = clientTransport.ReadFrame(ctx)
	if err == nil {
		t.Fatal("expected connection to be closed by server for unauthorized client")
	}
}
