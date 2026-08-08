package dgpv1

import (
	"context"
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
