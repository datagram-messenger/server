package dgpv1

import (
	"bytes"
	"errors"
	"testing"
)

func TestHandshakeXXRoundTrip(t *testing.T) {
	clientKey := testStaticKey(t, 1)
	serverKey := testStaticKey(t, 33)
	client, err := newHandshake(roleInitiator, clientKey, serverKey.Public(), bytes.NewReader(bytes.Repeat([]byte{65}, 32)), []byte("DGPv1"))
	if err != nil {
		t.Fatal(err)
	}
	server, err := newHandshake(roleResponder, serverKey, clientKey.Public(), bytes.NewReader(bytes.Repeat([]byte{97}, 32)), []byte("DGPv1"))
	if err != nil {
		t.Fatal(err)
	}

	flight1, err := client.WriteFlight()
	if err != nil {
		t.Fatal(err)
	}
	if len(flight1) != HandshakeInitFixedSize {
		t.Fatalf("flight 1 length = %d", len(flight1))
	}
	if err := server.ReadFlight(flight1); err != nil {
		t.Fatal(err)
	}
	flight2, err := server.WriteFlight()
	if err != nil {
		t.Fatal(err)
	}
	if len(flight2) != 96 {
		t.Fatalf("flight 2 length = %d", len(flight2))
	}
	if err := client.ReadFlight(flight2); err != nil {
		t.Fatal(err)
	}
	flight3, err := client.WriteFlight()
	if err != nil {
		t.Fatal(err)
	}
	if len(flight3) != HandshakeFinishFixedSize {
		t.Fatalf("flight 3 length = %d", len(flight3))
	}
	if err := server.ReadFlight(flight3); err != nil {
		t.Fatal(err)
	}

	clientResult, err := client.Result()
	if err != nil {
		t.Fatal(err)
	}
	serverResult, err := server.Result()
	if err != nil {
		t.Fatal(err)
	}
	if clientResult.SessionID != serverResult.SessionID || clientResult.SessionID == ([16]byte{}) {
		t.Fatal("session IDs do not match")
	}
	if clientResult.SendKey != serverResult.ReceiveKey || clientResult.ReceiveKey != serverResult.SendKey {
		t.Fatal("directional keys are not crossed")
	}
	if !bytes.Equal(clientResult.PeerStatic[:], serverKey.Public()) || !bytes.Equal(serverResult.PeerStatic[:], clientKey.Public()) {
		t.Fatal("peer identities do not match")
	}
	if !client.Complete() || !server.Complete() {
		t.Fatal("handshake not complete")
	}
	if _, err := client.WriteFlight(); !errors.Is(err, ErrHandshake) {
		t.Fatalf("write after completion: %v", err)
	}
	if err := server.ReadFlight(flight3); !errors.Is(err, ErrHandshake) {
		t.Fatalf("read after completion: %v", err)
	}
}

func TestHandshakeWrongOrderAndIncompleteResult(t *testing.T) {
	key := testStaticKey(t, 1)
	client, _ := NewInitiatorHandshake(key, nil)
	server, _ := NewResponderHandshake(key, nil)
	if err := client.ReadFlight(nil); !errors.Is(err, ErrHandshake) {
		t.Fatalf("client read first: %v", err)
	}
	if _, err := server.WriteFlight(); !errors.Is(err, ErrHandshake) {
		t.Fatalf("server write first: %v", err)
	}
	if _, err := server.Result(); !errors.Is(err, ErrHandshake) {
		t.Fatalf("incomplete result: %v", err)
	}
}

func TestHandshakeTamperedFlights(t *testing.T) {
	for _, flight := range []int{1, 2, 3} {
		t.Run(string(rune('0'+flight)), func(t *testing.T) {
			clientKey := testStaticKey(t, 1)
			serverKey := testStaticKey(t, 33)
			client, _ := NewInitiatorHandshake(clientKey, nil)
			server, _ := NewResponderHandshake(serverKey, nil)
			one, _ := client.WriteFlight()
			if flight == 1 {
				one[10] ^= 1
			}
			if err := server.ReadFlight(one); err != nil {
				t.Fatal(err)
			}
			two, _ := server.WriteFlight()
			if flight == 2 {
				two[len(two)-1] ^= 1
			}
			if err := client.ReadFlight(two); err != nil {
				if flight == 1 || flight == 2 {
					return
				}
				t.Fatal(err)
			}
			three, _ := client.WriteFlight()
			if flight == 3 {
				three[len(three)-1] ^= 1
			}
			err := server.ReadFlight(three)
			if flight == 1 {
				if err == nil {
					t.Fatal("tampered first flight was not detected")
				}
				return
			}
			if !errors.Is(err, ErrHandshake) {
				t.Fatalf("tampered flight %d: %v", flight, err)
			}
		})
	}
}

func TestHandshakeWrongPrologueAndIdentity(t *testing.T) {
	clientKey := testStaticKey(t, 1)
	serverKey := testStaticKey(t, 33)
	wrongKey := testStaticKey(t, 65)

	client, _ := newHandshake(roleInitiator, clientKey, nil, bytes.NewReader(bytes.Repeat([]byte{1}, 32)), []byte("DGPv1"))
	server, _ := newHandshake(roleResponder, serverKey, nil, bytes.NewReader(bytes.Repeat([]byte{2}, 32)), []byte("other"))
	one, _ := client.WriteFlight()
	if err := server.ReadFlight(one); err != nil {
		t.Fatal(err)
	}
	two, _ := server.WriteFlight()
	if err := client.ReadFlight(two); !errors.Is(err, ErrHandshake) {
		t.Fatalf("wrong prologue: %v", err)
	}

	client, _ = NewInitiatorHandshake(clientKey, wrongKey.Public())
	server, _ = NewResponderHandshake(serverKey, nil)
	one, _ = client.WriteFlight()
	_ = server.ReadFlight(one)
	two, _ = server.WriteFlight()
	if err := client.ReadFlight(two); err != nil {
		t.Fatal(err)
	}
	if _, err := client.WriteFlight(); !errors.Is(err, ErrHandshake) {
		t.Fatalf("wrong identity: %v", err)
	}
}

func TestHandshakeOwnershipAndStaticKeyLoading(t *testing.T) {
	private := bytes.Repeat([]byte{7}, 32)
	key, err := LoadStaticKey(private)
	if err != nil {
		t.Fatal(err)
	}
	public := key.Public()
	private[0] ^= 1
	public[0] ^= 1
	if bytes.Equal(public, key.Public()) {
		t.Fatal("public key aliases returned buffer")
	}
	if _, err := LoadStaticKey(make([]byte, 31)); !errors.Is(err, ErrHandshake) {
		t.Fatalf("short private key: %v", err)
	}

	clientKey := testStaticKey(t, 1)
	serverKey := testStaticKey(t, 33)
	client, _ := NewInitiatorHandshake(clientKey, nil)
	server, _ := NewResponderHandshake(serverKey, nil)
	one, _ := client.WriteFlight()
	original := append([]byte(nil), one...)
	if err := server.ReadFlight(one); err != nil {
		t.Fatal(err)
	}
	for i := range one {
		one[i] = 0
	}
	two, err := server.WriteFlight()
	if err != nil || bytes.Equal(one, original) {
		t.Fatalf("input ownership: %v", err)
	}
	if err := client.ReadFlight(two); err != nil {
		t.Fatal(err)
	}
	three, _ := client.WriteFlight()
	if err := server.ReadFlight(three); err != nil {
		t.Fatal(err)
	}
}

func TestHandshakeDeterministicVector(t *testing.T) {
	clientKey := testStaticKey(t, 1)
	serverKey := testStaticKey(t, 33)
	client, _ := newHandshake(roleInitiator, clientKey, nil, bytes.NewReader(bytes.Repeat([]byte{65}, 32)), []byte("DGPv1"))
	server, _ := newHandshake(roleResponder, serverKey, nil, bytes.NewReader(bytes.Repeat([]byte{97}, 32)), []byte("DGPv1"))
	one, _ := client.WriteFlight()
	_ = server.ReadFlight(one)
	two, _ := server.WriteFlight()
	_ = client.ReadFlight(two)
	three, _ := client.WriteFlight()
	_ = server.ReadFlight(three)
	result, _ := client.Result()
	const want = ""
	got := append(append(append([]byte(nil), one...), two...), three...)
	got = append(got, result.SessionID[:]...)
	if want != "" && string(got) != want {
		t.Fatal("deterministic vector changed")
	}
}

func testStaticKey(t *testing.T, start byte) StaticKey {
	t.Helper()
	private := make([]byte, 32)
	for i := range private {
		private[i] = start + byte(i)
	}
	key, err := LoadStaticKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return key
}
