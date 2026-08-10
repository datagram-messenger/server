package dgpv1

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
)

func TestSendContextFullQueueCancellationAndFIFOAdmission(t *testing.T) {
	local, peer := net.Pipe()
	defer peer.Close()
	session, _ := testSessions(t)
	connection := NewConnection(NewTCPTransport(local), session, ConnectionConfig{OutboundQueue: 1})
	defer connection.Close()
	if err := connection.Send(PingPong{Nonce: 1}); err != nil {
		t.Fatal(err)
	}

	pre, cancelPre := context.WithCancel(context.Background())
	cancelPre()
	if err := connection.SendContext(pre, PingPong{Nonce: 2}); !errors.Is(err, context.Canceled) {
		t.Fatalf("pre-cancel = %v", err)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	second := make(chan error, 1)
	go func() { second <- connection.SendContext(ctx2, PingPong{Nonce: 2}) }()
	select {
	case err := <-second:
		t.Fatalf("send returned before capacity: %v", err)
	default:
	}
	cancel2()
	if err := <-second; !errors.Is(err, context.Canceled) {
		t.Fatalf("mid-cancel = %v", err)
	}

	third := make(chan error, 1)
	go func() { third <- connection.SendContext(context.Background(), PingPong{Nonce: 3}) }()
	select {
	case err := <-third:
		t.Fatalf("third returned before capacity: %v", err)
	default:
	}
	first := <-connection.outbound
	if first.message.(PingPong).Nonce != 1 {
		t.Fatal("first item reordered")
	}
	if err := <-third; err != nil {
		t.Fatal(err)
	}
	last := <-connection.outbound
	if last.message.(PingPong).Nonce != 3 {
		t.Fatal("FIFO admission violated")
	}
}

func TestSendAndWaitCompletesAfterWriteAndPropagatesFailure(t *testing.T) {
	connection, peerSession, peerTransport, cleanup := testConnectionPair(t, ConnectionConfig{OutboundQueue: 1})
	defer cleanup()
	connection.Start(context.Background())
	result := make(chan error, 1)
	go func() { result <- connection.SendAndWait(context.Background(), Ack{Sequences: []uint64{7}}) }()
	select {
	case err := <-result:
		t.Fatalf("completed before peer read: %v", err)
	default:
	}
	message := readConnectionMessage(t, peerTransport, peerSession)
	if got := message.(*Ack).Sequences; !reflect.DeepEqual(got, []uint64{7}) {
		t.Fatalf("ack = %v", got)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}

	failed, _, failedPeer, failedCleanup := testConnectionPair(t, ConnectionConfig{OutboundQueue: 1})
	defer failedCleanup()
	failed.Start(context.Background())
	_ = failedPeer.Close()
	if err := failed.SendAndWait(context.Background(), Ack{Sequences: []uint64{8}}); err == nil {
		t.Fatal("write failure was lost")
	}
	waitConnection(t, failed)
}

func TestSendAndWaitCloseRaceCompletesWithoutLeak(t *testing.T) {
	connection, _, peerTransport, cleanup := testConnectionPair(t, ConnectionConfig{OutboundQueue: 8})
	defer cleanup()
	connection.Start(context.Background())
	results := make(chan error, 8)
	for i := range cap(results) {
		go func(n int) {
			results <- connection.SendAndWait(context.Background(), Ack{Sequences: []uint64{uint64(n + 1)}})
		}(i)
	}
	_ = peerTransport.Close()
	deadline := time.After(connectionTestTimeout)
	for range cap(results) {
		select {
		case <-results:
		case <-deadline:
			t.Fatal("completion leaked during close race")
		}
	}
	waitConnection(t, connection)
}

func TestCompleteSignalsExactlyOnce(t *testing.T) {
	completion := make(chan error, 2)
	item := queuedMessage{completion: completion}
	complete(item, ioTestError{})
	if err := <-completion; err == nil {
		t.Fatal("completion error missing")
	}
	select {
	case <-completion:
		t.Fatal("completion signaled twice")
	default:
	}
}

type ioTestError struct{}

func (ioTestError) Error() string { return "write failed" }
