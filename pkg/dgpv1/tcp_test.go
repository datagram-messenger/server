package dgpv1

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

func testTransportFrame(t *testing.T, sequence uint64, payload []byte) Frame {
	t.Helper()
	f, err := NewFrame(MessageTypeEncryptedData, [16]byte{1}, sequence, payload, make([]byte, AEADTagSize), nil)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func framedBytes(t *testing.T, f Frame) []byte {
	t.Helper()
	b, err := f.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTCPTransportFragmentedAndCoalescedReads(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tr := NewTCPTransport(client)
	first := testTransportFrame(t, 1, []byte("one"))
	second := testTransportFrame(t, 2, []byte("two"))
	wire := append(framedBytes(t, first), framedBytes(t, second)...)
	go func() {
		for _, b := range wire {
			_, _ = server.Write([]byte{b})
		}
	}()
	for _, want := range []Frame{first, second} {
		got, err := tr.ReadFrame(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("got %+v, want %+v", got, want)
		}
	}
}

type shortConn struct {
	net.Conn
	max int
}

func (c shortConn) Write(p []byte) (int, error) {
	if len(p) > c.max {
		p = p[:c.max]
	}
	return c.Conn.Write(p)
}

func TestTCPTransportPartialWritesUseCanonicalWireFormat(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	writer := NewTCPTransport(shortConn{Conn: a, max: 3})
	want := testTransportFrame(t, 7, bytes.Repeat([]byte{9}, 100))
	wantWire := framedBytes(t, want)
	errCh := make(chan error, 1)
	go func() { errCh <- writer.WriteFrame(context.Background(), want) }()

	gotWire := make([]byte, len(wantWire))
	if _, err := io.ReadFull(b, gotWire); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotWire, wantWire) {
		t.Fatal("wire frame mismatch")
	}
	if !bytes.Equal(gotWire[:4], Magic[:]) {
		t.Fatalf("first four bytes = %q, want DGP1 magic", gotWire[:4])
	}
}

func TestTCPTransportRejectsOversizedHeaderBeforeBody(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	wire := make([]byte, HeaderSize)
	copy(wire[:4], Magic[:])
	wire[4] = Version
	wire[6] = byte(MessageTypeEncryptedData)
	binary.LittleEndian.PutUint32(wire[32:36], MaxFrameSize)
	go func() { _, _ = b.Write(wire) }()
	_, err := NewTCPTransport(a).ReadFrame(context.Background())
	if !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("error = %v, want %v", err, ErrFrameTooLarge)
	}
}

func TestTCPTransportEOFAndMalformedFrame(t *testing.T) {
	t.Run("EOF", func(t *testing.T) {
		a, b := net.Pipe()
		b.Close()
		defer a.Close()
		_, err := NewTCPTransport(a).ReadFrame(context.Background())
		if !errors.Is(err, io.EOF) {
			t.Fatalf("error = %v, want EOF", err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		a, b := net.Pipe()
		defer a.Close()
		defer b.Close()
		wire := make([]byte, minFrameSize)
		copy(wire, []byte("BAD!"))
		go func() { _, _ = b.Write(wire) }()
		_, err := NewTCPTransport(a).ReadFrame(context.Background())
		if !errors.Is(err, ErrInvalidMagic) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidMagic)
		}
	})
}

func TestTCPTransportTruncatedFrame(t *testing.T) {
	a, b := net.Pipe()
	want := testTransportFrame(t, 9, []byte("truncated"))
	wire := framedBytes(t, want)
	go func() {
		_, _ = b.Write(wire[:len(wire)-1])
		_ = b.Close()
	}()
	defer a.Close()
	_, err := NewTCPTransport(a).ReadFrame(context.Background())
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("error = %v, want %v", err, io.ErrUnexpectedEOF)
	}
}

func TestTCPTransportConcurrentWritesSerialized(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	tr := NewTCPTransport(shortConn{Conn: a, max: 1})
	reader := NewTCPTransport(b)
	const count = 12
	var wg sync.WaitGroup
	errCh := make(chan error, count)
	for i := range count {
		wg.Go(func() {
			errCh <- tr.WriteFrame(context.Background(), testTransportFrame(t, uint64(i), bytes.Repeat([]byte{byte(i)}, 32)))
		})
	}
	seen := make(map[uint64]bool)
	for range count {
		f, err := reader.ReadFrame(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		seen[f.Header.Sequence] = true
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(seen) != count {
		t.Fatalf("read %d distinct frames, want %d", len(seen), count)
	}
}

func TestTCPTransportContextCancellation(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := NewTCPTransport(a).ReadFrame(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error = %v", err)
	}
}

func TestTCPTransportCompletedOperationDoesNotLeakCancellationDeadline(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	transport := NewTCPTransport(a)
	first := testTransportFrame(t, 1, []byte("first"))
	second := testTransportFrame(t, 2, []byte("second"))

	ctx, cancel := context.WithCancel(context.Background())
	firstWrite := make(chan error, 1)
	go func() { firstWrite <- transport.WriteFrame(ctx, first) }()
	if _, err := io.ReadFull(b, make([]byte, len(framedBytes(t, first)))); err != nil {
		t.Fatal(err)
	}
	if err := <-firstWrite; err != nil {
		t.Fatal(err)
	}
	cancel()

	secondWrite := make(chan error, 1)
	go func() { secondWrite <- transport.WriteFrame(context.Background(), second) }()
	if _, err := io.ReadFull(b, make([]byte, len(framedBytes(t, second)))); err != nil {
		t.Fatalf("second write was poisoned by stale deadline: %v", err)
	}
	if err := <-secondWrite; err != nil {
		t.Fatalf("second write was poisoned by stale deadline: %v", err)
	}
}
