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
	out := make([]byte, 4+len(b))
	binary.LittleEndian.PutUint32(out, uint32(len(b)))
	copy(out[4:], b)
	return out
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

func TestTCPTransportPartialWritesAndRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	writer := NewTCPTransport(shortConn{Conn: a, max: 3})
	reader := NewTCPTransport(b)
	want := testTransportFrame(t, 7, bytes.Repeat([]byte{9}, 100))
	errCh := make(chan error, 1)
	go func() { errCh <- writer.WriteFrame(context.Background(), want) }()
	got, err := reader.ReadFrame(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("round trip mismatch")
	}
}

func TestTCPTransportPrefixErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		n    uint32
		want error
	}{
		{"undersized", minFrameSize - 1, ErrTransportFrameTooShort},
		{"oversized", MaxFrameSize + 1, ErrTransportFrameTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			go func() { var p [4]byte; binary.LittleEndian.PutUint32(p[:], tc.n); _, _ = b.Write(p[:]) }()
			_, err := NewTCPTransport(a).ReadFrame(context.Background())
			if !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
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
		go func() {
			var p [4]byte
			binary.LittleEndian.PutUint32(p[:], uint32(len(wire)))
			_, _ = b.Write(append(p[:], wire...))
		}()
		_, err := NewTCPTransport(a).ReadFrame(context.Background())
		if !errors.Is(err, ErrInvalidMagic) {
			t.Fatalf("error = %v, want %v", err, ErrInvalidMagic)
		}
	})
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
	for i := 0; i < count; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errCh <- tr.WriteFrame(context.Background(), testTransportFrame(t, uint64(i), bytes.Repeat([]byte{byte(i)}, 32)))
		}(i)
	}
	seen := make(map[uint64]bool)
	for i := 0; i < count; i++ {
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
