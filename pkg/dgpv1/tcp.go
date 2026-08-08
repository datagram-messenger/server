package dgpv1

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const minFrameSize = HeaderSize

// TCPTransport carries canonical DGPv1 frames directly over a TCP stream.
// Frames have no transport length prefix. One read and one write may proceed
// concurrently; reads are serialized with reads and writes with writes.
type TCPTransport struct {
	conn  net.Conn
	read  sync.Mutex
	write sync.Mutex
}

// NewTCPTransport wraps conn and panics if conn is nil.
func NewTCPTransport(conn net.Conn) *TCPTransport {
	if conn == nil {
		panic("dgpv1: nil TCP connection")
	}
	return &TCPTransport{conn: conn}
}

// ReadFrame blocks until one complete frame is read or ctx is canceled.
// It derives the body length from the fixed DGPv1 header, not a length prefix.
func (t *TCPTransport) ReadFrame(ctx context.Context) (Frame, error) {
	t.read.Lock()
	defer t.read.Unlock()

	stop, err := t.watchContext(ctx, true)
	if err != nil {
		return Frame{}, err
	}
	defer stop()

	headerWire := make([]byte, HeaderSize)
	if _, err := io.ReadFull(t.conn, headerWire); err != nil {
		return Frame{}, transportError(ctx, err)
	}

	var header Header
	if err := header.UnmarshalBinary(headerWire); err != nil {
		return Frame{}, err
	}
	frameSize := header.FrameSize()
	if frameSize < minFrameSize {
		return Frame{}, fmt.Errorf("%w: got %d, want at least %d", ErrTransportFrameTooShort, frameSize, minFrameSize)
	}
	if frameSize > MaxFrameSize {
		return Frame{}, fmt.Errorf("%w: got %d, maximum %d", ErrTransportFrameTooLarge, frameSize, MaxFrameSize)
	}

	wire := make([]byte, int(frameSize))
	copy(wire, headerWire)
	if _, err := io.ReadFull(t.conn, wire[HeaderSize:]); err != nil {
		return Frame{}, transportError(ctx, err)
	}
	var frame Frame
	if err := frame.UnmarshalBinary(wire); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

// WriteFrame validates and writes one complete frame, blocking until all bytes
// are written or ctx is canceled.
func (t *TCPTransport) WriteFrame(ctx context.Context, frame Frame) error {
	wire, err := frame.MarshalBinary()
	if err != nil {
		return err
	}
	if len(wire) < minFrameSize {
		return fmt.Errorf("%w: got %d, want at least %d", ErrTransportFrameTooShort, len(wire), minFrameSize)
	}
	if len(wire) > MaxFrameSize {
		return fmt.Errorf("%w: got %d, maximum %d", ErrTransportFrameTooLarge, len(wire), MaxFrameSize)
	}

	t.write.Lock()
	defer t.write.Unlock()
	stop, err := t.watchContext(ctx, false)
	if err != nil {
		return err
	}
	defer stop()

	for len(wire) != 0 {
		n, err := t.conn.Write(wire)
		if err != nil {
			return transportError(ctx, err)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		wire = wire[n:]
	}
	return nil
}

// Close closes the underlying connection.
func (t *TCPTransport) Close() error {
	if err := t.conn.Close(); err != nil {
		if errors.Is(err, net.ErrClosed) {
			return ErrTransportClosed
		}
		return err
	}
	return nil
}

func (t *TCPTransport) watchContext(ctx context.Context, read bool) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	exited := make(chan struct{})
	go func() {
		defer close(exited)
		select {
		case <-ctx.Done():
			if read {
				_ = t.conn.SetReadDeadline(time.Now())
			} else {
				_ = t.conn.SetWriteDeadline(time.Now())
			}
		case <-done:
		}
	}()
	return func() {
		close(done)
		// Wait for a concurrently selected cancellation branch before clearing
		// its deadline. Otherwise it can poison the next serialized operation.
		<-exited
		if read {
			_ = t.conn.SetReadDeadline(time.Time{})
		} else {
			_ = t.conn.SetWriteDeadline(time.Time{})
		}
	}, nil
}

func transportError(ctx context.Context, err error) error {
	if ctxErr := ctx.Err(); ctxErr != nil {
		return ctxErr
	}
	if errors.Is(err, net.ErrClosed) {
		return ErrTransportClosed
	}
	return err
}
