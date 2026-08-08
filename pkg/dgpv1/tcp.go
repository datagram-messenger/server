package dgpv1

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const minFrameSize = HeaderSize

// TCPTransport carries length-prefixed DGPv1 frames over a stream connection.
type TCPTransport struct {
	conn  net.Conn
	read  sync.Mutex
	write sync.Mutex
}

func NewTCPTransport(conn net.Conn) *TCPTransport {
	if conn == nil {
		panic("dgpv1: nil TCP connection")
	}
	return &TCPTransport{conn: conn}
}

func (t *TCPTransport) ReadFrame(ctx context.Context) (Frame, error) {
	t.read.Lock()
	defer t.read.Unlock()

	stop, err := t.watchContext(ctx, true)
	if err != nil {
		return Frame{}, err
	}
	defer stop()

	var prefix [4]byte
	if _, err := io.ReadFull(t.conn, prefix[:]); err != nil {
		return Frame{}, transportError(ctx, err)
	}
	n := binary.LittleEndian.Uint32(prefix[:])
	if n < minFrameSize {
		return Frame{}, fmt.Errorf("%w: got %d, want at least %d", ErrTransportFrameTooShort, n, minFrameSize)
	}
	if n > MaxFrameSize {
		return Frame{}, fmt.Errorf("%w: got %d, maximum %d", ErrTransportFrameTooLarge, n, MaxFrameSize)
	}

	wire := make([]byte, int(n))
	if _, err := io.ReadFull(t.conn, wire); err != nil {
		return Frame{}, transportError(ctx, err)
	}
	var frame Frame
	if err := frame.UnmarshalBinary(wire); err != nil {
		return Frame{}, err
	}
	return frame, nil
}

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

	packet := make([]byte, 4+len(wire))
	binary.LittleEndian.PutUint32(packet[:4], uint32(len(wire)))
	copy(packet[4:], wire)

	t.write.Lock()
	defer t.write.Unlock()
	stop, err := t.watchContext(ctx, false)
	if err != nil {
		return err
	}
	defer stop()

	for len(packet) != 0 {
		n, err := t.conn.Write(packet)
		if err != nil {
			return transportError(ctx, err)
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		packet = packet[n:]
	}
	return nil
}

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
	go func() {
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
