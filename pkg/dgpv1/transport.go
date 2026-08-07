package dgpv1

import (
	"context"
	"errors"
)

var (
	ErrTransportFrameTooShort = errors.New("dgpv1: transport frame too short")
	ErrTransportFrameTooLarge = errors.New("dgpv1: transport frame too large")
	ErrTransportClosed        = errors.New("dgpv1: transport closed")
)

// FrameReader reads one complete DGPv1 frame.
type FrameReader interface {
	ReadFrame(context.Context) (Frame, error)
}

// FrameWriter writes one complete DGPv1 frame.
type FrameWriter interface {
	WriteFrame(context.Context, Frame) error
}

// Transport reads, writes, and closes a framed connection.
type Transport interface {
	FrameReader
	FrameWriter
	Close() error
}
