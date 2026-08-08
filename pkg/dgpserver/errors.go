package dgpserver

import (
	"errors"
	"fmt"
)

var (
	// ErrServerStarted indicates that an attempted mutation happened after freeze.
	ErrServerStarted = errors.New("dgpserver: router is frozen")
	// ErrDuplicateHandler indicates that a message type already has a handler.
	ErrDuplicateHandler = errors.New("dgpserver: duplicate handler")
	// ErrNilHandler indicates that a nil handler or middleware was supplied.
	ErrNilHandler = errors.New("dgpserver: nil handler")
	// ErrUnsupportedMessage indicates a non-application-visible DGP message type.
	ErrUnsupportedMessage = errors.New("dgpserver: unsupported message")
	// ErrInvalidMessageForm indicates that Dispatch received a value instead of the documented pointer form.
	ErrInvalidMessageForm = errors.New("dgpserver: inbound messages must use pointer form")
	// ErrNotFound indicates that no handler is registered for a supported message type.
	ErrNotFound = errors.New("dgpserver: handler not found")
	// ErrHandlerPanic indicates that Dispatch recovered a handler panic.
	ErrHandlerPanic = errors.New("dgpserver: handler panic")
	// ErrRecorderFull indicates that a Recorder has reached its configured bound.
	ErrRecorderFull = errors.New("dgpserver: recorder full")
	// ErrRecorderClosed indicates that a Recorder no longer accepts messages.
	ErrRecorderClosed = errors.New("dgpserver: recorder closed")
)

// PanicError records a value recovered from a handler panic.
type PanicError struct {
	Value any
}

// Error implements error.
func (e *PanicError) Error() string { return fmt.Sprintf("%v: %v", ErrHandlerPanic, e.Value) }

// Unwrap makes PanicError match ErrHandlerPanic.
func (e *PanicError) Unwrap() error { return ErrHandlerPanic }
