package dgpserver

import (
	"context"
	"sync"
	"time"

	"github.com/datagram-messenger/dgproto-go"
)

// RecordedSend is one defensively copied send accepted by Recorder.
type RecordedSend struct {
	Message any
	Wait    bool
	At      time.Time
}

// Recorder is a bounded, thread-safe in-memory send capability for tests.
type Recorder struct {
	mu      sync.Mutex
	items   []RecordedSend
	slots   chan struct{}
	closed  chan struct{}
	closeMu sync.Once
}

// NewRecorder creates a recorder with capacity. Capacity must be positive.
func NewRecorder(capacity int) *Recorder {
	if capacity <= 0 {
		panic("dgpserver: recorder capacity must be positive")
	}
	return &Recorder{items: make([]RecordedSend, 0, capacity), slots: make(chan struct{}, capacity), closed: make(chan struct{})}
}

// NewContext creates a handler context backed by r.
func (r *Recorder) NewContext(ctx context.Context, peer Peer, metadata Metadata, params Params) *Context {
	return newContext(ctx, peer, metadata, params, r)
}

// TrySend records a message without blocking.
func (r *Recorder) TrySend(message any) error { return r.trySendWithWait(message, false) }

// Send waits for recorder capacity or ctx cancellation.
func (r *Recorder) Send(ctx context.Context, message any) error { return r.send(ctx, message, false) }

// SendAndWait records a completed send, waiting for capacity or cancellation.
func (r *Recorder) SendAndWait(ctx context.Context, message any) error {
	return r.send(ctx, message, true)
}

// Close stops the recorder and wakes blocked senders.
func (r *Recorder) Close() error { return r.close() }

// Snapshot returns defensive copies without releasing capacity.
func (r *Recorder) Snapshot() []RecordedSend {
	r.mu.Lock()
	defer r.mu.Unlock()
	return cloneRecorded(r.items)
}

// Drain returns all recorded sends and releases their capacity.
func (r *Recorder) Drain() []RecordedSend {
	r.mu.Lock()
	defer r.mu.Unlock()
	items := cloneRecorded(r.items)
	for range len(r.items) {
		<-r.slots
	}
	r.items = r.items[:0]
	return items
}

// Len returns the number of retained sends.
func (r *Recorder) Len() int { r.mu.Lock(); defer r.mu.Unlock(); return len(r.items) }

func (r *Recorder) trySend(message any) error { return r.trySendWithWait(message, false) }

func (r *Recorder) trySendWithWait(message any, wait bool) error {
	select {
	case <-r.closed:
		return ErrRecorderClosed
	default:
	}
	select {
	case r.slots <- struct{}{}:
	default:
		return ErrRecorderFull
	}
	return r.append(message, wait)
}

func (r *Recorder) send(ctx context.Context, message any, wait bool) error {
	if ctx == nil {
		ctx = context.Background()
	}
	select {
	case <-r.closed:
		return ErrRecorderClosed
	case <-ctx.Done():
		return ctx.Err()
	case r.slots <- struct{}{}:
	}
	return r.append(message, wait)
}

func (r *Recorder) append(message any, wait bool) error {
	select {
	case <-r.closed:
		<-r.slots
		return ErrRecorderClosed
	default:
	}
	r.mu.Lock()
	r.items = append(r.items, RecordedSend{Message: cloneMessage(message), Wait: wait, At: time.Now()})
	r.mu.Unlock()
	return nil
}

func (r *Recorder) close() error { r.closeMu.Do(func() { close(r.closed) }); return nil }

func cloneRecorded(items []RecordedSend) []RecordedSend {
	out := make([]RecordedSend, len(items))
	for index, item := range items {
		out[index] = item
		out[index].Message = cloneMessage(item.Message)
	}
	return out
}

func cloneMessage(message any) any {
	switch value := message.(type) {
	case dgproto.EncryptedData:
		copy := cloneEncrypted(value)
		return copy
	case *dgproto.EncryptedData:
		if value == nil {
			return (*dgproto.EncryptedData)(nil)
		}
		copy := cloneEncrypted(*value)
		return &copy
	case dgproto.Ack:
		return dgproto.Ack{Sequences: append([]uint64(nil), value.Sequences...)}
	case *dgproto.Ack:
		if value == nil {
			return (*dgproto.Ack)(nil)
		}
		return &dgproto.Ack{Sequences: append([]uint64(nil), value.Sequences...)}
	default:
		return message
	}
}

func cloneEncrypted(value dgproto.EncryptedData) dgproto.EncryptedData {
	out := value
	out.Fields = make([]dgproto.TLV, len(value.Fields))
	for index, field := range value.Fields {
		out.Fields[index] = dgproto.TLV{Type: field.Type, Value: append([]byte(nil), field.Value...)}
	}
	return out
}
