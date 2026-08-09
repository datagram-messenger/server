package dgpserver

import (
	"context"
	"time"

	"github.com/tr1xdev/datagram-server/pkg/dgpv1"
)

// Peer is an immutable snapshot of the authenticated remote peer.
type Peer struct {
	address   string
	sessionID [16]byte
	identity  []byte
}

// NewPeer creates a peer snapshot and copies identity.
func NewPeer(address string, sessionID [16]byte, identity []byte) Peer {
	return Peer{address: address, sessionID: sessionID, identity: append([]byte(nil), identity...)}
}

// Address returns the peer's transport address.
func (p Peer) Address() string { return p.address }

// SessionID returns the peer's DGP session identifier.
func (p Peer) SessionID() [16]byte { return p.sessionID }

// Identity returns a defensive copy of authenticated identity bytes.
func (p Peer) Identity() []byte { return append([]byte(nil), p.identity...) }

// Metadata is immutable per-message dispatch metadata.
type Metadata struct {
	messageType dgpv1.MessageType
	receivedAt  time.Time
}

// NewMetadata constructs per-message metadata.
func NewMetadata(messageType dgpv1.MessageType, receivedAt time.Time) Metadata {
	return Metadata{messageType: messageType, receivedAt: receivedAt}
}

// MessageType returns the exact DGP message type.
func (m Metadata) MessageType() dgpv1.MessageType { return m.messageType }

// ReceivedAt returns the message arrival time.
func (m Metadata) ReceivedAt() time.Time { return m.receivedAt }

// Params is an immutable snapshot of routing parameters.
type Params struct{ values map[string]string }

// NewParams copies values into a parameter snapshot.
func NewParams(values map[string]string) Params {
	p := Params{values: make(map[string]string, len(values))}
	for key, value := range values {
		p.values[key] = value
	}
	return p
}

// Get returns a parameter and whether it exists.
func (p Params) Get(key string) (string, bool) { value, ok := p.values[key]; return value, ok }

// All returns a defensive copy of all parameters.
func (p Params) All() map[string]string {
	out := make(map[string]string, len(p.values))
	for key, value := range p.values {
		out[key] = value
	}
	return out
}

type sendCapability interface {
	trySend(any) error
	send(context.Context, any, bool) error
	close() error
}

// Context carries cancellation, immutable request snapshots, and narrow send capabilities.
// It intentionally is not a general-purpose state bag and does not expose dgpv1.Connection.
type Context struct {
	context.Context
	peer      Peer
	principal Principal
	metadata  Metadata
	params    Params
	sender    sendCapability
}

// NewContext creates a receive-only handler context.
func NewContext(ctx context.Context, peer Peer, metadata Metadata, params Params) *Context {
	return newContext(ctx, peer, metadata, params, nil)
}

func newContext(ctx context.Context, peer Peer, metadata Metadata, params Params, sender sendCapability) *Context {
	return newContextWithPrincipal(ctx, peer, nil, metadata, params, sender)
}

func newContextWithPrincipal(ctx context.Context, peer Peer, principal Principal, metadata Metadata, params Params, sender sendCapability) *Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return &Context{Context: ctx, peer: NewPeer(peer.address, peer.sessionID, peer.identity), principal: principal, metadata: metadata, params: NewParams(params.values), sender: sender}
}

// Principal returns the identity produced by the configured Authenticator.
func (c *Context) Principal() Principal { return c.principal }

// Peer returns the immutable peer snapshot.
func (c *Context) Peer() Peer { return NewPeer(c.peer.address, c.peer.sessionID, c.peer.identity) }

// Metadata returns immutable dispatch metadata.
func (c *Context) Metadata() Metadata { return c.metadata }

// Params returns an immutable routing-parameter snapshot.
func (c *Context) Params() Params { return NewParams(c.params.values) }

// TrySend attempts a nonblocking send.
func (c *Context) TrySend(message any) error {
	if c.sender == nil {
		return ErrRecorderClosed
	}
	return c.sender.trySend(message)
}

// Send waits for capacity or context cancellation.
func (c *Context) Send(message any) error {
	if c.sender == nil {
		return ErrRecorderClosed
	}
	return c.sender.send(c.Context, message, false)
}

// SendAndWait sends and waits for completion by the configured capability.
func (c *Context) SendAndWait(message any) error {
	if c.sender == nil {
		return ErrRecorderClosed
	}
	return c.sender.send(c.Context, message, true)
}

// Close closes the configured send capability.
func (c *Context) Close() error {
	if c.sender == nil {
		return ErrRecorderClosed
	}
	return c.sender.close()
}
