package dgpserver

import (
	"context"
	"crypto/subtle"
	"errors"
)

// ErrUnauthenticated indicates that an authenticated Noise peer was rejected
// by application admission policy.
var ErrUnauthenticated = errors.New("dgpserver: unauthenticated")

// Credentials contains the authenticated peer identity presented to an Authenticator.
type Credentials struct {
	PeerStatic [32]byte
	SessionID  [16]byte
	RemoteAddr string
}

// Principal is the application identity returned by an Authenticator.
type Principal any

// Authenticator maps cryptographically authenticated credentials to a principal.
type Authenticator interface {
	Authenticate(context.Context, Credentials) (Principal, error)
}

// AuthenticatorFunc adapts a function to Authenticator.
type AuthenticatorFunc func(context.Context, Credentials) (Principal, error)

// Authenticate calls f.
func (f AuthenticatorFunc) Authenticate(ctx context.Context, credentials Credentials) (Principal, error) {
	return f(ctx, credentials)
}

// StaticKeyAllowlist authenticates peers by Noise static public key. Values are
// copied on construction and compared in constant time.
type StaticKeyAllowlist struct{ entries map[[32]byte]Principal }

// NewStaticKeyAllowlist constructs an allowlist from static keys and principals.
func NewStaticKeyAllowlist(entries map[[32]byte]Principal) *StaticKeyAllowlist {
	copyEntries := make(map[[32]byte]Principal, len(entries))
	for key, principal := range entries {
		copyEntries[key] = principal
	}
	return &StaticKeyAllowlist{entries: copyEntries}
}

// Authenticate returns the mapped principal or ErrUnauthenticated.
func (a *StaticKeyAllowlist) Authenticate(_ context.Context, credentials Credentials) (Principal, error) {
	if a == nil {
		return nil, ErrUnauthenticated
	}
	for key, principal := range a.entries {
		if subtle.ConstantTimeCompare(key[:], credentials.PeerStatic[:]) == 1 {
			return principal, nil
		}
	}
	return nil, ErrUnauthenticated
}
