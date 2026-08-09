package dgpserver

import (
	"context"
	"time"
)

// Dispatch invokes handler for one application-visible inbound message without
// starting a server or creating network or cryptographic state. The Context
// contains immutable peer, principal, and message metadata snapshots and has no
// send capability. Panics are converted to PanicError using the same policy as
// Router.Dispatch.
func Dispatch(ctx context.Context, handler Handler, peer Peer, principal Principal, message any) (err error) {
	if nilInterface(handler) {
		return ErrNilHandler
	}
	messageType, err := inboundType(message)
	if err != nil {
		return err
	}
	handlerContext := newContextWithPrincipal(
		ctx,
		peer,
		principal,
		NewMetadata(messageType, time.Now()),
		Params{},
		nil,
	)
	defer func() {
		if value := recover(); value != nil {
			err = &PanicError{Value: value}
		}
	}()
	return handler.Handle(handlerContext, message)
}
