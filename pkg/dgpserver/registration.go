package dgpserver

import "github.com/datagram-messenger/protocol"

// Handle registers a typed application handler using the contract-level API.
// T must be a non-pointer ApplicationMessage; the handler receives *T.
func Handle[T ApplicationMessage](router *Router, handler TypedHandlerFunc[T]) error {
	return RegisterTyped(router, handler)
}

// HandleEncryptedData registers a typed EncryptedData handler.
func (r *Router) HandleEncryptedData(handler TypedHandlerFunc[dgpv1.EncryptedData]) error {
	return Handle(r, handler)
}

// HandleAck registers a typed Ack handler.
func (r *Router) HandleAck(handler TypedHandlerFunc[dgpv1.Ack]) error {
	return Handle(r, handler)
}

// HandleError registers a typed ErrorMessage handler.
func (r *Router) HandleError(handler TypedHandlerFunc[dgpv1.ErrorMessage]) error {
	return Handle(r, handler)
}
