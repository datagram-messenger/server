// Package dgpserver provides the high-level, application-facing server layer
// for authenticated DGPv1 messages.
//
// The package deliberately exposes only EncryptedData, Ack, and ErrorMessage to
// handlers. Inbound messages use pointer form, matching dgpv1.Session.Receive.
// A zero Router is ready for registration and freezes before serving or on its
// first dispatch. CommandRouter provides codec-neutral routing within
// EncryptedData, while Middleware composes application policy around handlers.
//
// Server combines routing with post-Noise authentication, principals, lifecycle
// hooks, bounded sending, and graceful shutdown. Context exposes immutable peer
// and message snapshots plus narrow send capabilities; it does not expose the
// underlying connection or cryptographic state. Dispatch and Recorder support
// unit tests without TCP or Noise.
//
// See ../../docs/dgpserver/README.md in the repository for the developer guide,
// practical quickstart, operational caveats, and testing examples.
package dgpserver
