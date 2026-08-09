// Package dgpserver provides the high-level, application-facing foundation for
// dispatching authenticated DGPv1 messages.
//
// The package deliberately exposes only EncryptedData, Ack, and ErrorMessage to
// handlers. Inbound messages use pointer form, matching dgpv1.Session.Receive.
// A Router is configured before Freeze; its zero value is ready for use.
package dgpserver
