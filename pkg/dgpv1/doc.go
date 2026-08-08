// Package dgpv1 implements the strict MVP profile of Datagram Protocol v1.
//
// The package provides the 40-byte little-endian wire header, frames and TLVs,
// Noise XX handshakes, authenticated sessions with replay protection and atomic
// rekeying, and TCP stream transport. TCP frames begin directly with the DGP1
// header; there is no separate length prefix. Message type 0x07 and flag bits 0
// and 2 are reserved for post-MVP use and are not available through Session.
// Receivers retain and ignore reserved header flags for forward compatibility.
package dgpv1
