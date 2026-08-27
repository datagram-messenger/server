# Datagram Protocol Version 1 (DGProto v1) Specification

**Status:** Draft — Implementation Track
**Version:** 1.0.0
**Category:** Application-Layer Secure Transport Protocol
**Normative profile:** Current MVP

> **Scope.** Unless a section is explicitly labeled **Historical / Post-MVP**, normative terms such as MUST, SHOULD, and MAY describe the current MVP. The MVP uses TCP, a three-flight Noise XX handshake, and ChaCha20-Poly1305. QUIC, transport obfuscation, Noise IK, resumption tickets, and 0-RTT are not implemented, negotiated, required, or permitted by the MVP. They are retained only in §8 as protocol history.

---

## 1. Overview & Architecture

### 1.1 Executive Summary

DGProto v1 is a binary, session-oriented, cryptographically secured application
protocol designed for low-latency, bidirectional, multiplexed communication
between native desktop clients (Rust, embedded in Tauri v2) and
high-concurrency Go microservice backends.

DGProto v1 separates transport, framing, cryptographic, session, and application
layers. The current MVP carries its fixed binary frames over TCP and uses the
Noise Protocol Framework, modern AEAD, and HKDF-based key schedules rather
than bespoke cryptographic constructions.

### 1.2 Layered Architecture (ASCII Diagram)

```
+--------------------------------------------------------------+
| L4  Application Messages                                     |
|     (Chat events, presence, typing, sync, acks)              |
+--------------------------------------------------------------+
| L3  DGP Session Layer                                        |
|     (Session state machine, sequence numbers, multiplexing)  |
+--------------------------------------------------------------+
| L2  DGP Cryptographic Layer                                  |
|     (Noise XX handshake, AEAD encrypt/decrypt,               |
|      HKDF-SHA256 key schedule, replay window)                |
+--------------------------------------------------------------+
| L1  DGP Framing Layer                                        |
|     (TLV binary envelope, fixed header, optional padding)    |
+--------------------------------------------------------------+
| L0  Transport Layer                                          |
|     (TCP stream framing)                                     |
+--------------------------------------------------------------+
```

The MVP fixes L0 to TCP and data-frame encryption to ChaCha20-Poly1305.
Future profiles may substitute layers only after separate specification.

### 1.3 Protocol Capabilities

- **Multiplexing.** A single encrypted session (identified by a 128-bit
  Session ID) may carry multiple independent logical message streams,
  distinguished at L3 by a `Stream ID` sub-field inside the L4 payload
  envelope (not part of the L1 fixed header — see §5).
- **Pipelining.** Multiple in-flight requests are supported without
  head-of-line blocking at the application layer; correlation is achieved
  via monotonically increasing per-direction Sequence Numbers combined
  with an explicit `Ack` control message (§5.6).

---

## 2. Binary Serialization & Type System

### 2.1 Primitives

| Type      | Size (bytes) | Description                                    |
|-----------|--------------|------------------------------------------------|
| `uint8`   | 1            | Unsigned 8-bit integer                         |
| `uint16`  | 2            | Unsigned 16-bit integer                        |
| `uint32`  | 4            | Unsigned 32-bit integer                        |
| `uint64`  | 8            | Unsigned 64-bit integer                        |
| `bytes16` | 16           | Fixed-length 128-bit opaque byte string        |
| `bytes32` | 32           | Fixed-length 256-bit opaque byte string (keys) |
| `bytes`   | variable     | Length-prefixed opaque byte string (see TLV)   |
| `string`  | variable     | UTF-8 encoded, length-prefixed as `bytes`      |

### 2.2 Byte Ordering

All multi-byte integer fields in DGProto v1 are encoded **Little-Endian**,
chosen to match native encoding on the overwhelming majority of deployment
targets (x86_64, aarch64) and to avoid byte-swapping overhead in the
zero-copy Rust parsing path.

> Implementers on Go MUST use `binary.LittleEndian`, not the package
> default assumption of Big-Endian used in some legacy protocols.

### 2.3 TLV Envelope

Variable-length application-layer fields (used inside decrypted L4
payloads, not in the fixed L1 header) follow a uniform TLV shape:

```
 0               1               2               3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|     Type      |            Length (uint16, LE)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Value (Length bytes)                   |
|                     ... padded to 4-byte boundary ...         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `Type` — 1 byte, field identifier scoped to the enclosing message.
- `Length` — 2 bytes (`uint16`, LE), byte length of `Value`, **excluding**
  alignment padding.
- `Value` — raw bytes, zero-padded up to the next 4-byte boundary.

### 2.4 Memory Alignment Rules

All fixed-size structures (L1 header, handshake messages) are defined
such that their total byte length is a multiple of 4. This guarantees:

1. Safe reinterpretation of buffer slices as `#[repr(C, align(4))]`
   structs in Rust via `zerocopy`, without unaligned-access UB.
2. Predictable offsets for Go's `unsafe.Pointer` struct-casting path,
   where used as a performance fast path (with `binary.Read` as the safe
   fallback — see §6.2).

TLV `Value` fields are zero-padded to the next 4-byte boundary; the
padding bytes are not covered by `Length` and MUST be treated as
opaque/ignored by parsers (they exist purely for alignment, not for
anti-fingerprinting — see §3.3 for the distinct padding mechanism used
there).

---

## 3. Frame Layout & Wire Format

### 3.1 Transport Framing — Fixed Header (40 bytes)

```
 0               1               2               3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Magic octets 44 47 50 31 ("DGP1")             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|    Version    |     Flags     |  Msg Type     |   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                         Session ID (128 bits)                 +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
+                     Sequence Number (uint64, LE)              +
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Payload Length (uint32, LE)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Pad Length   |               Reserved (3 bytes)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Payload (Payload Length bytes)             |
|                     [ AEAD ciphertext ]                       |
~                              ...                              ~
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       AEAD Tag (128 bits)                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Padding (Pad Length bytes, random)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 3.2 Field Specification

| Field            | Offset | Size (bytes) | Type      | Description |
|------------------|--------|--------------|-----------|--------------|
| Magic            | 0      | 4            | `bytes4`  | Fixed octets `44 47 50 31` (ASCII "DGP1"). If interpreted as a little-endian `uint32`, the value is `0x31504744`; the octets are normative. |
| Version          | 4      | 1            | `uint8`   | Protocol version. `0x01` for this specification. |
| Flags            | 5      | 1            | `uint8`   | Bit 1: Padding Present. Bits 0 and 2 are post-MVP reservations. Other bits are reserved. MVP senders MUST leave all reserved bits zero; receivers ignore unknown bits. |
| Msg Type         | 6      | 1            | `uint8`   | See §5 Message Type registry. |
| Reserved         | 7      | 1            | `uint8`   | MUST be zero on send and preserved on receive as part of the exact AEAD associated data. Reserved for alignment / future flags. |
| Session ID       | 8      | 16           | `bytes16` | Session identifier derived from the completed Noise transcript and assigned only after handshake completion. |
| Sequence Number  | 24     | 8            | `uint64`  | Monotonically increasing per sending direction. Used as AEAD nonce material (§4) and for replay-window validation (§4.4). MUST NOT repeat within a session's cipher key epoch. |
| Payload Length   | 32     | 4            | `uint32`  | Length of the encrypted payload (ciphertext), **excluding** the AEAD Tag and Padding. |
| Pad Length       | 36     | 1            | `uint8`   | Length of trailing random padding, 0–255 bytes. |
| Reserved         | 37     | 3            | —         | MUST be zero on send and preserved on receive as part of the exact AEAD associated data. |
| Payload          | 40     | variable     | `bytes`   | AEAD ciphertext of the L4 message, or a Noise handshake message for Msg Type `0x01`/`0x02`. |
| AEAD Tag         | 40+PL  | 0 or 16      | `bytes16` | Absent on handshake frames (`0x01` and `0x02`); otherwise the 128-bit Poly1305 or GCM authentication tag. Noise provides handshake-message authentication internally. |
| Padding          | ...    | Pad Length   | `bytes`   | Cryptographically random cleartext bytes. For encrypted frames every padding octet MUST be appended to the 40-byte header when forming AEAD associated data, so the tag authenticates the padding without encrypting it. |

Handshake frames use a zero Session ID and Sequence Number because those
values are established only after the third Noise XX flight completes.

### 3.3 Length Calculation & Anti-Fingerprinting Padding

Total wire frame size:

```
data_frame_size      = 40 + Payload Length + 16 + Pad Length
handshake_frame_size = 40 + Payload Length      + Pad Length
```

To reduce the effectiveness of packet-length-based traffic classification
(a known weakness in naive binary protocols, including early MTProto
deployments), implementations SHOULD NOT pad to arbitrary lengths derived
directly from plaintext size. Instead, implementations SHOULD apply
**length bucketing**: round the total frame size up to the nearest
boundary in a fixed set (e.g., 256 / 512 / 1024 / 1500 bytes), computing
`Pad Length` accordingly, capped at 255. Padding bytes MUST be
cryptographically random, not zero-filled, to avoid a distinct statistical
signature. Encrypted-frame AAD is exactly `header[0:40] || padding`. This changes v1 wire semantics for padded frames: layout and unpadded bytes are unchanged, but legacy padded frames that authenticated only the header are rejected.

---

## 4. Cryptographic Handshake & Key Exchange

### 4.1 MVP Handshake

The MVP uses only `Noise_XX_25519_ChaChaPoly_SHA256`. It is a three-flight,
1.5-RTT mutual-authentication handshake. Implementations MUST reject any
other pattern in the MVP profile. Before processing the first Noise token, both peers MUST call `MixHash(prologue)` with the exact five ASCII octets `44 47 50 76 31` (`DGPv1`), with no NUL terminator, length prefix, or newline.

### 4.2 Phase 1 — Client Hello / Ephemeral Key Exchange (Msg Type `0x01`)

```text
HandshakeInit Payload:
+----------------------+----------+--------------------------------+
| Field                | Size     | Description                    |
+----------------------+----------+--------------------------------+
| Pattern              | 1 byte   | MUST be 0x01 (Noise XX)        |
| Reserved             | 3 bytes  | MUST be zero                   |
| Client Ephemeral (e) | 32 bytes | X25519 public key              |
+----------------------+----------+--------------------------------+
```

Noise XX message 1 is `→ e`. Its payload is exactly 36 bytes in the DGProto v1
wrapper. It carries no Noise payload, static key material, or application data.

### 4.3 Phases 2–3 — Authentication & Key Derivation (Msg Type `0x02`)

Noise XX always has three messages. DGProto v1 carries both the server's second
flight and the client's third flight in handshake frames with message type
`0x02`; direction and handshake state distinguish the two payload shapes.
Neither frame has an outer DGProto v1 AEAD tag.

```
HandshakeResponse Payload (server → client, Noise XX message 2):
+------------------------+----------+---------------------------------+
| Field                  | Size     | Description                     |
+------------------------+----------+---------------------------------+
| Server Ephemeral (e)   | 32 bytes | X25519 public key               |
| Noise Payload          | 64 bytes | Encrypted server static key     |
+------------------------+----------+---------------------------------+

HandshakeFinish Payload (client → server, Noise XX message 3):
+------------------------+----------+---------------------------------+
| Field                  | Size     | Description                     |
+------------------------+----------+---------------------------------+
| Noise Payload          | 64 bytes | Encrypted client static key     |
+------------------------+----------+---------------------------------+
```

The client and server MUST NOT enter the encrypted-session state or use the
Session ID until message 3 has been produced or authenticated, respectively. Let `channel_binding` be Noise's final 32-byte handshake hash returned by `ChannelBinding()` after message 3. Both peers MUST derive `SessionID = SHA-256(ASCII("DGPv1 SessionID") || channel_binding)[0:16]`; concatenation has no separator or length prefix.
At that point both parties compute the full Diffie-Hellman transcript and
derive the session key schedule via the Noise `Split()` convention. The two
independent, directional 256-bit traffic keys are exactly the standard Noise
`Split()` outputs; DGProto v1 MUST NOT apply an additional HKDF or label. In the
canonical Noise order `(k1, k2) = Split()`, `k1` protects initiator-to-responder
traffic and `k2` protects responder-to-initiator traffic. The client therefore
uses `k1` to send and `k2` to receive; the server uses `k2` to send and `k1` to
receive. Each subsequent MVP data frame MUST be encrypted with **ChaCha20-Poly1305**,
using a 96-bit nonce constructed by
zero-extending the 64-bit `Sequence Number` field from the L1 header.

### 4.4 Session State Machine

```
   [ INIT ]
      |  send/recv HandshakeInit (0x01)
      v
[ HANDSHAKE_1 ]
      |  server sends / client receives Noise message 2 (0x02)
      v
[ HANDSHAKE_2 ]
      |  client sends / server receives Noise message 3 (0x02)
      v
[ KEYS_DERIVED ]  --- Noise Split() ---
      v
[ ENCRYPTED_SESSION ]  <------------------------+
      |  EncryptedData (0x03) / Ping (0x04) /   |
      |  Ack (0x06)                             |
      |                                         |
      | rekey interval elapsed or N frames sent |
      v                                         |
[ REKEYING ] -- new HKDF derivation ------------+
      |
      | SessionClose (0x05) or idle timeout
      v
[ CLOSED ]
```

#### 4.4.1 Rekeying

Rekeying is directional. The handshake establishes epoch `1` independently
for each sending direction. A sender MUST initiate the next epoch before
encrypting further application traffic when either 2^32 frames have been
sent in the current epoch or 10 minutes have elapsed since that epoch began.
Concurrent senders observing one trigger boundary MUST produce exactly one
`RekeyInit`; the remaining sends continue after that transition.

`RekeyInit` uses message type `0x08` and is encrypted under the current
epoch's traffic key. Its plaintext is exactly 36 bytes:

```
+----------------------+----------+------------------------------------+
| Field                | Size     | Description                        |
+----------------------+----------+------------------------------------+
| Epoch                | 4 bytes  | Next uint32 epoch, little-endian   |
| Key Confirm          | 32 bytes | HMAC-SHA256 confirmation           |
+----------------------+----------+------------------------------------+
```

For current directional traffic secret `K` and proposed epoch `E`, the sender
MUST compute:

```
KeyConfirm = HMAC-SHA256(K, "DGPv1 Rekey Confirm" || LE32(E))
K_next     = HMAC-SHA256(K, "DGPv1 Rekey Send Key")
```

The label `"DGPv1 Rekey Receive Key"` is reserved as the receive-labelled
output of the key-ratchet API. On the wire, both peers ratchet the same
directional secret with the send label, so the sender's next send key equals
the receiver's next receive key.

The sender MUST transmit `RekeyInit` as the final frame of epoch `E-1`, then
install `K_next`, set the directional epoch to `E`, and reset that direction's
Sequence Number to `1`. The receiver MUST authenticate the frame under the
old key, require `E` to equal its current epoch plus one, verify `KeyConfirm`
in constant time, install `K_next`, reset the new epoch replay window, and
then accept new-epoch frames beginning at Sequence Number `1`.

After accepting a rekey, a receiver MAY accept delayed non-rekey frames from
the immediately previous epoch for at most 2048 current-epoch frames and 30
seconds, whichever expires first. Previous-epoch frames remain subject to
their own replay window. A `RekeyInit` authenticated under the previous key
MUST be rejected as a duplicate or rollback even when its sequence was
already seen; it MUST NOT be reported as a generic authentication failure.
Epoch zero, duplicate or rollback epochs, skipped or future epochs, and epoch
advance past `uint32` maximum MUST be rejected. An invalid confirmation MUST
be rejected without changing keys, epoch, sequence state, replay state, or
grace state. Frames that authenticate under neither current nor retained
previous keys MUST be rejected as authentication failures.

### 4.5 Replay Window Mechanics

Each session maintains, per receive direction, a 64-bit sliding-window
anti-replay structure (modeled on the mechanism specified for IPsec ESP
and used in WireGuard):

- `highest_seq` — the highest validated Sequence Number received.
- `window_bitmap` — a fixed-size bitmap (RECOMMENDED: 2048 bits) tracking
  which of the most recent Sequence Numbers below `highest_seq` have
  already been accepted.

Validation algorithm for an incoming frame with Sequence Number `n`:

1. If `n > highest_seq`: accept, shift the bitmap by `n - highest_seq`,
   set `highest_seq = n`, mark bit for `n`.
2. If `n <= highest_seq` and `n > highest_seq - window_size`: check the
   bitmap; if already marked, **reject** (replay); otherwise accept and
   mark the bit.
3. If `n <= highest_seq - window_size`: **reject** unconditionally (frame
   too old to verify against the window).

---

## 5. Message Types & Control Messages

### 5.1 Core Message ID Registry

| ID    | Name               | Direction      | Encrypted? |
|-------|--------------------|----------------|------------|
| 0x01  | HandshakeInit       | Client → Server| No (Noise handles its own confidentiality per pattern) |
| 0x02  | HandshakeResponse   | Server → Client| No (as above) |
| 0x03  | EncryptedData        | Bidirectional  | Yes |
| 0x04  | Ping / Pong          | Bidirectional  | Yes |
| 0x05  | SessionClose         | Bidirectional  | Yes |
| 0x06  | Ack                  | Bidirectional  | Yes |
| 0x07  | Reserved (post-MVP resumption ticket) | — | MVP implementations MUST NOT send it |
| 0x08  | RekeyInit             | Bidirectional  | Yes (under the current epoch key) |
| 0x09  | Error                 | Bidirectional  | Yes |

### 5.2 EncryptedData (0x03) Payload

```
+----------------+----------+----------------------------------+
| Field          | Size     | Description                      |
+----------------+----------+----------------------------------+
| Stream ID      | 2 bytes  | Logical multiplexing channel     |
| App Msg Type   | 1 byte   | L4 application message type      |
| Reserved       | 1 byte   | Alignment filler, MUST be zero   |
| App Payload    | variable | TLV-encoded application message  |
+----------------+----------+----------------------------------+
```

### 5.3 Ping / Pong (0x04)

```
+----------------+----------+----------------------------------+
| Field          | Size     | Description                      |
+----------------+----------+----------------------------------+
| Is Response    | 1 byte   | 0x00 = Ping, 0x01 = Pong         |
| Nonce          | 8 bytes  | Echoed back unmodified by Pong   |
+----------------+----------+----------------------------------+
```

### 5.4 SessionClose (0x05)

```
+----------------+----------+-------------------------------------+
| Field          | Size     | Description                         |
+----------------+----------+-------------------------------------+
| Close Code     | 2 bytes  | 0x0000 Normal, 0x0001 Auth Expired, |
|                |          | 0x0002 Protocol Error, 0x0003 Idle  |
| Reason         | variable | UTF-8 string, TLV-encoded, optional |
+----------------+----------+-------------------------------------+
```

### 5.5 Ack (0x06)

```
+----------------------+----------+---------------------------------+
| Field                | Size     | Description                     |
+----------------------+----------+---------------------------------+
| Acked Sequence Count | 1 byte   | Number of entries, 1–255        |
| Acked Sequences[]    | 8*N bytes| List of Sequence Numbers acked  |
+----------------------+----------+---------------------------------+
```

Acks MAY be batched (multiple acknowledged Sequence Numbers in a single
frame) to reduce control-message overhead under high message throughput.

---

## 6. Implementation Guidelines

### 6.1 Rust (Tauri v2 Backend)

- **Async runtime:** build the connection actor on `tokio`, with a
  dedicated task per session performing the read loop, and a bounded
  `tokio::sync::mpsc` channel feeding a single dedicated write task —
  identical in spirit to the single-writer discipline established for the
  Go server (§6.2), preventing interleaved partial writes on the
  underlying socket.
- **Zero-copy buffer management:** use the `bytes` crate's `Bytes` /
  `BytesMut` for all frame buffers. Incoming socket reads should fill a
  reusable `BytesMut`, and the fixed L1 header should be parsed via
  `zerocopy::FromBytes` on a `.split_to(40)` sub-slice, avoiding a memcpy
  of the header into a separate owned struct.
- **Header parsing:** prefer `nom` combinators for the variable-length TLV
  application payload (§2.3), where boundaries are not statically known,
  and `zerocopy` for the fixed 40-byte L1 header where the layout is
  static and alignment-guaranteed (§2.4).
- **Cryptographic primitives:** DO NOT hand-implement the Noise state
  machine, X25519 scalar multiplication, or the AEAD constructions.
  Use the `snow` crate (a maintained, widely deployed Rust implementation
  of the Noise Protocol Framework) for the handshake, and `chacha20poly1305`
  / `aes-gcm` (RustCrypto) for the per-frame AEAD, driven by keys derived
  through `snow`'s own `Split()` output. Hand-rolled reimplementation of
  these primitives is explicitly discouraged — see §7.

### 6.2 Go (Server)

- **Concurrency model:** one goroutine performing `conn.Read()` in a loop
  per session; exactly one goroutine performing `conn.Write()`, fed by a
  buffered channel — mirroring the single-writer pattern already adopted
  elsewhere in this system's TCP-based services.
- **Allocation mitigation:** use `sync.Pool` for the reusable read/write
  byte buffers (`[]byte`, sized to the maximum frame length) to avoid
  per-frame heap allocation and reduce GC pressure under high connection
  concurrency.
- **Binary reader efficiency:** parse the fixed L1 header via
  `encoding/binary.LittleEndian.Uint32/Uint64` calls against buffer
  offsets rather than `binary.Read` with reflection, which is measurably
  slower in the hot path; reserve `binary.Read` for cold-path / debug
  tooling only.
- **Cryptographic primitives:** use the `flynn/noise` package (a general
  purpose Go implementation of the Noise Protocol Framework) for the
  handshake, and the Go standard library `crypto/chacha20poly1305` /
  `crypto/cipher` (AES-GCM) for per-frame AEAD. As with the Rust client,
  do not reimplement these primitives.

---

## 7. Security Considerations

### 7.1 Threat Model

DGProto v1 is designed against the following adversary classes:

- **Passive network observer** — capable of recording all traffic on the
  path, attempting traffic analysis, protocol fingerprinting, or
  metadata correlation.
- **Active on-path adversary (MitM)** — capable of intercepting,
  modifying, injecting, or replaying frames.
- **DPI / censorship middlebox** — attempting to classify and selectively
  block DGProto v1 traffic based on static byte signatures or packet-length
  distributions.
- **Malicious or compromised relay** — a future node forwarding traffic
  that must not be able to decrypt session content even if it can observe
  framing metadata.

### 7.2 Mitigations

| Threat                       | Mitigation |
|-------------------------------|------------|
| Passive eavesdropping          | End-to-end ChaCha20-Poly1305 confidentiality established via Noise XX; forward secrecy from ephemeral X25519 keys. |
| Active MitM / key substitution | Noise XX mutual static-key authentication; the server static key SHOULD be pinned or anchored to an out-of-band trust root rather than trusted on first use in production. |
| Message replay                 | 64-bit sliding replay window (§4.5) per session per direction; Sequence Number reuse within a key epoch is prohibited by the rekeying policy (§4.4). |
| Ciphertext malleability         | ChaCha20-Poly1305 provides integrity and authenticity; any ciphertext or tag modification fails authentication. |
| Downgrade attacks               | The MVP has no cipher or handshake-pattern negotiation; peers MUST use the fixed profile in §4.1. |
| Traffic analysis / fingerprinting | Random padding and optional length bucketing (§3.3) reduce packet-length-based classification; the MVP does not conceal its fixed magic bytes. |
| Nonce reuse                     | Sequence-Number-derived nonces combined with mandatory rekeying bound the ciphertext volume per key, keeping usage within safe margins for ChaCha20-Poly1305. |

### 7.3 Implementation Risk Disclosure

This specification defines a protocol built from well-studied, formally
analyzed primitives (Noise Protocol Framework, X25519, ChaCha20-Poly1305,
HKDF-SHA256). Composition of individually secure primitives
into a new protocol is nonetheless a well-known source of subtle,
practically exploitable flaws (nonce derivation errors, transcript
binding omissions, replay-window off-by-ones, side channels in
non-constant-time comparisons). Accordingly:

1. Cryptographic primitives and the Noise state machine MUST be sourced
   from maintained, widely reviewed libraries (§6), never reimplemented
   from this document's description alone.
2. This specification has not undergone third-party formal security
   review or a symbolic/computational proof pass of the exact profile and
   extensions defined here.
3. Prior to any production deployment handling real user data, an
   independent cryptographic security audit of both this specification
   and its concrete implementation is strongly RECOMMENDED.

---

## 8. Historical / Post-MVP Design Notes (Non-Normative)

Earlier DGProto v1 drafts proposed the following extensions. They are retained as
protocol history only. Normative terms in this section do not apply to the MVP.
An MVP implementation MUST NOT require, advertise, or send them:

- QUIC datagram or stream transport and connection migration.
- Header or transport obfuscation.
- The Noise IK handshake pattern.
- Resumption tickets (`0x07`).
- 0-RTT application data.

These ideas require a future versioned profile with complete wire semantics,
negotiation, downgrade protection, replay policy, and interoperability tests.

*End of DGProto v1 Specification.*
