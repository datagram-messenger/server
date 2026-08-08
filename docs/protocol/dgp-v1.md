# Datagram Protocol Version 1 (DGPv1) Specification

**Status:** Draft — Implementation Track
**Version:** 1.0.0
**Category:** Application-Layer Secure Transport Protocol

---

## 1. Overview & Architecture

### 1.1 Executive Summary

DGPv1 is a binary, session-oriented, cryptographically secured application
protocol designed for low-latency, bidirectional, multiplexed communication
between native desktop clients (Rust, embedded in Tauri v2) and
high-concurrency Go microservice backends.

DGPv1 draws its layered structure and framing philosophy from Telegram's
MTProto (strict separation of transport / cryptographic / application
layers, custom TLV-oriented framing, transport obfuscation), while
replacing MTProto's historical, custom-built cryptographic core with a
handshake constructed from the **Noise Protocol Framework**, modern AEAD
ciphers, and HKDF-based key schedules — primitives with established formal
security proofs, rather than bespoke constructions.

DGPv1 is transport-agnostic at the application layer: the same encrypted
frame format is carried either directly over TCP or over QUIC datagrams,
allowing automatic fallback when one transport is degraded or blocked.

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
|     (Noise_XX / Noise_IK handshake, AEAD encrypt/decrypt,    |
|      HKDF-SHA256 key schedule, replay window)                |
+--------------------------------------------------------------+
| L1  DGP Framing Layer                                        |
|     (TLV binary envelope, fixed header, padding/obfuscation) |
+--------------------------------------------------------------+
| L0  Transport Layer                                          |
|     (TCP stream framing  |  QUIC datagram/stream framing)    |
+--------------------------------------------------------------+
```

Each layer is independently substitutable. L0 may change (TCP ↔ QUIC)
without affecting L1–L4. L2 may rotate cipher suites without affecting
L3/L4 message semantics.

### 1.3 Protocol Capabilities

- **Multiplexing.** A single encrypted session (identified by a 128-bit
  Session ID) may carry multiple independent logical message streams,
  distinguished at L3 by a `Stream ID` sub-field inside the L4 payload
  envelope (not part of the L1 fixed header — see §5).
- **Pipelining.** Multiple in-flight requests are supported without
  head-of-line blocking at the application layer; correlation is achieved
  via monotonically increasing per-direction Sequence Numbers combined
  with an explicit `Ack` control message (§5.6).
- **Obfuscation.** An optional obfuscation mode (flag-gated, §3) removes
  static, fingerprintable byte patterns (magic bytes, fixed header shape)
  from the wire by XOR-striping the header with a per-session keystream
  derived at handshake time, mitigating DPI-based protocol classification.

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

All multi-byte integer fields in DGPv1 are encoded **Little-Endian**,
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
|                     Magic (0x44475031 "DGP1")                 |
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
| Magic            | 0      | 4            | `uint32`  | Fixed constant `0x44475031` (ASCII "DGP1"). Identifies the protocol on a shared port. Absent/randomized in Obfuscated Mode (Flags bit 0). |
| Version          | 4      | 1            | `uint8`   | Protocol version. `0x01` for this specification. |
| Flags            | 5      | 1            | `uint8`   | Bit 0: Obfuscated Mode. Bit 1: Padding Present. Bit 2: 0-RTT Resumption. Bits 3–7: Reserved, MUST be zero. |
| Msg Type         | 6      | 1            | `uint8`   | See §5 Message Type registry. |
| Reserved         | 7      | 1            | `uint8`   | MUST be zero on send, ignored on receive. Reserved for alignment / future flags. |
| Session ID       | 8      | 16           | `bytes16` | Cryptographically random session identifier, assigned at handshake completion. Doubles as a QUIC-style Connection ID for connection migration across network paths. |
| Sequence Number  | 24     | 8            | `uint64`  | Monotonically increasing per sending direction. Used as AEAD nonce material (§4) and for replay-window validation (§4.4). MUST NOT repeat within a session's cipher key epoch. |
| Payload Length   | 32     | 4            | `uint32`  | Length of the encrypted payload (ciphertext), **excluding** the AEAD Tag and Padding. |
| Pad Length       | 36     | 1            | `uint8`   | Length of trailing random padding, 0–255 bytes. |
| Reserved         | 37     | 3            | —         | Alignment filler, MUST be zero. |
| Payload          | 40     | variable     | `bytes`   | AEAD ciphertext of the L4 message (or handshake message for Msg Type `0x01`/`0x02`/`0x07`, which MAY be partially or fully unencrypted per handshake phase — see §4). |
| AEAD Tag         | 40+PL  | 16           | `bytes16` | Authentication tag (Poly1305 or GCM tag, both 128 bits). |
| Padding          | ...    | Pad Length   | `bytes`   | Cryptographically random bytes, not covered by the AEAD tag's confidentiality guarantee for content but MAY be included in the AEAD associated data for integrity of the length field (implementation choice, RECOMMENDED). |

### 3.3 Length Calculation & Anti-Fingerprinting Padding

Total wire frame size:

```
frame_size = 40 (fixed header) + Payload Length + 16 (AEAD tag) + Pad Length
```

To reduce the effectiveness of packet-length-based traffic classification
(a known weakness in naive binary protocols, including early MTProto
deployments), implementations SHOULD NOT pad to arbitrary lengths derived
directly from plaintext size. Instead, implementations SHOULD apply
**length bucketing**: round the total frame size up to the nearest
boundary in a fixed set (e.g., 256 / 512 / 1024 / 1500 bytes), computing
`Pad Length` accordingly, capped at 255. Padding bytes MUST be
cryptographically random, not zero-filled, to avoid a distinct statistical
signature.

---

## 4. Cryptographic Handshake & Key Exchange

### 4.1 Design Rationale

DGPv1's handshake is constructed using the **Noise Protocol Framework**
rather than a bespoke Diffie-Hellman + custom-AES construction (as in
classic MTProto). Two Noise patterns are used, mirroring the "Noise
Pipes" construction:

- **Noise_XX** — used for the *first* connection between a client and a
  given server identity, where neither side has cached the other's static
  public key. Provides mutual authentication with zero prior
  key knowledge, at the cost of a full 3-message, 1.5-RTT handshake.
- **Noise_IK** — used for *subsequent* connections once the client has
  cached the server's static public key from a prior successful `XX`
  handshake (or from an out-of-band pinned key). Reduces the handshake to
  2 messages and allows the client to transmit encrypted 0-RTT
  application data in the first flight.

### 4.2 Phase 1 — Client Hello / Ephemeral Key Exchange (Msg Type `0x01`)

```
HandshakeInit Payload:
+----------------------+----------+--------------------------------+
| Field                | Size     | Description                    |
+----------------------+----------+--------------------------------+
| Pattern              | 1 byte   | 0x01 = XX, 0x02 = IK           |
| Client Ephemeral (e) | 32 bytes | X25519 public key              |
| Encrypted Payload    | variable | Pattern-dependent (see below)  |
+----------------------+----------+--------------------------------+
```

- **Noise_XX, message 1 (`→ e`):** only the ephemeral public key is sent
  in the clear; no static key material or application data is exposed.
- **Noise_IK, message 1 (`→ e, es, s, ss`):** the client encrypts its own
  static public key and optional 0-RTT application payload using a key
  derived from `DH(client_ephemeral, server_static)`, since the client
  already possesses the server's static public key.

### 4.3 Phase 2 — Server Hello / Authentication & Key Derivation (Msg Type `0x02`)

```
HandshakeResponse Payload:
+------------------------+----------+---------------------------------+
| Field                  | Size     | Description                     |
+------------------------+----------+---------------------------------+
| Server Ephemeral (e)   | 32 bytes | X25519 public key               |
| Encrypted Static (s)   | variable | Server static key, AEAD-sealed  |
| Encrypted Payload      | variable | Optional early application data |
+------------------------+----------+---------------------------------+
```

Upon receipt, both parties compute the full Diffie-Hellman transcript
(`ee`, `es`/`se`, and `ss` depending on pattern) and derive the session
key schedule via **HKDF-SHA256**, following the Noise `Split()`
convention: the accumulated handshake chaining key `ck` is expanded into
two independent, directional 256-bit traffic keys:

```
(k_send, k_recv) = HKDF-SHA256-Expand(ck, "dgpv1 traffic keys", 64)
```

`k_send` on the client equals `k_recv` on the server and vice versa. Each
subsequent data frame is encrypted with **ChaCha20-Poly1305** (default) or
**AES-256-GCM** (negotiated fallback for hardware with AES-NI and no
ChaCha20 acceleration), using a 96-bit nonce constructed by
zero-extending the 64-bit `Sequence Number` field from the L1 header.

### 4.4 Session State Machine

```
   [ INIT ]
      |  send/recv HandshakeInit (0x01)
      v
[ HANDSHAKE_1 ]
      |  send/recv HandshakeResponse (0x02)
      v
[ KEYS_DERIVED ]  --- HKDF-SHA256 Split() ---
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

### 4.6 Zero-RTT Session Resumption

On successful completion of a Noise_XX handshake, the server issues an
opaque, encrypted **Resumption Ticket** (delivered as an `EncryptedData`
message immediately following handshake completion) containing the
negotiated static keys and a short validity window. On reconnect, the
client presents this ticket inside the `HandshakeInit` (Flags bit 2 set)
using the Noise_IK pattern, allowing the first flight to simultaneously
complete authentication **and** carry encrypted application payload,
achieving effective zero-RTT for the common reconnect case discussed in
§7 of the companion protocol-design document (session resume after
transient network loss).

> **0-RTT caveat (MUST be implemented):** data sent in the 0-RTT flight is
> replayable by a network attacker who captures and re-sends the first
> flight before the server marks the resumption ticket as consumed.
> Servers MUST treat 0-RTT-flight application data as at-most-once and
> non-idempotent-unsafe: only idempotent operations (e.g., `SyncRequest`,
> `Ping`) may be processed from the 0-RTT payload; state-mutating
> operations (e.g., `SendMessage`) received in the 0-RTT flight MUST be
> deferred until the full handshake confirmation completes.

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
| 0x07  | ResumptionTicket      | Server → Client| Yes (extension, required for §4.6) |
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
| Acked Sequence Count | 1 byte   | Number of entries following     |
| Acked Sequences[]    | 8*N bytes| List of Sequence Numbers acked  |
+----------------------+----------+---------------------------------+
```

Acks MAY be batched (multiple acknowledged Sequence Numbers in a single
frame) to reduce control-message overhead under high message throughput.

### 5.6 ResumptionTicket (0x07)

```
+----------------------+----------+-------------------------------+
| Field                | Size     | Description                   |
+----------------------+----------+-------------------------------+
| Ticket               | variable | Opaque, server-encrypted blob |
| Valid Until           | 8 bytes  | Unix timestamp (uint64, LE)  |
+----------------------+----------+-------------------------------+
```

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

DGPv1 is designed against the following adversary classes:

- **Passive network observer** — capable of recording all traffic on the
  path, attempting traffic analysis, protocol fingerprinting, or
  metadata correlation.
- **Active on-path adversary (MitM)** — capable of intercepting,
  modifying, injecting, or replaying frames.
- **DPI / censorship middlebox** — attempting to classify and selectively
  block DGPv1 traffic based on static byte signatures or packet-length
  distributions.
- **Malicious or compromised relay** — a node forwarding traffic (e.g., a
  future obfuscation proxy) that must not be able to decrypt session
  content even if it can observe framing metadata.

### 7.2 Mitigations

| Threat                       | Mitigation |
|-------------------------------|------------|
| Passive eavesdropping          | End-to-end AEAD confidentiality (ChaCha20-Poly1305 / AES-256-GCM) established via Noise handshake; forward secrecy from ephemeral X25519 keys. |
| Active MitM / key substitution | Noise_IK/XX mutual static-key authentication; server static key SHOULD be pinned or anchored to an out-of-band trust root (e.g., delivered via the existing TLS-secured `auth` gRPC service) rather than trusted-on-first-use in production. |
| Message replay                 | 64-bit sliding replay window (§4.5) per session per direction; Sequence Number reuse within a key epoch is prohibited by the rekeying policy (§4.4). |
| Ciphertext malleability         | AEAD (both candidate ciphers) provides integrity and authenticity, not merely confidentiality; any bit-flip invalidates the Poly1305/GCM tag. |
| Downgrade attacks               | Version and cipher/pattern negotiation fields are themselves covered by the handshake transcript hash, so a MitM cannot silently force a weaker configuration without detection at handshake completion. |
| Traffic analysis / fingerprinting | Optional obfuscation mode strips static magic bytes; length-bucketed random padding (§3.3) reduces packet-length-based classification. |
| Nonce reuse                     | Sequence-Number-derived nonces combined with mandatory rekeying bound the ciphertext volume per key, keeping usage within safe margins for both ChaCha20-Poly1305 and AES-256-GCM. |

### 7.3 Implementation Risk Disclosure

This specification defines a protocol built from well-studied, formally
analyzed primitives (Noise Protocol Framework, X25519, ChaCha20-Poly1305,
AES-256-GCM, HKDF-SHA256). Composition of individually secure primitives
into a new protocol is nonetheless a well-known source of subtle,
practically exploitable flaws (nonce derivation errors, transcript
binding omissions, replay-window off-by-ones, side channels in
non-constant-time comparisons). Accordingly:

1. Cryptographic primitives and the Noise state machine MUST be sourced
   from maintained, widely reviewed libraries (§6), never reimplemented
   from this document's description alone.
2. This specification has not undergone third-party formal security
   review or a symbolic/computational proof pass (e.g., via ProVerif,
   Tamarin, or a Noise-specific formal analysis of the exact pattern and
   extensions defined here, including the custom 0-RTT ticket mechanism
   in §4.6, which is a DGPv1-specific addition not covered by the
   upstream Noise specification's own analysis).
3. Prior to any production deployment handling real user data, an
   independent cryptographic security audit of both this specification
   and its concrete implementation is strongly RECOMMENDED, with
   particular attention to the 0-RTT replay surface described in §4.6.

---

*End of DGPv1 Specification.*
