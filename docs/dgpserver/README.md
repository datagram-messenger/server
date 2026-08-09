# Building applications with `dgpserver`

`pkg/dgpserver` is the application-facing server layer above [`pkg/dgpv1`](../../pkg/dgpv1/doc.go). It owns typed application dispatch, command routing, middleware, admission, principals, lifecycle hooks, bounded sends, and test seams. `pkg/dgpv1` continues to own TCP framing, Noise XX, encryption, replay protection, rekeying, keepalives, and connection I/O.

Use this guide when building a service on DGPv1. Read the [normative protocol specification](../protocol/dgp-v1.md) when implementing another peer or reasoning about wire compatibility.

## Start here

1. [Quickstart](quickstart.md) — build and stop a small authenticated server.
2. [Routing and middleware](routing.md) — typed DGP routes, application commands, groups, and policy wrappers.
3. [Authentication and request context](authentication-and-context.md) — trust boundaries, principals, metadata, and send semantics.
4. [Lifecycle, errors, and operations](lifecycle-and-errors.md) — hooks, graceful shutdown, panic policy, limits, and production caveats.
5. [Testing handlers](testing.md) — test with `Dispatch` and `Recorder` without TCP or cryptography.

The package's compiling examples are in [`example_test.go`](../../pkg/dgpserver/example_test.go). The runnable `api_datagram` service is a larger integration example in [`cmd/api_datagram`](../../cmd/api_datagram/main.go).

## Mental model

An inbound connection moves through these layers:

```text
TCP -> Noise XX handshake -> optional Authenticator -> OnConnect
    -> dgpv1 session/runtime -> dgpserver Router -> middleware -> handler
    -> Context send capability -> bounded dgpv1 outbound queue -> TCP
    -> OnDisconnect
```

Important boundaries:

- Only `*dgpv1.EncryptedData`, `*dgpv1.Ack`, and `*dgpv1.ErrorMessage` reach application routes. Ping/pong, rekey, close, and handshake messages are runtime-owned.
- A `Router` is configuration, not a live registry. `Serve`, `Freeze`, or the first dispatch freezes it; later mutation returns `ErrServerStarted`.
- DGP message routing selects the envelope type. A `CommandRouter` optionally performs a second, codec-neutral dispatch inside `EncryptedData`.
- The `Context` embeds the connection-scoped `context.Context` and exposes immutable peer/principal/metadata snapshots plus narrow send and close methods. It does not expose session keys or a raw connection.
- Each connection's application handlers run serially. Different connections can execute concurrently, so shared application state still needs synchronization.
- Queues and connection counts are bounded. Backpressure is an error or a wait, never an implicit unbounded buffer.

## What this package does not provide

`dgpserver` does not choose an application payload codec, dependency container, authorization model, logger, metrics backend, retry policy, or wire-level request/response convention. It also does not implement QUIC, Noise IK, resumption, or 0-RTT. Build those application concerns explicitly and do not infer them from DGP sequence numbers or `SendAndWait`.
