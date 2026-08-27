# Authentication and request context

## Two authentication layers

Noise XX proves possession of the peer's static private key. After that handshake, `Authenticator.Authenticate` maps `Credentials` to an application `Principal` or rejects admission.

`Credentials` contains the peer static public key, DGP session ID, and remote address string. These are identifiers, not authorization by themselves. A remote address can change or be shared; do not use it as the primary identity.

For a fixed deployment, use `NewStaticKeyAllowlist`. It copies the input map and compares keys in constant time:

```go
auth := dgpserver.NewStaticKeyAllowlist(map[[32]byte]dgpserver.Principal{
    clientPublicKey: User{ID: "alice"},
})
```

For database or policy-backed admission, implement `Authenticator` or use `AuthenticatorFunc`. Honor context cancellation, return `ErrUnauthenticated` (or another sanitized local error) on rejection, and never log credentials or secret key material. Authenticator panics are recovered as rejection.

A nil authenticator admits any peer that completes the cryptographic handshake and produces a nil principal. Set an authenticator explicitly for production trust boundaries. `dgproto.ServerConfig.AllowedClients` is a lower-level static-key filter; prefer one clearly owned admission policy rather than inconsistent duplicate lists.

## Principal and authorization

`Principal` is `any`: choose an immutable application value or pointer with safe concurrent behavior. The same principal is provided to `OnConnect`, each handler through `Context.Principal`, and `OnDisconnect`. `dgpserver` does not define roles or permissions; enforce them in command-group middleware or handlers.

Do not put secrets in a principal's formatted representation. Error and log calls can accidentally format application values.

## Context snapshots

For each inbound application message, `Context` provides:

- the embedded `context.Context`, canceled when the connection terminates;
- `Peer()` with address, session ID, and a defensive copy of the authenticated peer identity bytes;
- `Principal()` from admission;
- `Metadata()` with exact DGP message type and local receive time;
- `Params()`, an immutable routing-parameter snapshot (currently empty in the production command router);
- bounded `TrySend`, `Send`, `SendAndWait`, and `Close` capabilities.

Do not retain the handler context for background work. If work must outlive a handler, define ownership, copy required values, and arrange independent cancellation. Inbound messages may contain slices; copy data before retaining it or building independently mutable state.

## Send semantics

| Method | Backpressure | Success means |
|---|---|---|
| `TrySend(message)` | Never waits; can return `dgproto.ErrOutboundQueueFull` | Accepted into the bounded outbound queue |
| `Send(message)` | Waits for queue capacity or handler-context cancellation | Enqueued, not written |
| `SendAndWait(message)` | Waits for capacity and local transport completion | Written locally, not processed by the peer |
| `Close()` | Uses the connection close path | Graceful close was initiated/completed as defined by the runtime |

All three send forms use the handler's embedded context. `SendAndWait` is not an application acknowledgement. Define an explicit response or Ack convention if the business operation needs peer confirmation.

Do not mutate an outbound message or nested slices while a send is in progress. For echo-like responses, make defensive copies if request data could be retained or changed. Handle queue-full, cancellation, and connection-closed errors deliberately; retries need bounded policy and application-level idempotency.

A context built with `dgpserver.NewContext` or `Dispatch` is receive-only; send methods return `ErrRecorderClosed`. Use a `Recorder` when a unit test needs send assertions.
