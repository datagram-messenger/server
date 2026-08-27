# Lifecycle, errors, and operations

## Lifecycle

`New` constructs a stopped high-level server. It creates a zero router when `Config.Router` is nil and defaults `DisconnectTimeout` to five seconds. Most network and capacity validation occurs when `Serve` creates the underlying `dgproto.Server`.

`Serve(ctx, listener)`:

- permits exactly one call;
- freezes the router before accepting traffic;
- takes operational ownership of the supplied listener;
- stops the core server when `ctx` is canceled;
- returns nil for the normal `dgproto.ErrServerClosed` shutdown path and otherwise returns startup/listener errors.

Coordinate shutdown explicitly instead of discarding the `Serve` result. `Shutdown(ctx)` starts graceful core closure and waits for serving, connections, handlers, and hooks. If its deadline expires, it aborts network I/O and returns an `*OpError` wrapping `ctx.Err()`. Application code that ignores cancellation may continue running; do not write unbounded handlers.

`Close` triggers immediate server closure without a caller-provided deadline. It is safe before serving and repeat calls are tolerated. A server cannot be restarted.

## Hooks

Order for an accepted peer is: Noise handshake, authenticator, state registration, `OnConnect`, message dispatch, then `OnDisconnect`.

- `OnConnect` can reject a connection. A returned error or recovered panic prevents dispatch.
- Once state is registered, `OnDisconnect` runs exactly once, including when `OnConnect` rejects or panics.
- `OnDisconnect` gets a detached context bounded by `DisconnectTimeout`; it cannot rely on the connection's send capability.
- Hook code must be cancellation-aware and must not expose peer secrets in logs.

Authentication rejection occurs before state registration and therefore does not call lifecycle hooks.

## Handler errors and panic policy

`Router.Dispatch` recovers handler, middleware, and command-decoder panics as `*PanicError`, matching `ErrHandlerPanic`. In production, the server passes each returned dispatch error to `Config.ErrorHandler` once when configured; this includes unchanged command-decoder errors and unknown commands matching `ErrNotHandled`.

- If no error handler is configured, `ErrNotHandled` is ignored and keeps the connection open.
- Other returned handler errors become `*HandlerError` and are terminal to the connection.
- An `ErrorHandler` can return nil to observe/consume an error and continue, or return an error to terminate the connection.
- A panic in `ErrorHandler` is recovered as a panic-kind `HandlerError` and terminates the connection.

There is no automatic wire error response. If policy permits one, send a sanitized `dgproto.ErrorMessage`; never copy raw internal errors, panic values, database details, principal values, or credentials to the peer. `HandlerError.Error` and `OpError.Error` intentionally omit wrapped causes while preserving `errors.Is`/`errors.As` locally.

`Dispatch` (the standalone test helper) also recovers panics, but it does not apply `Server.ErrorHandler` policy.

## Operational and security caveats

- Persist and protect the server Noise static private key. Rotation changes server identity and must be coordinated with clients.
- Bind explicitly. `:8090` exposes all interfaces; use a loopback or private address when public exposure is not intended.
- Configure positive handshake/write/idle/keepalive timeouts and ensure `ReadTimeout`, when enabled, is at least the liveness window accepted by `dgproto.NewServer`.
- Keep `OutboundQueue`, `HandlerQueue`, `MaxConcurrentHandshakes`, and `MaxActiveConnections` bounded. Handler-queue overflow is terminal rather than silently dropping messages.
- A slow handler blocks later application messages on the same connection. Move expensive work to a bounded application worker system only when ownership, cancellation, overload, and response correlation are explicit.
- Different connections run concurrently. Protect shared state and make middleware dependencies concurrency-safe.
- Avoid logging payloads, static keys, principals, session IDs, message text, or error causes unless a reviewed data policy permits it. Prefer coarse event types and safe correlation values.
- DGP transport security does not provide business authorization, idempotency, durable delivery, or peer processing confirmation.
- Do not enable or document historical post-MVP protocol features. Consult the [DGProto v1 specification](../protocol/dgproto-v1.md) and [pre-deployment checklist](../pre-deployment-checklist.md).

## Send behavior during termination

`Context.Send` and `Context.SendAndWait` use the handler context, so cancellation that wins before connection termination returns that context error. Once a terminal transition begins, new low-level sends return `dgproto.ErrConnectionClosed`, and pending queue-admission and completion waiters are released. `TrySend` remains nonblocking. Control close has a dedicated path and cannot be trapped behind a full application queue. Concurrent/repeated connection `Close`, server `Shutdown`, and server `Close` are idempotent; terminal-cause precedence remains stable. Disconnect hooks receive snapshots only and cannot send.
