# DGP High-Level Go Server SDK — implementation contract

This document is the implementation-ready contract for `pkg/dgpserver`, an ergonomic server SDK over `pkg/dgpv1`. The protocol core remains responsible for framing, Noise, sessions, replay protection, rekeying, keepalive, and connection I/O. Existing `dgpv1` APIs and the DGP v1 wire format remain compatible.

## Design review of the existing roadmap

The earlier roadmap had sound safety goals, but left too much architecture for implementation time:

- Its proposed `func(*Context, any) error` handler forced application type switches. `cmd/api_datagram` now uses typed DGP registration after its SDK migration, but application-command dispatch is still a local `AppMessageType` map rather than the planned SDK command router.
- Protocol-message routing was described, but codec-neutral routing of commands inside `EncryptedData` was not designed.
- `Context` risked becoming a synchronized state bag/service locator instead of a narrow request and connection capability.
- Listener creation/closure, root cancellation, graceful shutdown, immediate close, repeat calls, and `Serve` return values were not one precise state machine.
- Low-level `Connection.Send` means nonblocking queue admission, while the roadmap did not settle names for queued versus written delivery.
- Authentication timing, principal lifetime, hook rejection/panic paths, and exactly-once disconnect behavior were underspecified.
- Runtime route mutation and configuration freezing were unresolved, creating avoidable race risk.
- Testing still required crypto/TCP because there was no in-memory dispatch/recorder seam.
- Ten feature phases mixed essential MVP design with a large optional middleware/observability catalog.

The contract below closes those gaps. Remaining choices are isolated under **Owner decisions before coding**.

## Frozen public API contract

### Handler, typed adapter, and DGP routing

```go
type Handler interface {
    HandleDGP(*Context, any) error
}

type HandlerFunc func(*Context, any) error
func (f HandlerFunc) HandleDGP(c *Context, m any) error

type TypedHandlerFunc[T any] func(*Context, *T) error
type Middleware func(Handler) Handler

// Generic methods are unavailable in Go; use a package function.
func Handle[T any](r *Router, h TypedHandlerFunc[T]) error

func (r *Router) Use(...Middleware) error
func (r *Router) HandleEncryptedData(TypedHandlerFunc[dgpv1.EncryptedData]) error
func (r *Router) HandleAck(TypedHandlerFunc[dgpv1.Ack]) error
func (r *Router) HandleError(TypedHandlerFunc[dgpv1.ErrorMessage]) error
func (r *Router) NotFound(Handler) error
```

`Router{}` is ready for registration. `Handle[T]` accepts only the closed inbound application-visible set `dgpv1.EncryptedData`, `dgpv1.Ack`, and `dgpv1.ErrorMessage`; pointer type arguments, unsupported types, nil handlers, and duplicates return configuration errors. Ping/pong, close, and rekey remain runtime-owned in MVP. The checked assertion lives in the adapter, never in application handlers.

Registration is ordered, is not concurrency-safe, and is legal only before serving. Duplicate routes return `ErrRouteConflict`; there is no implicit replacement. The default unhandled route returns `ErrNotHandled`, which is observed but is nonfatal.

The module declares Go 1.25, so generic type declarations/functions are available. A generic registration function is the practical alternative to an impossible generic `Server` method.

### Hello-world (15 lines)

```go
func run(ctx context.Context, ln net.Listener, key dgpv1.StaticKey) error {
    r := new(dgpserver.Router)
    _ = r.HandleEncryptedData(func(c *dgpserver.Context, m *dgpv1.EncryptedData) error {
        return c.TrySend(&dgpv1.EncryptedData{
            StreamID: m.StreamID, AppMessageType: m.AppMessageType, Fields: m.Fields,
        })
    })
    s, err := dgpserver.New(dgpserver.Config{StaticKey: key, Handler: r})
    if err != nil {
        return err
    }
    defer s.Close()
    return s.Serve(ctx, ln)
}
```

Full examples must check registration errors; the compact example ignores only a constant-valid registration to stay within 15 lines.

### Server lifecycle and listener ownership

```go
type Config struct {
    StaticKey               dgpv1.StaticKey
    Handler                 Handler
    Authenticator           Authenticator
    ErrorHandler            ErrorHandler
    OnConnect               ConnectHook
    OnDisconnect            DisconnectHook
    HandshakeTimeout        time.Duration
    ReadTimeout             time.Duration
    WriteTimeout            time.Duration
    IdleTimeout             time.Duration
    KeepaliveInterval       time.Duration
    KeepaliveTimeout        time.Duration
    OutboundQueue           int
    HandlerQueue            int
    MaxConcurrentHandshakes int
    MaxActiveConnections    int
}

func New(Config) (*Server, error)
func (s *Server) Serve(ctx context.Context, ln net.Listener) error
func (s *Server) Shutdown(ctx context.Context) error
func (s *Server) Close() error
```

Lifecycle rules:

1. `New` copies and validates configuration and applies documented bounded defaults. It never creates a listener.
2. The caller creates/configures the listener. During `Serve`, the server may close that exact listener only to unblock `Accept`; it never creates, replaces, reopens, or reuses it. Thus creation ownership is external and operational closure is explicit.
3. A server permits one `Serve`. Immediately before its first `Accept`, it atomically freezes routes, groups, middleware, hooks, authenticator, and error handler. Later mutation returns `ErrServerStarted` without partial changes.
4. Canceling the root context initiates orderly shutdown. `Serve` returns nil after context-driven orderly shutdown; it returns listener/startup failures. Explicit `Close` racing with `Serve` may return an error matching `ErrServerClosed`.
5. `Shutdown(ctx)` is concurrent-safe and idempotent: stop accepting/admission, gracefully close active connections, stop starting handlers, wait for active handlers and disconnect hooks, then return. At deadline it force-closes the remainder and returns an `*OpError` wrapping `ctx.Err()`.
6. `Close()` is idempotent immediate termination: stop accepting, close handshake/active transports, cancel handler contexts, and finish runtime accounting. It is valid before `Serve`.
7. `ListenAndServe` is not MVP: explicit listener construction keeps socket policy and tests obvious.

### Request context, peer, and ownership

```go
type Context struct { /* unexported */ }
func (c *Context) Context() context.Context
func (c *Context) Peer() Peer
func (c *Context) Principal() Principal
func (c *Context) MessageType() dgpv1.MessageType
func (c *Context) Params() Params
func (c *Context) Metadata() Metadata
func (c *Context) TrySend(any) error
func (c *Context) Send(context.Context, any) error
func (c *Context) SendAndWait(context.Context, any) error
func (c *Context) Close(code uint16, reason string) error

type Peer struct {
    StaticKey   [32]byte
    SessionID   [16]byte
    RemoteAddr  net.Addr
    ConnectedAt time.Time
}

type Params struct {
    Command  Command
    StreamID uint16
}

type Metadata struct {
    ReceivedAt time.Time
    MessageType dgpv1.MessageType
}
```

`Context` is one inbound invocation. Its Go context derives from the connection and is canceled on disconnect/shutdown. It is not a service locator: no `Set/Get`, global bag, raw `*dgpv1.Connection`, `Session`, frame, or traffic secrets. Dependencies are captured in typed closures.

Peer, principal, params, and metadata are immutable snapshots. Accessors clone slices; `RemoteAddr` is read-only. Inbound messages and nested slices are valid for the handler call and must be copied before retention/mutation. An outbound message must not be mutated while a send call is in progress.

### Backpressure: queued versus written

- `TrySend` is nonblocking. Success means accepted into the bounded per-connection FIFO; full returns `ErrQueueFull`.
- `Send(ctx, m)` waits for bounded queue capacity. Success still means **queued**, not written; cancellation wraps `ctx.Err()`.
- `SendAndWait(ctx, m)` waits until the frame and any preceding automatic rekey are fully written. It does not mean peer receipt or business acknowledgement.
- Concurrent sends are ordered by successful queue admission; no stronger ordering is promised.
- Sends after cancellation and all sends from `OnDisconnect` return `ErrConnectionClosed`.
- `Close` uses a dedicated control path and is not trapped behind a full application queue.
- Inbound handler-queue overflow remains terminal; queues are never unbounded and messages are never silently dropped.

Implement this with a compatible extension to `dgpv1.Connection` for context-aware enqueue and per-item write completion, not a second high-level queue. Preserve existing `Connection.Send` behavior.

### Codec-neutral command router and groups

```go
type Command uint8

type CommandDecoder interface {
    DecodeCommand(*dgpv1.EncryptedData) (Command, any, error)
}
type CommandDecoderFunc func(*dgpv1.EncryptedData) (Command, any, error)

// Command routes reuse Handler/HandlerFunc. The message argument is the
// decoder result, so ordinary Middleware composes without another handler kind.
func NewCommandRouter(CommandDecoder) *CommandRouter
func (r *CommandRouter) Handle(Command, Handler) error
func (r *CommandRouter) Group(func(*CommandGroup) error) error
func (g *CommandGroup) Use(...Middleware) error
func (g *CommandGroup) Handle(Command, Handler) error
func (r *CommandRouter) Handler() TypedHandlerFunc[dgpv1.EncryptedData]
```

The SDK selects no payload codec. A decoder may route directly on `AppMessageType`, inspect TLVs, or decode an application struct:

```go
commands := dgpserver.NewCommandRouter(dgpserver.CommandDecoderFunc(
    func(m *dgpv1.EncryptedData) (dgpserver.Command, any, error) {
        return dgpserver.Command(m.AppMessageType), m, nil
    }))
_ = commands.Handle(1, dgpserver.HandlerFunc(
    func(c *dgpserver.Context, payload any) error {
        return c.TrySend(payload.(*dgpv1.EncryptedData))
    }))
_ = router.HandleEncryptedData(commands.Handler())
```

Groups are registration-time policy scopes, justified for authorization, logging, and rate limits; they are not URL trees. Duplicate command IDs across groups conflict. Global/router middleware wraps group middleware. For `Use(A, B)` and group `Use(C)`, ordering is `A before → B before → C before → handler → C after → B after → A after`. Chains are built once at freeze time.

### Errors, middleware, and panic policy

```go
type ErrorKind uint8
const (
    ErrorUnknown ErrorKind = iota
    ErrorBadMessage
    ErrorUnauthorized
    ErrorForbidden
    ErrorNotHandled
    ErrorOverloaded
    ErrorInternal
)

type HandlerError struct {
    Kind  ErrorKind
    Code  uint16
    Err   error
    Fatal bool
}
func (e *HandlerError) Error() string
func (e *HandlerError) Unwrap() error

type ErrorHandler interface { HandleError(*Context, error) }
type ErrorHandlerFunc func(*Context, error)

type OpError struct { Op string; Peer Peer; Err error }
func (e *OpError) Error() string
func (e *OpError) Unwrap() error
```

Sentinels: `ErrServerStarted`, `ErrServerClosed`, `ErrRouteConflict`, `ErrNotHandled`, `ErrQueueFull`, `ErrConnectionClosed`, `ErrUnauthorized`, and `ErrHandlerPanic`. Sensitive identity is excluded from formatted error strings. All errors remain usable with `errors.Is/As`.

Returned handler/decoder errors reach the single configured `ErrorHandler` exactly once. Default policy: observe and continue for `ErrNotHandled`; sanitize and optionally send `dgpv1.ErrorMessage` for nonfatal `*HandlerError`; close one connection for fatal errors, invariant failures, and panics. Never send raw internal/authentication errors.

An unremovable outer recovery boundary converts panic into an error wrapping `ErrHandlerPanic`; stack data is local-only. User recovery middleware may customize observation, not disable safety. `ErrorHandler` panic is itself recovered and closes the connection. Middleware may call `next` at most once; enforce this as a documented/tested contract without reflection.

```go
func requestLog(log *slog.Logger) dgpserver.Middleware {
    return func(next dgpserver.Handler) dgpserver.Handler {
        return dgpserver.HandlerFunc(func(c *dgpserver.Context, m any) error {
            started := time.Now()
            err := next.HandleDGP(c, m)
            log.InfoContext(c.Context(), "dgp", "type", c.MessageType(),
                "duration", time.Since(started), "err", err)
            return err
        })
    }
}
```

### Authentication boundary and principal

```go
type Credentials struct {
    StaticKey  [32]byte
    RemoteAddr net.Addr
}
type Principal interface { ID() string }
type Authenticator interface {
    Authenticate(context.Context, Credentials) (Principal, error)
}
type AuthenticatorFunc func(context.Context, Credentials) (Principal, error)
```

Noise first authenticates the client static key. The SDK then calls `Authenticator` while admission capacity is held but before active registration, hooks, or application dispatch. Nil authenticator admits every cryptographically valid peer with nil principal and must be called out in production documentation. Supply a static-key allowlist adapter.

Rejection maps locally to `ErrUnauthorized`, closes without policy details, and invokes neither hook. Principal is immutable and exposed through `Context.Principal`; authorization is middleware with closure-injected policy.

The low-level seam should expose only completed-handshake peer public key/session identity to the adapter—never mutable `Session` or handshake/traffic secrets.

### Hooks: exact ordering and exactly once

```go
type ConnectHook func(context.Context, ConnectionInfo) error
type DisconnectHook func(context.Context, ConnectionInfo, error)
```

For each transport: finish Noise → authenticate → reserve/register active connection and create context → call `OnConnect` once → dispatch serially → stop new handlers and cancel connection context → wait for current handler → call `OnDisconnect` once with terminal cause and a detached timeout-bounded cleanup context → release slot.

Authentication rejection invokes neither hook. Once active registration succeeds, disconnect runs exactly once even if connect returns an error or panics. Connect failure prevents dispatch. Hook panics are recovered and close only that connection. No new connect hook starts after shutdown closes admission. Disconnect cannot send. MVP has one hook of each type; applications explicitly compose multiple callbacks, avoiding ambiguous failure ordering.

### In-memory testing without crypto/TCP

```go
type Recorder struct { /* concurrency-safe */ }
func NewRecorder(Peer, Principal) *Recorder
func (r *Recorder) Context(context.Context) *Context
func (r *Recorder) Sent() []any
func (r *Recorder) Closed() (code uint16, reason string, ok bool)
func Dispatch(context.Context, Handler, Peer, Principal, any) error
```

`Recorder` implements bounded send/close behavior without TCP, Noise, goroutines, or timers; snapshots are defensive. `Dispatch` exercises routing/middleware when reply assertions are unnecessary.

```go
func TestEcho(t *testing.T) {
    rec := dgpserver.NewRecorder(dgpserver.Peer{}, nil)
    c := rec.Context(context.Background())
    err := echo(c, &dgpv1.EncryptedData{AppMessageType: 1})
    if err != nil || len(rec.Sent()) != 1 { t.Fatal(err) }
}
```

Integration tests still use real loopback TCP plus a `dgpv1` client for handshake, authentication, rekey, deadlines, saturation, and shutdown.

## MVP implementation phases

Audit basis: `HEAD` `903fd10`, the current `pkg/dgpserver`, `pkg/dgpv1`, and `cmd/api_datagram` code/tests, plus `docs/protocol/dgp-v1.md`. A checked aggregate item means every clause is implemented and covered; partial work stays open and is split below.

### Phase A — contract and low-level seams

- [ ] Approve the remaining public-contract decisions and add compile-only API examples.
  - [x] Implementation has selected behavior for local write completion, context-driven serving, nil authentication, error observation, and disconnect timeout.
  - [ ] Reconcile the frozen contract/examples with the implemented API (`RegisterTyped`, `Config.DGP`, embedded `Context`, send signatures, error names, and hook/auth types), then add compiling examples.
- [x] Add a narrow completed-handshake admission value/callback exposing peer public key, session ID, and address; preserve existing `dgpv1.Server` callers.
- [x] Add context-aware queue admission and write completion internally/compatibly to `dgpv1.Connection`; keep `Connection.Send` unchanged.
- [x] Define and test a precedence table for simultaneous transport, handler, local close, and shutdown terminal causes.

**Acceptance:** low-level seams and compatibility are implemented and current tests pass, but Phase A remains open until the public contract/examples and terminal-cause precedence are settled.

### Phase B — router, context, errors, and unit seam

- [ ] Complete handler types, typed adapters, frozen routing, command routing/groups, middleware compilation, `Context`, immutable metadata, recorder, and dispatch helper.
  - [x] Handler/middleware types, closed-set typed registration, frozen DGP routing, narrow `Context`, defensive snapshots, and a bounded recorder are implemented.
  - [x] Add the codec-neutral SDK command router/groups.
  - [ ] Add the contract-level dispatch helper and reconcile remaining API/error-policy differences.
- [ ] Complete unit coverage for duplicates, wrong generic forms, middleware order/short-circuit, decoder failures, panic recovery, ownership, and send semantics.
  - [x] Tests cover DGP-route duplication/type form, freeze behavior, middleware order/short-circuit, panic conversion, defensive copying, recorder bounds/cancellation, and low-level queue/write semantics.
  - [x] Add decoder/group coverage for command routing.
  - [ ] Add explicit coverage for middleware calling `next` twice and reconciled API semantics.

**Acceptance:** typed DGP handlers and in-memory tests work without crypto/network, but the command-router API and compile-only examples are missing.

### Phase C — admission, hooks, and runtime lifecycle

- [ ] Finish `New`, `Serve`, `Shutdown`, `Close`, authentication, principal propagation, error policy, and exact hooks over `dgpv1`.
  - [x] Runtime construction, one-shot serving, route freeze, context-triggered stop, shutdown escalation, immediate close, completed-handshake authentication, principal propagation, error observation, and hooks are implemented.
  - [x] A static-key allowlist adapter exists.
  - [x] Ensure connect rejection/panic triggers exactly one disconnect hook after active state registration.
  - [x] Complete terminal-cause precedence and exactly-once disconnect coverage; broader lifecycle race coverage remains tracked below.
  - [x] Define and enforce production authorization and identity mapping; `cmd/api_datagram` requires a fail-closed Noise static-key allowlist with unique principals.
- [ ] Complete lifecycle tests for freeze races, the one-`Serve` rule, cancellation, connect rejection/panic, every disconnect path, and shutdown deadline escalation.
  - [x] Real-TCP tests cover authenticate → connect → typed route/response → disconnect, connect rejection/panic isolation, exactly-once disconnect on the normal path, and shutdown escalation.
  - [ ] Add race-tested freeze/mutation, repeated/concurrent `Serve`, root-cancellation outcomes, and an exhaustive abnormal-exit/disconnect matrix.

**Acceptance:** runtime behavior is sufficient for MVP application development and loopback integration, but production lifecycle/authorization evidence is incomplete.

### Phase D — compatibility, examples, and release

- [x] Migrate `cmd/api_datagram` to `pkg/dgpserver` without changing protocol behavior.
  - [x] It uses `dgpserver.New`, typed `EncryptedData` registration, SDK lifecycle/auth/error hooks, and graceful shutdown; the former DGP type assertion/switch is gone.
  - [x] Application commands use the codec-neutral SDK command router; the local `AppMessageType` map was removed.
- [ ] Add echo, authenticated, command-router, middleware, graceful-shutdown, and migration examples.
  - [x] `cmd/api_datagram` is a tested service-migration example with echo/info handlers and graceful shutdown.
  - [ ] Add standalone compiled examples, especially allowlist authentication, SDK command groups, and middleware.
- [ ] Add real-TCP tests, race/stress/leak tests, fuzz registration/config boundaries, and benchmarks for dispatch overhead.
  - [x] SDK real-TCP integration covers authentication, hooks, typed dispatch/response, rejection/panic isolation, and shutdown escalation; `pkg/dgpv1` has parser fuzz targets.
  - [ ] Add automatic-rekey and all-abnormal-exit SDK flows, race/stress/leak suites, SDK registration/config fuzzing, and dispatch benchmarks.

**Acceptance:** direct `dgpv1` users remain source-compatible and `cmd/api_datagram` has migrated, but command routing, documentation/examples, and release evidence are incomplete.

### MVP messenger development boundary

The current code is sufficient to begin MVP messenger application development: DGPv1 framing/Noise/session behavior is implemented; the high-level server authenticates and exposes a principal; typed DGP messages support bounded sends; graceful shutdown exists; and real-TCP integration plus the migrated service exercise the main path.

This is not production-release readiness. Before production, finish authorization policy and static-key-to-application-identity mapping, terminal-cause/hook precedence, command-router/API reconciliation, and race/leak/stress/fuzz/benchmark/release evidence. The race gate remains open because the required run was not possible with the earlier CGO/toolchain.

## Explicit MVP non-goals

Do **not** include in the first release:

- a DI container or dependency registry;
- a global/per-connection mutable state bag;
- reflection-heavy registration, automatic parameter injection, or magic codecs;
- a built-in business payload codec, schema framework, RPC layer, or generated service model;
- dynamic route/middleware/hook mutation after `Serve` starts;
- unbounded queues, silent drops, or background queue expansion;
- listener creation helpers, runtime statistics API, distributed rate limiting,
  session resumption, multiple hook registries, or peer-level delivery acknowledgements.

## Security and reliability release gates

- [ ] Preserve wire compatibility and keep existing vectors/`dgpv1` behavior green.
  - [x] Current wire-vector and `pkg/dgpv1` tests pass at `903fd10`.
  - [ ] Record release evidence that committed vectors and compatibility were not unintentionally changed.
- [ ] Pass `go test ./...`, `go test -race ./... -count=10`, and `go vet ./...`.
  - [x] `go test ./...` and `go vet ./...` pass in this audit.
  - [ ] The race run remains unverified; do not close this gate because the earlier CGO/toolchain could not run it.
- [ ] Demonstrate no races, goroutine/connection leaks, double hooks, or callbacks started after cancellation.
  - [x] The normal admitted real-TCP path asserts one disconnect callback.
  - [ ] Add race/leak/stress coverage and the complete cancellation/abnormal-exit hook matrix.
- [ ] Demonstrate bounded memory under slow peers, full queues, and handshake floods.
  - [x] Queue/admission limits and bounded recorder/connection paths exist with focused tests.
  - [ ] Add sustained slow-peer, saturation, and handshake-flood stress evidence.
- [ ] Demonstrate graceful shutdown under load within its deadline with deterministic escalation.
  - [x] Deadline escalation and network cancellation have focused integration coverage.
  - [ ] Add loaded shutdown/stress coverage and terminal-cause precedence assertions.
- [ ] Ensure authentication errors and panic stacks never leak to peers; redact sensitive logs by default.
  - [x] Local wrapper errors sanitize causes, and authentication/hook/handler panic paths are recovered in focused tests.
  - [ ] Audit peer-visible responses and logging end to end; the migrated command logs remote addresses explicitly.
- [ ] Fuzz/property-test malformed messages, decoder errors, registration conflicts, and shutdown/send races.
  - [x] `pkg/dgpv1` contains malformed-parser fuzz coverage.
  - [ ] Add SDK decoder/registration/config and shutdown/send race fuzz/property tests.
- [ ] Cover authenticate → connect → route → automatic rekey → close and every abnormal exit over real TCP.
  - [x] Real TCP covers authenticate → connect → route/response → close, connect rejection/panic, and shutdown escalation.
  - [ ] Add automatic rekey and an exhaustive abnormal-exit matrix.
- [ ] Complete exported `go doc`, ownership/concurrency text, migration guidance, and compiled examples.
  - [x] Exported SDK symbols have baseline comments and ownership intent is represented in code/tests.
  - [ ] Reconcile docs with the implemented API and add complete compiled examples/migration guidance.
- [ ] Complete dependency review and SBOM; keep the first release experimental until exercised by a real service.
  - [x] `cmd/api_datagram` now exercises the SDK as the repository service migration.
  - [ ] Produce dependency-review/SBOM artifacts and explicit experimental-release evidence.

## Owner decisions before coding

1. **Written-delivery API:** approve `SendAndWait`, or rename it `Write`; both mean local transport write only. Recommendation: `SendAndWait` is explicit and avoids implying direct socket access.
2. **Root context cancellation:** approve `Serve` returning nil after orderly cancellation, rather than `context.Canceled`. Recommendation: nil matches normal server termination while shutdown errors still surface.
3. **Nil authenticator:** approve permissive cryptographic admission with nil principal, or require an explicit allow-all authenticator. Recommendation: permit nil for hello-world, emit clear production documentation.
4. **Nonfatal handler errors:** approve optional sanitized DGP `ErrorMessage` emission by default, or observation-only. Recommendation: observation-only in MVP unless stable application-safe error codes are defined.
5. **Disconnect cleanup timeout:** choose a default (recommend 5 seconds) and whether it is configurable in `Config`.
6. **Command payload typing:** keep `CommandHandler` payload as `any` after an application-owned decoder, or add a second generic adapter. Recommendation: keep the core small for MVP; applications can type-assert once in decoder-specific adapters.

---

## Legacy roadmap retained as detailed work inventory

The sections below are implementation inventory only. Where wording conflicts, the frozen contract above is authoritative.

# DGP Server SDK Roadmap

This document tracks the work required to turn the low-level `pkg/dgpv1` protocol
implementation into a convenient, safe, production-oriented Go server SDK.

The protocol core must remain independent from application concerns. New
high-level functionality should therefore live in `pkg/dgpserver` and build on
`pkg/dgpv1` without changing the DGP v1 wire format.

## Design principles

- **Safe by default:** bounded queues, explicit authentication, context-aware
  blocking, graceful shutdown, and no silently dropped messages.
- **Typed application API:** most server applications should not need type
  switches over `any` or direct access to frames, sessions, or rekeying.
- **Protocol-core isolation:** routing, middleware, logging, and application
  state must not leak into `dgpv1`.
- **Explicit lifecycle:** connect, message, disconnect, and shutdown behavior
  must be deterministic and documented.
- **Composable API:** middleware and handlers should be independently testable.
- **Observable operation:** errors should be classifiable and hooks should make
  metrics and structured logging straightforward.
- **Backward compatibility:** existing `dgpv1.Server`, `Connection`, and
  `Session` users must continue to work.

---

## Phase 0 — Architecture and public API

- [ ] Add `pkg/dgpserver` with package documentation.
- [ ] Define the boundary between `dgpserver` and `dgpv1`.
- [ ] Decide which low-level objects are intentionally exposed through the
      high-level API.
- [ ] Define stable public types:
  - [ ] `Server`
  - [ ] `Config`
  - [ ] `Context`
  - [ ] `Peer`
  - [ ] `Handler`
  - [ ] `Middleware`
  - [ ] lifecycle hook types
- [ ] Define error categories and wrapping rules.
- [ ] Document concurrency guarantees for every public method.
- [ ] Document ownership rules for messages, byte slices, contexts, and peer
      metadata.
- [ ] Add compile-time API examples before implementing runtime behavior.

### Proposed minimal API

```go
srv, err := dgpserver.New(dgpserver.Config{
    StaticKey:     key,
    Authenticator: auth,
})
if err != nil {
    return err
}

srv.Use(loggingMiddleware, metricsMiddleware)
srv.HandleEncryptedData(handleData)
srv.OnConnect(handleConnect)
srv.OnDisconnect(handleDisconnect)

return srv.Serve(ctx, listener)
```

### Acceptance criteria

- A basic server requires no direct `Frame`, `Session`, rekey, replay, or
  transport handling.
- Invalid configuration is rejected by `New` before listening.
- Public concurrency and shutdown semantics are documented and testable.

---

## Phase 1 — Context and peer identity

- [ ] Implement request-scoped `Context` embedding or exposing
      `context.Context`.
- [ ] Expose the active high-level connection through a narrow interface rather
      than requiring direct mutation of `dgpv1.Connection`.
- [ ] Implement immutable `Peer` metadata:
  - [ ] Noise static public key
  - [ ] DGP session ID
  - [ ] remote network address
  - [ ] connection establishment time
  - [ ] authenticated principal, when available
- [ ] Add per-connection application value storage with explicit synchronization
      semantics, or recommend typed closure-owned state instead.
- [ ] Add context helpers:
  - [ ] `TrySend(message any) error`
  - [ ] `Send(ctx context.Context, message any) error`
  - [ ] `Close(code uint16, reason string) error`
  - [ ] connection cancellation/terminal error access
- [ ] Ensure handlers cannot mutate internal peer identity buffers.
- [ ] Test cancellation, concurrent reads, ownership, and send-after-close.

### Acceptance criteria

- Handlers can identify the authenticated peer without inspecting handshake
  internals.
- Every potentially blocking operation accepts or inherits a context.
- Context helpers preserve `dgpv1` queue bounds and error identity.

---

## Phase 2 — Typed router

- [ ] Implement a router that adapts to `dgpv1.MessageHandler`.
- [ ] Provide typed registration methods for MVP application messages:
  - [ ] `HandleEncryptedData`
  - [ ] `HandleAck`
  - [ ] `HandleError`
  - [ ] optional `HandlePing`/`HandlePong` only if exposing protocol-control
        traffic is useful and safe
  - [ ] fallback `HandleMessage`
- [ ] Reject duplicate handler registration unless explicitly replaced.
- [ ] Define behavior for an unhandled message type.
- [ ] Keep protocol-control messages owned by the runtime where appropriate.
- [ ] Ensure handler dispatch is serial per connection, while different
      connections execute independently.
- [ ] Make panic and returned-error behavior explicit.
- [ ] Add table-driven routing and type-safety tests.

### Acceptance criteria

- Normal applications contain no `switch msg := message.(type)` dispatcher.
- Registering a handler for the wrong payload type is impossible through the
  typed methods.
- Unknown/unhandled message behavior is deterministic and observable.

---

## Phase 3 — Middleware

- [ ] Define:

```go
type Handler func(*Context, any) error
type Middleware func(Handler) Handler
```

- [ ] Specify middleware ordering.
- [ ] Build the middleware chain once before serving, not per message.
- [ ] Apply middleware consistently to typed and fallback handlers.
- [ ] Add standard middleware in `pkg/dgpserver/middleware`:
  - [ ] panic recovery
  - [ ] structured request logging
  - [ ] metrics hooks/interfaces
  - [ ] per-peer rate limiting
  - [ ] handler timeout
  - [ ] payload-size/application validation helpers
- [ ] Avoid mandatory dependencies on a specific logger or metrics backend.
- [ ] Ensure middleware cannot accidentally invoke the next handler twice
      without tests detecting it.
- [ ] Add ordering, short-circuit, panic, timeout, and cancellation tests.

### Acceptance criteria

- Cross-cutting behavior requires no edits to application handlers.
- Middleware is concurrency-safe across connections.
- Default middleware does not expose keys, plaintext payloads, or sensitive
  identity material in logs.

---

## Phase 4 — Authentication and authorization

- [ ] Replace high-level whitelist configuration with an extensible interface:

```go
type Authenticator interface {
    Authenticate(context.Context, PeerCredentials) (Principal, error)
}
```

- [ ] Preserve an adapter for static public-key allowlists.
- [ ] Decide whether authentication runs during handshake admission or directly
      after cryptographic authentication; avoid admitting unauthorized peers as
      active application connections.
- [ ] Define a minimal `Principal` contract without forcing application-specific
      user models into the SDK.
- [ ] Add optional authorization middleware for message-level policies.
- [ ] Normalize externally visible authentication failures.
- [ ] Add tests for accepted, rejected, canceled, slow, and panicking
      authenticators.
- [ ] Document trust-store reload and key-rotation patterns.

### Acceptance criteria

- Production servers do not need to preload all client keys into
  `ServerConfig.AllowedClients`.
- Authentication cannot bypass admission limits or leak detailed policy errors
  to unauthenticated clients.

---

## Phase 5 — Lifecycle hooks

- [ ] Add `OnConnect` hook after cryptographic authentication and application
      authentication succeed.
- [ ] Add `OnDisconnect` hook with the terminal cause.
- [ ] Add optional protocol/runtime error observer that cannot alter control
      flow.
- [ ] Define exact ordering:
  - [ ] authenticate
  - [ ] create context
  - [ ] call `OnConnect`
  - [ ] dispatch messages
  - [ ] cancel context
  - [ ] call `OnDisconnect` exactly once
- [ ] Decide what happens when `OnConnect` rejects a connection.
- [ ] Ensure shutdown does not start new hooks or handlers after cancellation.
- [ ] Isolate hook panics and define whether they close only one connection.
- [ ] Add exactly-once and ordering tests for every exit path.

### Acceptance criteria

- Presence/session registries can be implemented without modifying protocol
  internals.
- `OnDisconnect` runs exactly once for local close, remote close, timeout,
  handler failure, and server shutdown.

---

## Phase 6 — High-level server runtime

- [ ] Implement `New(Config) (*Server, error)`.
- [ ] Implement `Serve(context.Context, net.Listener) error`.
- [ ] Optionally provide `ListenAndServe` as a convenience wrapper; keep
      listener creation injectable for tests and deployment flexibility.
- [ ] Map high-level configuration to `dgpv1.ServerConfig`.
- [ ] Add configuration validation and documented defaults for:
  - [ ] handshake timeout
  - [ ] read/write timeout
  - [ ] idle/keepalive policy
  - [ ] outbound and handler queue sizes
  - [ ] concurrent handshakes
  - [ ] active connections
- [ ] Add graceful `Shutdown(ctx)` distinct from immediate `Close()` if the
      semantics can be guaranteed.
- [ ] Return classified errors suitable for `errors.Is`/`errors.As`.
- [ ] Make repeated shutdown calls safe.
- [ ] Expose read-only runtime statistics only after defining consistency and
      cardinality guarantees.

### Acceptance criteria

- Server startup and shutdown fit standard Go service lifecycle patterns.
- A canceled root context stops accepting connections and bounds shutdown time.
- No goroutine, connection, or handler leaks occur across repeated start/stop
  tests.

---

## Phase 7 — Backpressure and delivery API

- [ ] Keep nonblocking `TrySend` semantics.
- [ ] Add a context-aware blocking send without unbounded buffering.
- [ ] Decide whether queue admission or successful network write defines send
      completion; name methods accordingly.
- [ ] Add optional delivery result/future only if applications require it.
- [ ] Define ordering guarantees for concurrent sends.
- [ ] Preserve automatic rekey ordering inside `dgpv1.Connection`.
- [ ] Define behavior when sending from a disconnect hook or canceled handler.
- [ ] Add saturation, cancellation, close-race, and fairness tests.

### Acceptance criteria

- Backpressure is never silently converted into message loss.
- Applications can choose nonblocking or context-bounded sending explicitly.
- Memory remains bounded under slow-client load.

---

## Phase 8 — Observability

- [ ] Define structured event interfaces rather than hard-code a logging stack.
- [ ] Provide metrics for:
  - [ ] accepted/rejected handshakes
  - [ ] active connections
  - [ ] authentication failures
  - [ ] received/sent messages by safe type label
  - [ ] queue saturation
  - [ ] handler duration/failures
  - [ ] keepalive, timeout, replay, AEAD, and rekey failures
- [ ] Avoid unbounded labels such as raw peer key, session ID, or remote address.
- [ ] Add optional connection/session correlation IDs safe for logs.
- [ ] Redact payloads and cryptographic material by default.
- [ ] Document recommended operational alerts.

### Acceptance criteria

- Operators can distinguish protocol attacks, unhealthy clients, application
  failures, and capacity saturation.
- Enabling observability does not change protocol behavior.

---

## Phase 9 — Examples and documentation

- [ ] Add `examples/echo-server` using typed handlers.
- [ ] Add an authenticated server example.
- [ ] Add middleware composition example.
- [ ] Add graceful shutdown example.
- [ ] Add package-level documentation with a minimal runnable server.
- [ ] Document:
  - [ ] concurrency model
  - [ ] handler lifecycle
  - [ ] error handling
  - [ ] backpressure
  - [ ] authentication/trust model
  - [ ] key storage and rotation
  - [ ] deployment timeouts and limits
- [ ] Add a migration guide from direct `dgpv1.Server` usage.
- [ ] Keep examples free of embedded production secrets.

### Acceptance criteria

- A developer can build a safe echo server by reading one package example.
- Documentation clearly separates transport authentication from application
  authorization.

---

## Phase 10 — Verification and release readiness

- [ ] Unit tests for every public API contract and error path.
- [ ] Integration tests using real TCP listeners, not only `net.Pipe`.
- [ ] Race-detector suite for routing, middleware, hooks, send, and shutdown.
- [ ] Stress tests with many concurrent connections and slow consumers.
- [ ] Stateful tests covering connect → authenticate → route → rekey → close.
- [ ] Leak tests for goroutines and blocked handlers.
- [ ] Fuzz registration/configuration boundaries where useful.
- [ ] Benchmarks for dispatch and middleware overhead.
- [ ] Run:

```text
go test ./...
go test -race ./... -count=10
go vet ./...
```

- [ ] Verify all exported declarations with `go doc`.
- [ ] Review dependencies and generated SBOM before release.
- [ ] Tag the first high-level SDK as experimental until used by at least one
      real Datagram service.

### Release gate

- No known correctness or race defects.
- Clean shutdown under load within the configured deadline.
- Bounded memory under queue saturation and slow-client tests.
- Typed API example and migration documentation complete.
- Public API reviewed before compatibility guarantees are declared.

---

## Initial implementation slice

The first implementation should remain deliberately small:

- [x] Create `pkg/dgpserver`.
- [x] Implement `Context` and immutable `Peer`.
- [x] Implement typed routing for `EncryptedData`, `Ack`, and `ErrorMessage`.
- [x] Implement middleware composition.
- [x] Implement `OnConnect` and `OnDisconnect` exactly-once hooks.
- [x] Adapt the router to the existing `dgpv1.Server`.
- [x] Add a real-TCP echo integration test.
- [ ] Add a minimal package example.

Features intentionally deferred from the first slice:

- blocking delivery acknowledgements;
- runtime statistics API;
- dynamic route mutation after serving starts;
- distributed rate limiting;
- protocol resumption support;
- generic application RPC semantics.

## Configuration series
- [x] Add the typed Viper loader and fully migrate api_datagram.
- [ ] Migrate api_bot, auth, and user when those command entrypoints gain runtime configuration.

## CI quality series
- [x] Add reproducible GitHub Actions checks for formatting, modules, vet, build, tests, race detection, and coverage.
- [x] Add focused golangci-lint configuration.
- [x] Add govulncheck and fork-safe, read-only secret scanning.
- [x] Document the coverage scope, threshold, artifacts, and action update policy.
- [ ] Add continuous deployment only after the deployment target and release policy are defined.
