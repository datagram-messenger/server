# DGP High-Level Go Server SDK — implementation contract

This document is the implementation-ready contract for `pkg/dgpserver`, an ergonomic server SDK over `pkg/dgproto`. The protocol core remains responsible for framing, Noise, sessions, replay protection, rekeying, keepalive, and connection I/O. Existing `dgproto` APIs and the DGP v1 wire format remain compatible.

## Design review of the existing roadmap

The earlier roadmap had sound safety goals, but left too much architecture for implementation time:

- Its proposed `func(*Context, any) error` handler forced application type switches. `cmd/api_datagram` now uses typed DGP registration and the SDK command router after its migration.
- Protocol-message routing was described, but codec-neutral routing of commands inside `EncryptedData` was not designed.
- `Context` risked becoming a synchronized state bag/service locator instead of a narrow request and connection capability.
- Listener creation/closure, root cancellation, graceful shutdown, immediate close, repeat calls, and `Serve` return values were not one precise state machine.
- Low-level `Connection.Send` means nonblocking queue admission, while the roadmap did not settle names for queued versus written delivery.
- Authentication timing, principal lifetime, hook rejection/panic paths, and exactly-once disconnect behavior were underspecified.
- Runtime route mutation and configuration freezing were unresolved, creating avoidable race risk.
- Testing still required crypto/TCP because there was no in-memory dispatch/recorder seam.
- Ten feature phases mixed essential MVP design with a large optional middleware/observability catalog.

The contract below closes those gaps. The implemented owner decisions and API reconciliation are recorded below.

## Future application payload format (deferred; not normative MVP)

- [ ] After a separate design/spec review, define Protobuf as the planned primary business/application payload format, with application data serialized from Protobuf messages. This is explicitly **not** a DGProto v1 wire-format change: encoded Protobuf bytes belong inside the `EncryptedData` payload, while the current codec-neutral SDK and compatibility remain intact. The review must define schema ownership, versioning and evolution, unknown-field behavior, size/resource limits, security validation, and cross-language compatibility vectors before implementation. Protobuf is not part of the current normative MVP.

## Frozen public API contract

### Handler, typed adapter, and DGP routing

```go
type Handler interface {
    Handle(*Context, any) error
}

type HandlerFunc func(*Context, any) error
func (f HandlerFunc) Handle(c *Context, m any) error

type ApplicationMessage interface {
    dgproto.EncryptedData | dgproto.Ack | dgproto.ErrorMessage
}
type TypedHandlerFunc[T ApplicationMessage] func(*Context, *T) error
type Middleware func(Handler) Handler

// Generic methods are unavailable in Go; use a package function.
func Handle[T ApplicationMessage](r *Router, h TypedHandlerFunc[T]) error
func RegisterTyped[T ApplicationMessage](r *Router, h TypedHandlerFunc[T]) error

func (r *Router) Use(...Middleware) error
func (r *Router) HandleEncryptedData(TypedHandlerFunc[dgproto.EncryptedData]) error
func (r *Router) HandleAck(TypedHandlerFunc[dgproto.Ack]) error
func (r *Router) HandleError(TypedHandlerFunc[dgproto.ErrorMessage]) error
```

`Router{}` is ready for registration. `Handle[T]` accepts only the closed inbound application-visible set `dgproto.EncryptedData`, `dgproto.Ack`, and `dgproto.ErrorMessage`; pointer type arguments, unsupported types, nil handlers, and duplicates return configuration errors. Ping/pong, close, and rekey remain runtime-owned in MVP. The checked assertion lives in the adapter, never in application handlers.

Registration is ordered, is not concurrency-safe, and is legal only before serving. Duplicate routes return `ErrDuplicateHandler`; there is no implicit replacement. The default unhandled route returns `ErrNotHandled`, which is observed but is nonfatal.

The module declares Go 1.25, so generic type declarations/functions are available. A generic registration function is the practical alternative to an impossible generic `Server` method.

### Hello-world (15 lines)

```go
func run(ctx context.Context, ln net.Listener, key dgproto.StaticKey) error {
    r := new(dgpserver.Router)
    _ = r.HandleEncryptedData(func(c *dgpserver.Context, m *dgproto.EncryptedData) error {
        return c.TrySend(&dgproto.EncryptedData{
            StreamID: m.StreamID, AppMessageType: m.AppMessageType, Fields: m.Fields,
        })
    })
    s, err := dgpserver.New(dgpserver.Config{
        DGP: dgproto.ServerConfig{StaticKey: key}, Router: r,
    })
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
    DGP               dgproto.ServerConfig
    Router            *Router
    Authenticator     Authenticator
    ErrorHandler      ErrorHandler
    OnConnect         func(context.Context, ConnectionInfo) error
    OnDisconnect      func(context.Context, ConnectionInfo, error)
    DisconnectTimeout time.Duration
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
type Context struct {
    context.Context
    // other fields are unexported
}
func (c *Context) Peer() Peer
func (c *Context) Principal() Principal
func (c *Context) Params() Params
func (c *Context) Metadata() Metadata
func (c *Context) TrySend(any) error
func (c *Context) Send(any) error
func (c *Context) SendAndWait(any) error
func (c *Context) Close() error

type Peer struct { /* unexported */ }
func NewPeer(address string, sessionID [16]byte, identity []byte) Peer
func (p Peer) Address() string
func (p Peer) SessionID() [16]byte
func (p Peer) Identity() []byte

type Params struct { /* unexported */ }
func NewParams(map[string]string) Params
func (p Params) Get(string) (string, bool)
func (p Params) All() map[string]string

type Metadata struct { /* unexported */ }
func NewMetadata(dgproto.MessageType, time.Time) Metadata
func (m Metadata) MessageType() dgproto.MessageType
func (m Metadata) ReceivedAt() time.Time
```

`Context` is one inbound invocation. Its Go context derives from the connection and is canceled on disconnect/shutdown. It is not a service locator: no `Set/Get`, global bag, raw `*dgproto.Connection`, `Session`, frame, or traffic secrets. Dependencies are captured in typed closures.

Peer, principal, params, and metadata are immutable snapshots. Accessors clone slices; peer identity bytes are defensively copied. Inbound messages and nested slices are valid for the handler call and must be copied before retention/mutation. An outbound message must not be mutated while a send call is in progress.

### Backpressure: queued versus written

- `TrySend` is nonblocking. Success means accepted into the bounded per-connection FIFO; full returns `dgproto.ErrOutboundQueueFull`.
- `Send(m)` waits for bounded queue capacity using the embedded handler context. Success still means **queued**, not written; cancellation returns that context error.
- `SendAndWait(m)` uses the embedded handler context and waits until the frame and any preceding automatic rekey are fully written. It does not mean peer receipt or business acknowledgement.
- Concurrent sends are ordered by successful queue admission; no stronger ordering is promised.
- Once connection termination wins, sends return `dgproto.ErrConnectionClosed`; a receive-only or disconnect context has no send capability and returns `ErrRecorderClosed`.
- `Close` uses a dedicated control path and is not trapped behind a full application queue.
- Inbound handler-queue overflow remains terminal; queues are never unbounded and messages are never silently dropped.

Implement this with a compatible extension to `dgproto.Connection` for context-aware enqueue and per-item write completion, not a second high-level queue. Preserve existing `Connection.Send` behavior.

### Codec-neutral command router and groups

```go
type Command uint8

type CommandDecoder interface {
    DecodeCommand(*dgproto.EncryptedData) (Command, any, error)
}
type CommandDecoderFunc func(*dgproto.EncryptedData) (Command, any, error)

// Command routes reuse Handler/HandlerFunc. The message argument is the
// decoder result, so ordinary Middleware composes without another handler kind.
func NewCommandRouter(CommandDecoder) *CommandRouter
func (r *CommandRouter) Handle(Command, Handler) error
func (r *CommandRouter) Group(func(*CommandGroup) error) error
func (g *CommandGroup) Use(...Middleware) error
func (g *CommandGroup) Handle(Command, Handler) error
func (r *CommandRouter) Handler() TypedHandlerFunc[dgproto.EncryptedData]
```

The SDK selects no payload codec. A decoder may route directly on `AppMessageType`, inspect TLVs, or decode an application struct:

```go
commands := dgpserver.NewCommandRouter(dgpserver.CommandDecoderFunc(
    func(m *dgproto.EncryptedData) (dgpserver.Command, any, error) {
        return dgpserver.Command(m.AppMessageType), m, nil
    }))
_ = commands.Handle(1, dgpserver.HandlerFunc(
    func(c *dgpserver.Context, payload any) error {
        return c.TrySend(payload.(*dgproto.EncryptedData))
    }))
_ = router.HandleEncryptedData(commands.Handler())
```

Groups are registration-time policy scopes, justified for authorization, logging, and rate limits; they are not URL trees. Duplicate command IDs across groups conflict. Global/router middleware wraps group middleware. For `Use(A, B)` and group `Use(C)`, ordering is `A before → B before → C before → handler → C after → B after → A after`. Chains are built once at freeze time.

### Errors, middleware, and panic policy

```go
type ErrorKind uint8
const (
    ErrorKindHandler ErrorKind = iota + 1
    ErrorKindPanic
)

type HandlerError struct {
    Kind ErrorKind
    Err  error
}
func (e *HandlerError) Error() string
func (e *HandlerError) Unwrap() error

type ErrorHandler func(*Context, error) error

type OpError struct { Op string; Err error }
func (e *OpError) Error() string
func (e *OpError) Unwrap() error
```

Sentinels: `ErrServerStarted`, `ErrDuplicateHandler`, `ErrNilHandler`, `ErrUnsupportedMessage`, `ErrInvalidMessageForm`, `ErrNotHandled`, `ErrHandlerPanic`, `ErrRecorderFull`, `ErrRecorderClosed`, and `ErrUnauthenticated`; transport queue/connection errors remain in `dgproto`. Sensitive identity is excluded from formatted error strings. All errors remain usable with `errors.Is/As`.

Returned handler/decoder errors reach the single configured `ErrorHandler` exactly once. Default policy: observe and continue for `ErrNotHandled`; sanitize and optionally send `dgproto.ErrorMessage` for nonfatal `*HandlerError`; close one connection for fatal errors, invariant failures, and panics. Never send raw internal/authentication errors.

An unremovable outer recovery boundary converts panic into an error wrapping `ErrHandlerPanic`; stack data is local-only. User recovery middleware may customize observation, not disable safety. `ErrorHandler` panic is itself recovered and closes the connection. Middleware may call `next` at most once; enforce this as a documented/tested contract without reflection.

```go
func requestLog(log *slog.Logger) dgpserver.Middleware {
    return func(next dgpserver.Handler) dgpserver.Handler {
        return dgpserver.HandlerFunc(func(c *dgpserver.Context, m any) error {
            started := time.Now()
            err := next.Handle(c, m)
            log.InfoContext(c, "dgp", "type", c.Metadata().MessageType(),
                "duration", time.Since(started), "err", err)
            return err
        })
    }
}
```

### Authentication boundary and principal

```go
type Credentials struct {
    PeerStatic [32]byte
    SessionID  [16]byte
    RemoteAddr string
}
type Principal any
type Authenticator interface {
    Authenticate(context.Context, Credentials) (Principal, error)
}
type AuthenticatorFunc func(context.Context, Credentials) (Principal, error)
```

Noise first authenticates the client static key. The SDK then calls `Authenticator` while admission capacity is held but before active registration, hooks, or application dispatch. Nil authenticator admits every cryptographically valid peer with nil principal and must be called out in production documentation. Supply a static-key allowlist adapter.

Rejection maps locally to `ErrUnauthenticated`, closes without policy details, and invokes neither hook. Principal is immutable and exposed through `Context.Principal`; authorization is middleware with closure-injected policy.

The low-level seam should expose only completed-handshake peer public key/session identity to the adapter—never mutable `Session` or handshake/traffic secrets.

### Hooks: exact ordering and exactly once

```go
type ConnectionInfo struct {
    Peer      Peer
    Principal Principal
}
// Config uses these function signatures directly:
// OnConnect func(context.Context, ConnectionInfo) error
// OnDisconnect func(context.Context, ConnectionInfo, error)
```

For each transport: finish Noise → authenticate → reserve/register active connection and create context → call `OnConnect` once → dispatch serially → stop new handlers and cancel connection context → wait for current handler → call `OnDisconnect` once with terminal cause and a detached timeout-bounded cleanup context → release slot.

Authentication rejection invokes neither hook. Once active registration succeeds, disconnect runs exactly once even if connect returns an error or panics. Connect failure prevents dispatch. Hook panics are recovered and close only that connection. No new connect hook starts after shutdown closes admission. Disconnect cannot send. MVP has one hook of each type; applications explicitly compose multiple callbacks, avoiding ambiguous failure ordering.

### In-memory testing without crypto/TCP

```go
type Recorder struct { /* concurrency-safe */ }
func NewRecorder(capacity int) *Recorder
func (r *Recorder) NewContext(context.Context, Peer, Metadata, Params) *Context
func (r *Recorder) Snapshot() []RecordedSend
func (r *Recorder) Drain() []RecordedSend
func (r *Recorder) Close() error
func Dispatch(context.Context, Handler, Peer, Principal, any) error
```

`Recorder` implements bounded send/close behavior without TCP, Noise, goroutines, or timers; snapshots are defensive. `Dispatch` exercises routing/middleware when reply assertions are unnecessary.

```go
func TestEcho(t *testing.T) {
    rec := dgpserver.NewRecorder(1)
    c := rec.NewContext(context.Background(), dgpserver.Peer{}, dgpserver.Metadata{}, dgpserver.Params{})
    err := echo(c, &dgproto.EncryptedData{AppMessageType: 1})
    if err != nil || len(rec.Snapshot()) != 1 { t.Fatal(err) }
}
```

Integration tests still use real loopback TCP plus a `dgproto` client for handshake, authentication, rekey, deadlines, saturation, and shutdown.

## MVP implementation phases

Audit basis: `HEAD` `ac8fd30`, the current `pkg/dgpserver`, `pkg/dgproto`, and `cmd/api_datagram` code/tests, plus `docs/protocol/dgp-v1.md` and `docs/dgpserver/`. A checked aggregate item means every clause is implemented and covered; partial work stays open and is split below.

Static-analysis audit: the repository and CI use golangci-lint v2 configuration, with CI pinned to v2.11.4. That release does not expose linters named `waitgroupgo` or `rangeint`; their supported equivalents are the revive rule `use-waitgroup-go` and the `intrange` linter. Both are enabled in `.golangci.yml`. Validation with `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4 config verify`, a focused `intrange,revive` run, and the full configured repository run completed successfully with zero issues. The final working-copy audit also passed `gofmt -l .` with no output, `go test ./...`, `go vet ./...`, the pinned full golangci-lint v2.11.4 run with zero issues, and `git diff --check`. The native `go test -race ./...` attempt was blocked because `CGO_ENABLED=0`; Windows reported `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1`, and no `gcc` executable was available, so the CGO-enabled retry could not run without installing a toolchain. No CI pin update or benchmark-loop change was required.

### Phase A — contract and low-level seams

- [x] Approve the remaining public-contract decisions and add compile-only API examples.
  - [x] Implementation has selected behavior for local write completion, context-driven serving, nil authentication, error observation, and disconnect timeout.
  - [x] Reconcile the frozen contract/examples with the implemented API (`Config.DGP`, embedded `Context`, send signatures, error names, and hook/auth types).
  - [x] Add the contract-level generic `Handle` function, typed router registration methods, and compiling router/command-router examples while preserving `RegisterTyped`.
- [x] Add a narrow completed-handshake admission value/callback exposing peer public key, session ID, and address; preserve existing `dgproto.Server` callers.
- [x] Add context-aware queue admission and write completion internally/compatibly to `dgproto.Connection`; keep `Connection.Send` unchanged.
- [x] Define and test a precedence table for simultaneous transport, handler, local close, and shutdown terminal causes.

**Acceptance:** low-level seams and compatibility are implemented and current tests pass, and the frozen public contract and compile-only examples now match the implemented API.

### Phase B — router, context, errors, and unit seam

- [ ] Complete handler types, typed adapters, frozen routing, command routing/groups, middleware compilation, `Context`, immutable metadata, recorder, and dispatch helper.
  - [x] Handler/middleware types, closed-set typed registration, frozen DGP routing, narrow `Context`, defensive snapshots, and a bounded recorder are implemented.
  - [x] Add the codec-neutral SDK command router/groups.
  - [x] Add the contract-level dispatch helper; API and error-policy reconciliation is complete in Phase A.
- [ ] Complete unit coverage for duplicates, wrong generic forms, middleware order/short-circuit, decoder failures, panic recovery, ownership, and send semantics.
  - [x] Tests cover DGP-route duplication/type form, freeze behavior, middleware order/short-circuit, panic conversion, defensive copying, recorder bounds/cancellation, and low-level queue/write semantics.
  - [x] Add decoder/group coverage for command routing.
  - [x] Add explicit coverage for middleware calling `next` twice.
  - [x] Reconcile remaining API semantics in Phase A.

**Acceptance:** typed DGP and command handlers plus in-memory tests work without crypto/network; public API reconciliation is complete in Phase A.

### Phase C — admission, hooks, and runtime lifecycle

- [ ] Finish `New`, `Serve`, `Shutdown`, `Close`, authentication, principal propagation, error policy, and exact hooks over `dgproto`.
  - [x] Runtime construction, one-shot serving, route freeze, context-triggered stop, shutdown escalation, immediate close, completed-handshake authentication, principal propagation, error observation, and hooks are implemented.
  - [x] A static-key allowlist adapter exists.
  - [x] Ensure connect rejection/panic triggers exactly one disconnect hook after active state registration.
  - [x] Complete terminal-cause precedence and exactly-once disconnect coverage; broader lifecycle race coverage remains tracked below.
  - [x] Define and enforce production authorization and identity mapping; `cmd/api_datagram` requires a fail-closed Noise static-key allowlist with unique principals.
- [ ] Complete lifecycle tests for freeze races, the one-`Serve` rule, cancellation, connect rejection/panic, every disconnect path, and shutdown deadline escalation.
  - [x] Real-TCP tests cover authenticate → connect → typed route/response → disconnect, connect rejection/panic isolation, exactly-once disconnect on the normal path, and shutdown escalation.
  - [x] Add deterministic freeze/mutation, repeated/concurrent `Serve`, and root-cancellation outcome coverage; race execution remains skipped by prior user instruction.
  - [ ] Add an exhaustive abnormal-exit/disconnect matrix.

**Acceptance:** runtime behavior is sufficient for MVP application development and loopback integration, but production lifecycle evidence is incomplete.

### Phase D — compatibility, examples, and release

- [x] Migrate `cmd/api_datagram` to `pkg/dgpserver` without changing protocol behavior.
  - [x] It uses `dgpserver.New`, typed `EncryptedData` registration, SDK lifecycle/auth/error hooks, and graceful shutdown; the former DGP type assertion/switch is gone.
  - [x] Application commands use the codec-neutral SDK command router; the local `AppMessageType` map was removed.
- [ ] Add echo, authenticated, command-router, middleware, graceful-shutdown, and migration examples.
  - [x] `cmd/api_datagram` is a tested service-migration example with echo/info handlers and graceful shutdown.
  - [x] Add standalone compiled typed-router and SDK command-router examples.
  - [x] Add standalone compiled allowlist-authentication, command-group, middleware, and graceful-shutdown examples; `cmd/api_datagram` remains the compiled migration example.
- [ ] Add real-TCP tests, race/stress/leak tests, fuzz registration/config boundaries, and benchmarks for dispatch overhead.
  - [x] SDK real-TCP integration covers authentication, hooks, typed dispatch/response, rejection/panic isolation, and shutdown escalation; `pkg/dgproto` has parser fuzz targets.
  - [x] Add deterministic dispatch-overhead benchmarks for a direct handler, the `Dispatch` helper, frozen typed routing, middleware, and command routing; record a reproducible machine-specific baseline.
  - [x] Add deterministic SDK registration/config fuzzing for bounded Config/New, typed Router, and CommandRouter registration states.
  - [ ] Add automatic-rekey and all-abnormal-exit SDK flows plus race/stress/leak suites.

**Acceptance:** direct `dgproto` users remain source-compatible, `cmd/api_datagram` has migrated, and developer documentation/examples exist; broader release evidence is incomplete.

### MVP messenger development boundary

The current code is sufficient to begin MVP messenger application development: DGProto v1 framing/Noise/session behavior is implemented; the high-level server authenticates and exposes a principal; typed DGP messages support bounded sends; graceful shutdown exists; and real-TCP integration plus the migrated service exercise the main path.

This is not production-release readiness. Before production, finish automatic-rekey/abnormal-exit coverage plus race/leak/stress/fuzz/release evidence. The race gate remains open because the required run was not possible with the earlier CGO/toolchain.

### Production-readiness progress estimate

Approximately **48% of the work remains** before production readiness. A pinned, application-scoped CycloneDX SBOM target and CI artifact now provide repeatable dependency inventory evidence; dependency review remains partially open because the standalone protocol module has no explicit license file. Integer range-loop modernization is a completed quality cleanup with no wire or user-facing semantic change. Deterministic shutdown/send property coverage is now complete. The focused race attempt is recorded below, but the broader race/leak/stress gate remains open pending toolchain support, repeated whole-suite race evidence, loaded shutdown/slow-peer/handshake-flood stress, and leak accounting; automatic-rekey and abnormal-exit integration, wire-compatibility release evidence, security/logging review, and dependency/SBOM work also remain.

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

- [ ] Preserve wire compatibility and keep existing vectors/`dgproto` behavior green.
  - [x] Current wire-vector and `pkg/dgproto` tests pass at `ac8fd30`.
  - [ ] Record release evidence that committed vectors and compatibility were not unintentionally changed.
- [ ] Pass `go test ./...`, `go test -race ./... -count=10`, and `go vet ./...`.
  - [x] `go test ./...` and `go vet ./...` pass in this audit.
  - [ ] Focused race attempt on `pkg/dgpserver` and `pkg/dgproto` failed exactly with `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1`; keep this gate open.
- [ ] Demonstrate no races, goroutine/connection leaks, double hooks, or callbacks started after cancellation.
  - [x] The normal admitted real-TCP path asserts one disconnect callback.
  - [ ] Add race/leak/stress coverage and the complete cancellation/abnormal-exit hook matrix.
- [ ] Demonstrate bounded memory under slow peers, full queues, and handshake floods.
  - [x] Queue/admission limits and bounded recorder/connection paths exist with focused tests.
  - [ ] Add sustained slow-peer, saturation, and handshake-flood stress evidence.
- [ ] Demonstrate graceful shutdown under load within its deadline with deterministic escalation.
  - [x] Deadline escalation and network cancellation have focused integration coverage.
  - [ ] Add loaded shutdown/stress coverage.
- [ ] Ensure authentication errors and panic stacks never leak to peers; redact sensitive logs by default.
  - [x] Local wrapper errors sanitize causes, and authentication/hook/handler panic paths are recovered in focused tests.
  - [ ] Audit peer-visible responses and logging end to end; the migrated command logs remote addresses explicitly.
- [ ] Fuzz/property-test malformed messages, decoder errors, registration conflicts, and shutdown/send races.
  - [x] `pkg/dgproto` contains malformed-parser fuzz coverage.
  - [x] Add bounded deterministic SDK registration/config fuzz/property tests.
  - [x] Add deterministic SDK decoder-error table/property/fuzz coverage, including runtime `ErrorHandler` propagation.
  - [x] Add deterministic shutdown/send race property tests covering send variants, cancellation/terminal precedence, waiter release, close idempotence, control-close priority, handler/disconnect rejection, and stable terminal cause.
- [ ] Cover authenticate → connect → route → automatic rekey → close and every abnormal exit over real TCP.
  - [x] Real TCP covers authenticate → connect → route/response → close, connect rejection/panic, and shutdown escalation.
  - [ ] Add automatic rekey and an exhaustive abnormal-exit matrix.
- [ ] Complete exported `go doc`, ownership/concurrency text, migration guidance, and compiled examples.
  - [x] Exported SDK symbols have baseline comments and ownership intent is represented in code/tests.
  - [x] Add the `docs/dgpserver` developer guide, reconcile it with the implemented API, link it from package/root docs, and add compiled examples plus migration guidance.
- [ ] Complete dependency review and SBOM; keep the first release experimental until exercised by a real service.
  - [x] `cmd/api_datagram` now exercises the SDK as the repository service migration.
  - [x] Add a pinned CycloneDX SBOM target, CI artifact, and documented dependency/license review.
  - [ ] Add an explicit reviewed license to the standalone protocol module and retain SBOM/review evidence with the first experimental release.

## Implemented owner decisions

1. **Written-delivery API:** `SendAndWait` means local transport write completion only.
2. **Root context cancellation:** `Serve` returns nil after orderly context-driven shutdown.
3. **Nil authenticator:** nil permits cryptographically valid peers with a nil principal; production guidance requires an explicit trust policy.
4. **Nonfatal handler errors:** the default policy is observation-only unless the application defines safe wire error codes.
5. **Disconnect cleanup timeout:** `Config.DisconnectTimeout` is configurable and defaults to 5 seconds.
6. **Command payload typing:** application-owned decoders return `any`; the SDK does not add a second generic command adapter.

---

## Legacy roadmap retained as detailed work inventory

The sections below are implementation inventory only. Where wording conflicts, the frozen contract above is authoritative.

# DGP Server SDK Roadmap

This document tracks the work required to turn the low-level `pkg/dgproto` protocol
implementation into a convenient, safe, production-oriented Go server SDK.

The protocol core must remain independent from application concerns. New
high-level functionality should therefore live in `pkg/dgpserver` and build on
`pkg/dgproto` without changing the DGP v1 wire format.

## Design principles

- **Safe by default:** bounded queues, explicit authentication, context-aware
  blocking, graceful shutdown, and no silently dropped messages.
- **Typed application API:** most server applications should not need type
  switches over `any` or direct access to frames, sessions, or rekeying.
- **Protocol-core isolation:** routing, middleware, logging, and application
  state must not leak into `dgproto`.
- **Explicit lifecycle:** connect, message, disconnect, and shutdown behavior
  must be deterministic and documented.
- **Composable API:** middleware and handlers should be independently testable.
- **Observable operation:** errors should be classifiable and hooks should make
  metrics and structured logging straightforward.
- **Backward compatibility:** existing `dgproto.Server`, `Connection`, and
  `Session` users must continue to work.

---

## Phase 0 — Architecture and public API

- [ ] Add `pkg/dgpserver` with package documentation.
- [ ] Define the boundary between `dgpserver` and `dgproto`.
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
      than requiring direct mutation of `dgproto.Connection`.
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
- Context helpers preserve `dgproto` queue bounds and error identity.

---

## Phase 2 — Typed router

- [ ] Implement a router that adapts to `dgproto.MessageHandler`.
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
- [ ] Map high-level configuration to `dgproto.ServerConfig`.
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
- [ ] Preserve automatic rekey ordering inside `dgproto.Connection`.
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
- [ ] Add a migration guide from direct `dgproto.Server` usage.
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
- [x] Benchmarks for dispatch and middleware overhead.
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
- [x] Adapt the router to the existing `dgproto.Server`.
- [x] Add a real-TCP echo integration test.
- [x] Add a minimal package example.

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

## Release delivery pipeline

- [x] Add a tag-only GitHub Release workflow with strict `vMAJOR.MINOR.PATCH` validation and least privileges.
- [x] Cross-compile only the runnable `api_datagram` service for the supported Linux, Windows, and macOS targets.
- [x] Produce documented archives and mandatory `SHA256SUMS` through the locally reproducible release script.
- [x] Expose and test release version metadata through `-version`.
- [ ] Define target infrastructure, operational ownership, and credentials before adding any production deployment.

## Go 1.25 and DGProto v1 audit (current tree)

Audit basis: all 65 Go source/test files at `f71984f`, `docs/protocol/dgp-v1.md`, and `docs/dgpserver/`; implementation code was not changed by this audit.

### Go 1.25 modernization

- [x] Replace the audited manual `WaitGroup.Add(1)` + goroutine + deferred `Done` ownership with `WaitGroup.Go` at `pkg/dgpserver/dgpserver_test.go`, `pkg/dgpserver/shutdown_send_property_test.go`, `pkg/dgproto/rekey_test.go`, `pkg/dgproto/send_shutdown_property_test.go`, `pkg/dgproto/server.go`, `pkg/dgproto/session_test.go`, and `pkg/dgproto/tcp_test.go`. The production server still registers each accepted transport before launching its owned goroutine, and `Close` waits for the same handler lifecycle; no protocol path changed.
- [x] Review the aggregate lifecycle accounting in `pkg/dgproto/connection.go`. The original `Add(loops)` count corresponded one-for-one to the read, write, maintenance, and optional handler goroutines, and each loop's only `Done` was its entry defer. Replacing those launches with `WaitGroup.Go` is therefore equivalent: the same loops are included before the waiter starts, loop-local cleanup remains unchanged, and shutdown still occurs only after all runtime loops return.
- [x] Replace the audited equivalent zero-based exclusive counting loops in `pkg/dgproto/audit_test.go` and `pkg/dgproto/send_api_test.go` with range-over-int. The inclusive replay-window loop in `pkg/dgproto/session_test.go` was intentionally retained because a direct `range ReplayWindowSize` rewrite would change its boundary.
- [x] Enable the golangci-lint v2.11.4 equivalents of `waitgroupgo` and `rangeint`: revive rule `use-waitgroup-go` and linter `intrange`. The full configured repository run completed with zero issues; no benchmark-loop change was required.

### Protocol contract review

No provable implementation/specification mismatch was found in the audited framing and wire encoding, handshake profile/session-ID derivation, directional keys/nonces, state transitions, reserved-header/AAD handling, replay window, rekey transition/grace rules, close semantics, message registry, or bounded runtime paths. Two specification gaps should still be closed before compatibility guarantees are declared; they are not recorded as implementation defects because the current normative text does not state the opposite behavior:

- [ ] Specify the protocol-wide maximum frame size. The normative header carries a `uint32` payload length and defines frame-size arithmetic without an explicit maximum (`docs/protocol/dgp-v1.md:131-170`), while `pkg/dgproto/header.go:15-16` fixes `MaxFrameSize = 65535` and `pkg/dgproto/header.go:118-120` rejects larger frames. Document the intended limit and compatibility requirement before any implementation change.
- [ ] Specify whether duplicate application TLV types are permitted. The generic TLV envelope scopes identifiers to the enclosing message but does not define duplicate handling (`docs/protocol/dgp-v1.md:83-103`); `EncryptedData` rejects duplicates on send and receive (`pkg/dgproto/messages.go:222-255`, `pkg/dgproto/messages.go:296-305`). Resolve the normative ambiguity before changing parser behavior or vectors.

### Verification snapshot

- Modernization remediation: `gofmt` was applied only to the ten changed Go files; `gofmt -l` reports none of those files.
- Modernization remediation: `go test ./pkg/dgpserver ./pkg/dgproto` and `go vet ./pkg/dgpserver ./pkg/dgproto` pass (exit 0).
- Earlier audit: `go test ./...`, `go vet ./...`, and focused `go vet -waitgroup ./...` passed on Go 1.26.5 windows/amd64.
- `go test -race ./...`: not run successfully; exact toolchain error was `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1` (`CGO_ENABLED=0`). On Windows, `where gcc` found no compiler, so the requested CGO-enabled retry was unavailable without installing a toolchain. Keep the race release gate open.
- `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4 run ./...` completed with zero issues, including `intrange` and revive `use-waitgroup-go`.

## Completed maintenance

- [x] Re-validated the integer-loop modernization with the configured `intrange` analyzer; the full pinned golangci-lint run passed with zero issues.
- [x] Corrected the Go module and internal import paths by removing the erroneous `.git` suffix.
