# AGENTS.md

## Project overview

Datagram is a serious, production-oriented messenger.

- The backend is implemented in Go as a set of microservices.
- The desktop client/frontend is implemented in Rust using Tauri v2.
- This repository contains the Go backend and the DGPv1 protocol implementation.
- DGPv1 is a purpose-built protocol designed for fast, efficient messenger communication.
- The normative protocol specification is in `docs/protocol/`, currently `docs/protocol/dgp-v1.md`.

Treat this codebase as security-sensitive infrastructure. Correctness, wire compatibility, security, operability, and maintainability take priority over delivery speed.

## Sources of truth

Before changing protocol behavior, read `docs/protocol/dgp-v1.md` and the relevant implementation and tests under `pkg/dgpv1/`.

For protocol work:

1. The normative specification defines intended wire behavior.
2. Tests and wire vectors protect compatibility and document edge cases.
3. Implementation must agree with both.
4. If the specification is ambiguous or conflicts with established vectors, do not silently choose an interpretation. Clearly identify the conflict and resolve it explicitly in code, tests, and documentation.

Do not introduce undocumented protocol extensions, compatibility breaks, new cryptographic constructions, or changes to the wire format as incidental refactoring.

## Engineering standard

Write production-grade, senior-level code suitable for a large technology organization.

- Prefer simple, explicit designs with clear ownership and boundaries.
- Preserve package encapsulation and keep public APIs minimal.
- Keep changes focused; avoid unrelated refactors.
- Handle every meaningful error and add useful context without leaking secrets.
- Define timeouts, cancellation, backpressure, resource limits, and shutdown behavior deliberately.
- Treat concurrency as part of the design: document ownership, avoid goroutine leaks, and test race-prone paths.
- Validate all data crossing trust boundaries. Assume network input is malformed or hostile.
- Never log credentials, keys, plaintext messages, sensitive identifiers, or cryptographic material.
- Prefer the Go standard library unless a dependency has a clear, documented benefit.
- Keep dependencies minimal, maintained, pinned through `go.mod`, and reviewed for security impact.
- Maintain backward compatibility unless a breaking change is explicitly required and documented.
- Avoid premature abstraction, clever code, hidden control flow, and speculative features.
- Do not leave placeholder implementations, ignored errors, or unexplained TODOs in completed work.

Follow established repository conventions and idiomatic Go. Code must be formatted with `gofmt` and pass the configured static analysis.

The project targets Go 1.25 or newer. For simple counting loops from zero to an exclusive integer bound, use `for i := range n` (or `for range n` when the index is unused) when semantics are equivalent. Do not rewrite loops with a non-zero start, a custom step, a bound or index mutated by the body, or post-loop conditions that depend on the index. New code must not leave `rangeint` diagnostics.

For goroutines owned by a `sync.WaitGroup`, new code must use `wg.Go(func() { ... })` instead of the manual `wg.Add(1)` followed by `go func() { defer wg.Done(); ... }()`. Keep manual `Add`/`Done` only when `WaitGroup.Go` cannot express the lifecycle (for example, the count represents externally started work rather than a goroutine launched at that point); document the reason at the site. Do not use a manual pattern merely to pass loop arguments—capture a per-iteration value before `wg.Go` when needed. New code and completed changes must not leave `waitgroupgo` diagnostics.

### Production lifecycle and concurrency invariants

The following are release requirements for network servers and protocol sessions:

- Treat every reconnect as a fresh lifecycle: create new connection/session state, contexts, queues, counters, replay windows, key epochs, and completion barriers. Never reuse terminal state or cryptographic material.
- Register disconnect ownership before exposing a connection to application code. After registration, invoke the disconnect hook exactly once on every exit path, including connect-hook rejection or panic, and preserve the first terminal cause.
- A successful shutdown return is a completion barrier: the accept loop has stopped, core close has completed, connections are closed, and all server-owned handlers, hooks, and goroutines have exited. A deadline may force I/O abort, but must return the deadline error rather than report success while owned work remains.
- Application callbacks MUST honor cancellation and return promptly. Callback wrappers must recover panics, apply a finite deadline, and keep non-cooperative callbacks from blocking unrelated connection accounting; never hide them by decrementing ownership early or spawning an untracked goroutine.
- The layer that creates a deadline owns and stops its timer, cancels derived contexts on every exit, and does not extend a caller's earlier deadline. Blocking I/O and queue waits must have an explicit cancellation or deadline owner.
- Every queue and concurrency fan-out must have a documented finite bound and overload policy. Backpressure must block cancelably or fail explicitly; never silently drop, grow without bound, or create a goroutine per queued item.
- Keepalive and mandatory control messages must not wait behind a saturated application queue. They need bounded, reserved capacity or a dedicated control path; keepalive failure is a liveness/terminal event, not an application-message drop.
- Terminal transition is atomic and idempotent. The first terminal error remains stable for all waiters and hooks; close releases blocked producers, consumers, completion waiters, and deadline resources exactly once.
- No operation may leave an owned goroutine, timer, waiter, or queue entry after its lifecycle barrier. Ownership and the condition that releases each blocking operation must be reviewable from the code.

## DGPv1 requirements

Protocol code requires the highest review and testing standard in the repository.

- Treat parsing, framing, state transitions, replay protection, rekeying, handshakes, authentication, limits, and cryptographic nonce/key handling as security-critical.
- Preserve exact wire semantics, byte ordering, bounds, and error behavior.
- Reject malformed, oversized, unauthenticated, replayed, out-of-order, or otherwise invalid input safely and deterministically.
- Never weaken authentication, encryption, replay defenses, or resource limits for convenience.
- Use established cryptographic primitives and existing repository patterns; do not invent cryptography.
- Consider partial reads/writes, truncation, fragmentation, duplicate frames, boundary values, timeout paths, cancellation, disconnects, and malicious peers.
- Update the protocol specification whenever an intentional behavior or wire-level contract changes.

## Testing expectations

Tests are part of the implementation, not optional follow-up work.

Every behavior change must include tests at the lowest useful level. Bug fixes must include a regression test that fails before the fix. Protocol changes require especially comprehensive coverage.

For DGPv1, use the relevant combination of:

- table-driven unit tests;
- positive and negative cases;
- boundary and malformed-input tests;
- deterministic wire vectors and compatibility tests;
- state-machine and lifecycle tests;
- integration tests across connection endpoints;
- concurrency and race-detector coverage;
- fuzz tests for parsers, framing, and other attacker-controlled inputs;
- benchmarks for performance-sensitive wire paths when performance may change.

Tests must be deterministic, isolated, and meaningful. Do not hide failures with sleeps, retries, broad tolerances, or skipped assertions. Prefer injected clocks, controlled I/O, fixed vectors, and explicit synchronization.

Lifecycle or protocol-concurrency changes MUST include race-detector and repeated stress coverage for reconnect, shutdown versus close/send, queue saturation, cancellation-ignoring callbacks, exactly-once disconnect, stable terminal errors, and goroutine/timer cleanup. Parser and framing changes MUST cover malformed/truncated/oversized input and resource limits. Replay or rekey changes MUST prove check/authenticate/commit atomicity, duplicate/stale rejection, epoch-boundary behavior, and unchanged state after authentication or confirmation failure.

The protocol dependency is a separate module and is not covered by the server module's `go test ./...`. Any change that relies on protocol behavior MUST run the pinned dependency's relevant package tests explicitly (including `-race` for concurrency-sensitive behavior) or an equivalent checked-out protocol-module suite. CI must retain an explicit protocol-dependency job; a green server-only `./...` run is insufficient.

Before considering a change complete, run the relevant focused tests and, when practical:

```sh
go test ./...
go test -race ./...
go vet ./...
go test github.com/datagram-messenger/protocol
go test -race github.com/datagram-messenger/protocol
```

Also use repository CI/Makefile targets when they cover additional formatting, lint, coverage, vulnerability, or release checks. Do not reduce coverage thresholds or weaken tests merely to make CI pass.

## Documentation and comments

Documentation quality is as important as code quality.

- Document exported packages, types, functions, constants, and non-obvious contracts.
- Comments should explain intent, invariants, security assumptions, ownership, wire constraints, and why a decision exists—not restate syntax.
- Keep package docs, README material, configuration examples, operational guidance, and protocol docs synchronized with behavior.
- Record important tradeoffs and compatibility implications near the relevant code or design documentation.
- Write clear errors and logs that help operators diagnose failures without exposing sensitive data.

## Microservice and operational concerns

For backend services, preserve clear service boundaries and design for production operation.

- Use explicit configuration with validation and secure defaults.
- Support graceful startup and shutdown.
- Propagate `context.Context` for cancellation and deadlines where appropriate.
- Add observability at meaningful boundaries while keeping logs structured and safe.
- Avoid unbounded queues, goroutines, memory growth, retries, and request sizes.
- Make retry behavior bounded and safe; account for idempotency.
- Keep transport/domain concerns separated where practical.

## Change completion checklist

A change is complete only when:

- behavior is correct and consistent with the specification;
- security and compatibility effects were considered;
- relevant tests were added or updated and pass;
- protocol-critical paths have strong negative and boundary coverage;
- documentation and comments are current;
- formatting, vetting, linting, and applicable CI checks pass;
- no secrets, generated artifacts, debug code, or unrelated changes were introduced.
