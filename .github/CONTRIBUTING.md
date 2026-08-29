# Contributing to Datagram Server

Thank you for contributing to Datagram Server. This repository contains security-sensitive messaging infrastructure: the Go backend, server toolkit, and integration with the DGProto v1 protocol module. Correctness, wire compatibility, security, operability, and maintainability take priority over delivery speed.

## Before you begin

- Read the [README](README.md) for the project scope and development commands.
- Review the [DGProto v1 specification](docs/protocol/dgproto-v1.md) before changing protocol-dependent behavior.
- Read the relevant implementation, documentation, and tests before proposing a change.
- Keep changes focused. Open separate pull requests for unrelated work.
- For substantial features, compatibility changes, or architectural work, open an issue first so the approach can be discussed before implementation.

Do not use public issues or pull requests to disclose suspected vulnerabilities. See [Reporting security issues](#reporting-security-issues).

## Development setup

Development is supported on Linux and requires:

- Go 1.25 or newer;
- Git;
- GNU Make; and
- a C toolchain for race-detector runs.

Clone the repository and verify the checkout:

```sh
git clone https://github.com/tr1xdev/datagram-server.git
cd datagram-server
go mod download
go test ./...
```

To run the service locally, copy the example configuration:

```sh
cp config.example.yaml config.yaml
```

`config.yaml` is intentionally ignored. Use only local test credentials and keys, and never commit secrets, private keys, production identity allowlists, or sensitive message data. See the README for configuration and startup instructions.

## Making a change

1. Start from an up-to-date `main` branch.
2. Create a short, descriptive branch.
3. Make the smallest coherent change that solves the problem.
4. Add or update tests alongside the implementation.
5. Update documentation when behavior, configuration, APIs, operations, or protocol contracts change.
6. Run the applicable checks locally.
7. Submit a pull request with a clear explanation of the change and its risks.

### Engineering expectations

- Follow idiomatic Go and preserve package boundaries.
- Keep public APIs minimal and backward compatible unless a breaking change is explicitly approved and documented.
- Handle meaningful errors and add useful context without exposing sensitive data.
- Validate all input crossing trust boundaries; network input must be treated as malformed or hostile.
- Define ownership, cancellation, deadlines, resource limits, backpressure, and shutdown behavior deliberately.
- Avoid goroutine, timer, waiter, and queue-entry leaks.
- Prefer the standard library. New dependencies require a clear benefit and a security and maintenance review.
- Do not introduce placeholder implementations, ignored errors, unexplained TODOs, unrelated refactors, or generated artifacts.
- Format Go code with `gofmt` and satisfy the configured static analysis in `.golangci.yml`.

The repository targets modern Go conventions. Use integer ranges for simple zero-based counting loops when semantics are unchanged. For goroutines owned by a `sync.WaitGroup`, prefer `wg.Go` over a manual `Add`/`Done` lifecycle; document exceptional cases.

### Protocol and security-sensitive changes

Protocol behavior must agree with the normative specification, established wire vectors, and tests. Do not introduce an undocumented extension, wire-format change, compatibility break, or new cryptographic construction as incidental work.

Changes involving framing, parsing, handshakes, authentication, replay protection, rekeying, state transitions, cryptographic material, or resource limits must include strong positive, negative, malformed-input, and boundary coverage. Preserve exact byte ordering, bounds, error behavior, and state-transition semantics.

If the specification, implementation, and established vectors disagree, identify the conflict explicitly. Resolve it in the implementation, tests, and documentation rather than silently choosing one interpretation.

The protocol dependency is a separate Go module and is not covered by this repository's `go test ./...`. If a change relies on protocol behavior, test the pinned dependency explicitly:

```sh
go test github.com/datagram-messenger/dgproto-go
go test -race github.com/datagram-messenger/dgproto-go
```

## Testing and quality checks

Run focused tests while developing. Before opening a pull request, run the broadest applicable set of checks:

```sh
gofmt -w <changed-go-files>
go mod tidy
git diff --exit-code -- go.mod go.sum
go mod verify
go vet ./...
go build ./cmd/...
go test ./...
go test -race ./...
golangci-lint run
make coverage
```

`make coverage` enforces at least 85% coverage across the core packages. Do not lower thresholds, weaken assertions, add arbitrary sleeps or retries, or skip tests merely to make checks pass.

Tests should be deterministic, isolated, and meaningful. Bug fixes require a regression test that fails before the fix. Concurrency and lifecycle changes should include race-detector and repeated stress coverage. Parser and framing changes should include fuzz, malformed, truncated, oversized, and resource-limit cases where applicable.

Not every change requires every expensive check. In the pull request, state exactly which checks you ran and explain any relevant check you could not run.

## Documentation

Keep the README, package documentation, configuration examples, operational guidance, and protocol documentation synchronized with behavior. Document exported APIs and non-obvious contracts. Comments should explain intent, invariants, ownership, security assumptions, and compatibility constraints rather than restating code.

## Commits

Write concise, imperative commit subjects and keep each commit logically coherent. This repository generally uses Conventional Commit-style prefixes, for example:

```text
feat(dgpserver): add bounded handler dispatch
fix(config): reject invalid timeout combinations
test(protocol): cover truncated frames
docs: clarify local development setup
```

Common prefixes include `feat`, `fix`, `refactor`, `test`, `docs`, `ci`, `build`, and `chore`. Use a scope when it adds useful context. Explain the motivation, security implications, compatibility effects, and important tradeoffs in the commit body when they are not obvious from the diff.

## Pull requests

A strong pull request:

- explains the problem and why the proposed approach is appropriate;
- links related issues or design discussions;
- describes user-visible, operational, security, and compatibility effects;
- lists tests and checks performed;
- includes tests for changed behavior;
- updates affected documentation;
- calls out protocol or dependency changes explicitly; and
- contains no secrets, local configuration, debug code, generated output, or unrelated edits.

Reviewers may ask for additional negative tests, race coverage, protocol vectors, benchmarks, documentation, or a smaller change set. All required CI checks must pass before merge.

## Reporting security issues

Do not report suspected vulnerabilities in a public issue, discussion, commit, or pull request. Use the repository's private vulnerability reporting feature under the **Security** tab when available. If it is unavailable, contact the repository maintainer privately and provide only enough information to establish a secure reporting channel.

Include the affected component and version or commit, impact, reproduction conditions, and any suggested mitigation. Do not include real credentials, private keys, plaintext messages, personal data, or production artifacts.

## License

By contributing, you agree that your contributions will be licensed under the terms in [LICENSE](LICENSE).
