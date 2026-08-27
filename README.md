<div align="center">

# Datagram Server

**The Go backend for the Datagram messenger.**

Secure, real-time messaging services built on DGProto v1.

[![CI](https://github.com/datagram-messenger/server/actions/workflows/ci.yml/badge.svg)](https://github.com/datagram-messenger/server/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/Go-1.25%2B-00ADD8?logo=go&logoColor=white)](https://go.dev/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![DGProto v1](https://img.shields.io/badge/protocol-DGProto%20v1-6f42c1)](docs/protocol/dgproto-v1.md)

[Quick start](#quick-start) · [Configuration](#configuration) · [Development](#development-commands) · [Documentation](#documentation) · [Contributing](CONTRIBUTING.md)

</div>

---

## Overview

Datagram Server is the Go backend for the **Datagram messenger**. It contains the services and server-side infrastructure responsible for authenticated client connections, application-message routing, resource limits, and secure session lifecycle management.

The repository currently also contains `dgpserver`, the server package shared by these services. Protocol primitives live in the standalone [`dgproto-go`](https://github.com/datagram-messenger/dgproto-go) module, which implements Datagram's encrypted DGProto v1 wire protocol.

### Highlights

The runnable `api_datagram` service provides:

- authenticated TCP sessions with a three-flight `Noise_XX_25519_ChaChaPoly_SHA256` handshake;
- ChaCha20-Poly1305 encrypted frames, replay protection, and directional rekeying;
- encrypted Ping/Pong keepalives and idle-connection handling;
- bounded connection, handshake, queue, and handler concurrency;
- structured JSON logging and graceful, deadline-bounded shutdown.

> [!IMPORTANT]
> DGProto v1 is security-sensitive infrastructure. The [protocol specification](docs/protocol/dgproto-v1.md) is the source of truth for wire behavior.

## Project status

Datagram is under active development. The secure transport and server lifecycle are implemented; broader messenger services and product functionality are evolving. The echo and service-information commands exposed by `api_datagram` are integration examples, not the complete Datagram application API.

## Prerequisites

For development on Linux, install:

- [Go 1.25 or newer](https://go.dev/doc/install)
- Git
- GNU Make for the repository targets
- A C toolchain for race-detector runs (`go test -race`)

Release builds additionally require `tar`, `gzip`, `sha256sum`, and standard GNU command-line tools.

## Quick start

Clone the repository and create a local configuration:

```sh
git clone https://github.com/datagram-messenger/server.git
cd datagram-server
cp config.example.yaml config.yaml
```

Edit the ignored `config.yaml` before starting the service:

1. Replace the placeholder `static_key` with a persistent, cryptographically random 32-byte Noise private key encoded as 64 hexadecimal characters, or configure `static_key_file` instead.
2. Replace the example entry under `peer_identities` with an authorized client's 64-character hexadecimal Noise public key and a unique principal name.
3. Review the listen address and resource limits for your environment.

For local development, a key file can be generated with Linux's cryptographically secure random source:

```sh
umask 077
mkdir -p secrets
head -c 32 /dev/urandom | od -An -v -tx1 | tr -d ' \n' > secrets/noise-static-key.hex
```

Then remove `static_key` from `config.yaml` and set:

```yaml
static_key_file: "./secrets/noise-static-key.hex"
```

Start the service:

```sh
go run ./cmd/api_datagram -config ./config.yaml
```

On success, the service emits structured JSON logs with its bound TCP address. The example binds to `127.0.0.1:8090`; the built-in default is `:8090`.

Never commit private keys or production identity allowlists. Keep one server key per identity and reuse it across restarts.

## Configuration

`api_datagram` loads typed YAML configuration through Viper. Values are resolved in this order, from highest to lowest priority:

1. `DGP_*` environment variables
2. the YAML file selected by `-config`, or a discovered default file
3. built-in defaults

Without `-config`, the service searches for `./config.yaml` and `./config/config.yaml`. A missing discovered file is allowed; a missing explicitly selected file is an error. Unknown YAML fields and invalid values stop startup.

The complete template is [`config.example.yaml`](config.example.yaml). Important environment overrides are:

| Variable | Default | Meaning |
| --- | --- | --- |
| `DGP_ADDRESS` | `:8090` | TCP `host:port` listen address. |
| `DGP_STATIC_KEY` | none | Required unless `static_key_file` is configured; exactly 64 hexadecimal characters. |
| `DGP_STATIC_KEY_FILE` | none | File containing the 64-character hexadecimal server private key. |
| `DGP_PEER_IDENTITIES` | none | Fail-closed allowlist in `<public-key>=<principal>,...` form. |
| `DGP_HANDSHAKE_TIMEOUT` | `10s` | Maximum Noise handshake duration. |
| `DGP_READ_TIMEOUT` | `0s` | Per-frame read deadline; zero disables it. |
| `DGP_WRITE_TIMEOUT` | `10s` | Per-frame write deadline. |
| `DGP_IDLE_TIMEOUT` | `2m` | Authenticated inbound-idle limit. |
| `DGP_KEEPALIVE_INTERVAL` | `30s` | Encrypted Ping interval. |
| `DGP_KEEPALIVE_TIMEOUT` | `60s` | Maximum wait for the matching Pong. |
| `DGP_OUTBOUND_QUEUE` | `64` | Per-connection outbound queue capacity. |
| `DGP_HANDLER_QUEUE` | `64` | Per-connection pending handler capacity. |
| `DGP_MAX_CONCURRENT_HANDSHAKES` | `64` | Concurrent handshake limit. |
| `DGP_MAX_ACTIVE_CONNECTIONS` | `1024` | Authenticated connection limit. |

Durations use Go syntax such as `500ms`, `15s`, and `2m`. The identity allowlist is required, timeouts and capacities are validated, and unknown peers are rejected.

To override a non-secret setting for one run:

```sh
DGP_ADDRESS=127.0.0.1:9090 go run ./cmd/api_datagram -config ./config.yaml
```

## Development commands

Run these commands from the repository root:

```sh
make build                    # build bin/api_datagram
make test                     # run all server-module tests
make coverage                 # enforce 85% coverage for internal/ and pkg/
go test -race ./...           # run server-module tests with the race detector
go test github.com/datagram-messenger/dgproto-go
go test -race github.com/datagram-messenger/dgproto-go
go vet ./...
golangci-lint run             # uses .golangci.yml
```

The protocol dependency is a separate Go module and is not covered by `go test ./...`; run its tests explicitly when a change depends on protocol behavior.

Useful additional targets:

```sh
make benchmark BENCHTIME=2s COUNT=5
make sbom
make release VERSION=v1.2.3 DIST_DIR=dist
make verify-release DIST_DIR=dist
make clean
```

Use `make help` for the complete target list. See the [benchmark methodology](benchmarks/METHODOLOGY.md) and [dependency review](docs/dependency-review.md) before interpreting generated artifacts.

## Repository structure

```text
cmd/
  api_datagram/     Runnable DGProto v1 service
  api_bot/          Placeholder bot-service entrypoint
  auth/             Placeholder authentication-service entrypoint
  user/             Placeholder user-service entrypoint
docs/
  dgpserver/        Application-facing server guide
  protocol/         Normative DGProto v1 specification
internal/
  buildinfo/        Build and release metadata
  config/           Configuration loading and validation
pkg/
  dgpserver/        Routing, authentication, lifecycle, and test helpers
benchmarks/         Benchmark methodology and published result assets
.github/workflows/  CI and release automation
```

## Documentation

- [Contributing guide](CONTRIBUTING.md)
- [DGProto v1 protocol specification](docs/protocol/dgproto-v1.md)
- [`dgpserver` developer guide](docs/dgpserver/README.md)
- [`dgpserver` quickstart](docs/dgpserver/quickstart.md)
- [Routing and middleware](docs/dgpserver/routing.md)
- [Authentication and request context](docs/dgpserver/authentication-and-context.md)
- [Lifecycle, errors, and operations](docs/dgpserver/lifecycle-and-errors.md)
- [Testing handlers](docs/dgpserver/testing.md)
- [Dependency review](docs/dependency-review.md)

## Scope

The current service supports TCP, three-flight Noise XX, ChaCha20-Poly1305 data frames, replay protection, directional rekeying, encrypted Ping/Pong keepalives, idle close, and graceful process shutdown. `api_datagram` exposes echo (`0x01`) and service-information (`0x02`) application commands as integration examples.

QUIC, transport obfuscation, Noise IK, resumption tickets, and 0-RTT are not implemented or negotiated. AES-256-GCM exists as a protocol-library codec option, but the runnable service selects ChaCha20-Poly1305 and does not expose cipher negotiation.

Send `SIGINT` or `SIGTERM` to stop the service. Shutdown stops accepting connections, closes active sessions, waits for server-owned work, and is bounded by configured deadlines.

## Releases

A strict semantic-version tag such as `v1.2.3` triggers the release workflow. It tests and vets the project, builds `api_datagram` archives for the configured release targets, writes `SHA256SUMS`, and publishes a release for tag-triggered runs. Manual workflow runs create build artifacts without publishing a release.

Release binaries expose injected build metadata:

```sh
./bin/api_datagram -version
```

The release workflow produces artifacts only; no production deployment target is defined.

## License

See [`LICENSE`](LICENSE).
