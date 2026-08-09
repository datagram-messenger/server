# DGPv1 Datagram Server

[![Go CI](https://github.com/tr1xdev/datagram-server/actions/workflows/ci.yml/badge.svg)](https://github.com/tr1xdev/datagram-server/actions/workflows/ci.yml)

Go implementation of the current DGPv1 MVP: a TCP server with a three-flight `Noise_XX_25519_ChaChaPoly_SHA256` handshake, encrypted DGPv1 sessions, replay protection, directional rekeying, keepalives, idle close, and graceful process shutdown.

The normative wire protocol is documented in [`docs/protocol/dgp-v1.md`](docs/protocol/dgp-v1.md). Before a release, follow the [`DGPv1 pre-deployment checklist`](docs/pre-deployment-checklist.md).

## Prerequisites

- Go 1.25 or newer
- A cryptographically random, persistent 32-byte server Noise static private key

## Configure the server

`api_datagram` uses a typed Viper configuration layer. Precedence is explicit `-config` path, environment overrides, the selected/default YAML file, then secure defaults. Without `-config`, it searches `./config.yaml` and `./config/config.yaml`; a missing default file is allowed, while a missing explicit file fails startup. Unknown YAML fields fail loading.

Copy `config.example.yaml` to ignored `config.yaml`, replace placeholders locally, then run `go run ./cmd/api_datagram -config ./config.yaml`. `DGP_STATIC_KEY` must contain exactly 32 bytes encoded as 64 hexadecimal characters. YAML `peer_identities` is a map from a 64-hex Noise public key to a unique principal. The legacy `DGP_PEER_IDENTITIES=<key>=<principal>,...` override remains supported. Unknown peers are rejected; there is no permissive production default. Generate the static key once per server identity, store it in a secret manager, and reuse it across restarts. Do not commit it, paste it into logs, or use example material in production.

### Windows PowerShell

Generate a key for the current process without writing it to disk:

```powershell
$key = [byte[]]::new(32)
[System.Security.Cryptography.RandomNumberGenerator]::Fill($key)
$env:DGP_STATIC_KEY = [Convert]::ToHexString($key).ToLowerInvariant()
Remove-Variable key
```

To supply a key retrieved from your secret manager:

```powershell
$env:DGP_STATIC_KEY = '<64-hex-character-secret>'
```

### Platform-neutral

Use your operating system or secret manager's cryptographically secure generator to create exactly 32 random bytes, hex-encode them as 64 characters, and export the stored value:

```sh
export DGP_STATIC_KEY='<64-hex-character-secret>'
```

> Never generate the key with a predictable random source. Avoid command-line arguments for real secrets because process listings and shell history may expose them.

### Environment variables

| Variable | Required | Default | Validation / meaning |
|---|---:|---:|---|
| `DGP_STATIC_KEY` | Yes | — | Exactly 64 hex characters (32 decoded bytes). |
| `DGP_ADDRESS` | No | `:8090` | TCP listen address accepted by Go `net.Listen`. |
| `DGP_HANDSHAKE_TIMEOUT` | No | `10s` | Positive Go duration. |
| `DGP_READ_TIMEOUT` | No | `0` | Positive Go duration; per-frame read deadline. |
| `DGP_WRITE_TIMEOUT` | No | `10s` | Positive Go duration; per-frame write deadline and graceful-close allowance. |
| `DGP_IDLE_TIMEOUT` | No | `2m` | Positive Go duration; closes a connection after no authenticated inbound frames. |
| `DGP_KEEPALIVE_INTERVAL` | No | `30s` | Positive Go duration; interval for encrypted Ping frames. |
| `DGP_KEEPALIVE_TIMEOUT` | No | `60s` | Positive Go duration; maximum wait for the matching Pong. |
| `DGP_OUTBOUND_QUEUE` | No | `64` | Positive base-10 integer. |
| `DGP_HANDLER_QUEUE` | No | `64` | Positive base-10 integer; pending per-connection handler work. |
| `DGP_MAX_CONCURRENT_HANDSHAKES` | No | `64` | Positive base-10 integer; concurrent handshakes admitted. |
| `DGP_MAX_ACTIVE_CONNECTIONS` | No | `1024` | Positive base-10 integer; authenticated connections retained. |

Go duration examples include `500ms`, `15s`, and `2m`. Invalid configuration prevents startup and returns an error.

## Run, build, and test

### Windows PowerShell

```powershell
go test ./...
go build -o .\bin\api_datagram.exe .\cmd\api_datagram
Copy-Item .\config.example.yaml .\config.yaml
# Edit the ignored config.yaml, then:
go run .\cmd\api_datagram -config .\config.yaml
# Environment values override YAML:
$env:DGP_ADDRESS = '127.0.0.1:9090'
go run .\cmd\api_datagram -config .\config.yaml
```

### Platform-neutral

```sh
go test ./...
go build -o ./bin/api_datagram ./cmd/api_datagram
cp ./config.example.yaml ./config.yaml
# Edit the ignored config.yaml, then:
go run ./cmd/api_datagram -config ./config.yaml
# Environment values override YAML:
DGP_ADDRESS=127.0.0.1:9090 go run ./cmd/api_datagram -config ./config.yaml
```

On success, the server logs its bound TCP address. The default is all interfaces on port `8090`; set `DGP_ADDRESS=127.0.0.1:8090` to listen only on the local machine.

## Continuous integration

GitHub Actions runs formatting, module tidiness/verification, vet, builds every command, unit/integration tests, the Linux race detector, coverage, golangci-lint, govulncheck, and repository-history secret scanning for pushes and pull requests to `main`. The workflow has read-only repository permissions and does not pass secrets to pull-request code.

Coverage measures `./internal/...` and `./pkg/...` at an 85% minimum; command entrypoints are transparently excluded because they are wiring or placeholders. Run the same check on a POSIX shell with `./scripts/check-coverage.sh`. The generated `coverage.out` is uploaded for 14 days.

Actions use stable major tags because verified commit SHAs are not maintained in this repository. Dependabot checks GitHub Actions monthly; review and merge those updates to keep pins current.

## Shutdown behavior

Send an interrupt (`Ctrl+C`) or `SIGTERM`. The server stops accepting connections, attempts to send each active peer an encrypted normal `SessionClose`, closes sockets, waits for connection goroutines, and exits. The configured write timeout bounds each graceful close attempt.

## MVP boundary

The current server supports TCP, Noise XX in exactly three flights, ChaCha20-Poly1305 data frames, rekeying, replay protection, encrypted Ping/Pong keepalives, and idle close.

The following are preserved as post-MVP design history only and are **not implemented, negotiated, or required**: QUIC transport, transport obfuscation, Noise IK, resumption tickets, and 0-RTT. AES-256-GCM exists as a library codec option but the launch entrypoint selects ChaCha20-Poly1305 and exposes no cipher negotiation setting.

## Releases

Pushing a strict semantic-version tag such as `v1.2.3` runs the release delivery workflow. After tests, vet, and a production-command build, it cross-compiles only the runnable `api_datagram` service for Linux amd64/arm64, Windows amd64, and macOS amd64/arm64 with CGO disabled. Each archive includes `LICENSE`, `README.md`, and `config.example.yaml`; `SHA256SUMS` covers every archive. A GitHub Release is created only for a tag. Manual workflow runs are build-only and retain artifacts for 14 days.

Reproduce the archive set locally from a POSIX shell with Go, Git, tar, gzip, and sha256sum available:

```sh
./scripts/build-release.sh --output ./dist --version v1.2.3
(cd dist && sha256sum --check SHA256SUMS)
```

Release binaries report injected version, commit, and UTC source-commit date with `api_datagram -version`. Placeholder commands are intentionally excluded. This workflow delivers release artifacts; it does not deploy to production because no target infrastructure is defined.
