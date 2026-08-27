# Dependency review

This repository generates an application-scoped CycloneDX 1.6 SBOM for `cmd/api_datagram`.

## Reproduce

```sh
make sbom
```

The generator is pinned in `Makefile` to `cyclonedx-gomod` v1.12.0 and writes `sbom.cdx.json` by default. The SBOM is generated evidence and is not committed. CI regenerates and uploads it for each run.

Before a release:

1. Run `go mod verify`, `go test ./...`, `go vet ./...`, and the configured vulnerability scan.
2. Generate the SBOM and review all component names and versions against `go.mod` and `go.sum`.
3. Review detected license evidence. Detection is advisory and must not be treated as legal approval.
4. Investigate every component with missing license evidence or an unexpected dependency path.
5. Retain the reviewed SBOM with the release evidence.

## Current review

The application SBOM contains 16 third-party Go modules. The dependency set is small and pinned by `go.mod`/`go.sum`. Most detected licenses are permissive BSD, MIT, or Apache-family licenses.

One blocker remains: `github.com/datagram-messenger/dgproto-go` currently has no license file in its repository, so automated license detection reports no evidence for that module. Add and review an explicit license in the protocol repository before a production release.

The first `dgpserver` release remains experimental until production race, leak, stress, abnormal-exit, and automatic-rekey gates are complete and the SDK has been exercised by a real service.
