# Quickstart

This server accepts only one known Noise static public key and echoes application command `0x01`. Error checks are intentionally explicit because registration and listener failures are startup failures.

```go
package example

import (
    "context"
    "net"
    "time"

    "github.com/tr1xdev/datagram-server/pkg/dgpserver"
    "github.com/tr1xdev/datagram-server/pkg/dgpv1"
)

func serve(ctx context.Context, ln net.Listener, serverKey dgpv1.StaticKey, clientKey [32]byte) error {
    commands := dgpserver.NewCommandRouter(dgpserver.CommandDecoderFunc(
        func(message *dgpv1.EncryptedData) (dgpserver.Command, any, error) {
            return dgpserver.Command(message.AppMessageType), message, nil
        },
    ))
    if err := commands.Handle(1, dgpserver.HandlerFunc(
        func(ctx *dgpserver.Context, payload any) error {
            request := payload.(*dgpv1.EncryptedData)
            return ctx.Send(&dgpv1.EncryptedData{
                StreamID: request.StreamID, AppMessageType: request.AppMessageType,
                Fields: request.Fields,
            })
        },
    )); err != nil {
        return err
    }

    server, err := dgpserver.New(dgpserver.Config{
        DGP: dgpv1.ServerConfig{
            StaticKey: serverKey, HandshakeTimeout: 10 * time.Second,
            WriteTimeout: 10 * time.Second, OutboundQueue: 64, HandlerQueue: 64,
            MaxConcurrentHandshakes: 64, MaxActiveConnections: 1024,
        },
        Authenticator: dgpserver.NewStaticKeyAllowlist(
            map[[32]byte]dgpserver.Principal{clientKey: "example-client"},
        ),
    })
    if err != nil {
        return err
    }
    if err := server.Router().HandleEncryptedData(commands.Handler()); err != nil {
        return err
    }

    serveDone := make(chan error, 1)
    go func() { serveDone <- server.Serve(context.Background(), ln) }()
    select {
    case err := <-serveDone:
        return err
    case <-ctx.Done():
        shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        if err := server.Shutdown(shutdownCtx); err != nil {
            return err
        }
        return <-serveDone
    }
}
```

A complete production wiring example, including configuration loading and signal handling, is [`cmd/api_datagram/main.go`](../../cmd/api_datagram/main.go).

## Startup checklist

1. Load a persistent 32-byte server Noise static private key with `dgpv1.LoadStaticKey`. Do not generate a new identity on every restart.
2. Create a `Router` or obtain `server.Router()`, add middleware and routes, and check every registration error.
3. Configure an `Authenticator`. A nil authenticator admits every peer that completes a valid Noise handshake and is normally inappropriate for an internet-facing service.
4. Set finite handshake/write/liveness limits and bounded queue/connection capacities in `dgpv1.ServerConfig`.
5. Create the `net.Listener` yourself. `Serve` takes operational ownership and closes it to unblock acceptance during shutdown.
6. Run `Serve` exactly once and coordinate its returned error with `Shutdown`.

## Choosing routes

Use `HandleEncryptedData` for application payloads, `HandleAck` for DGP acknowledgement messages, and `HandleError` for peer error messages. Use a `CommandRouter` when `EncryptedData.AppMessageType` or decoded payload data identifies multiple application operations. See [routing](routing.md).
