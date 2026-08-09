# Testing handlers

Most routing and business-policy tests do not need TCP, Noise, goroutines, or timers. Use `Dispatch` for receive-only behavior and `Recorder` when the handler sends.

## Test a typed route with `Dispatch`

```go
func TestAck(t *testing.T) {
    var router dgpserver.Router
    if err := router.HandleAck(func(ctx *dgpserver.Context, ack *dgpv1.Ack) error {
        if ctx.Principal() != "alice" || ack.Sequences[0] != 7 {
            return errors.New("unexpected request")
        }
        return nil
    }); err != nil {
        t.Fatal(err)
    }

    err := dgpserver.Dispatch(
        context.Background(),
        dgpserver.HandlerFunc(router.Dispatch),
        dgpserver.NewPeer("test", [16]byte{1}, []byte{2}),
        "alice",
        &dgpv1.Ack{Sequences: []uint64{7}},
    )
    if err != nil {
        t.Fatal(err)
    }
}
```

`Dispatch` derives metadata from the pointer-form message, supplies peer and principal snapshots, has no send capability, and recovers panics like `Router.Dispatch`. It does not run authentication, hooks, network lifecycle, or `Server.ErrorHandler`.

You can also call `router.Dispatch` directly with `NewContext` when exact metadata or params matter.

## Record sends

```go
func TestReply(t *testing.T) {
    recorder := dgpserver.NewRecorder(2)
    ctx := recorder.NewContext(
        context.Background(), dgpserver.Peer{},
        dgpserver.NewMetadata(dgpv1.MessageTypeEncryptedData, time.Now()),
        dgpserver.Params{},
    )

    err := handler(ctx, &dgpv1.EncryptedData{StreamID: 9})
    if err != nil {
        t.Fatal(err)
    }
    sent := recorder.Snapshot()
    if len(sent) != 1 || sent[0].Message.(*dgpv1.Ack).Sequences[0] != 9 {
        t.Fatalf("sent = %#v", sent)
    }
}
```

`Recorder` is bounded and concurrency-safe. `TrySend` returns `ErrRecorderFull` at capacity; blocking sends wait until `Drain`, cancellation, or `Close`. `Snapshot` does not release capacity; `Drain` does. Recorded `EncryptedData` and `Ack` slice data is defensively copied. `RecordedSend.Wait` distinguishes `SendAndWait` from queued sends; it simulates completion rather than network I/O.

Use a positive capacity. `NewRecorder(0)` panics by contract.

## What still needs integration tests

Use real loopback TCP and a `dgpv1` client for:

- Noise identities and authentication rejection;
- session and wire interoperability;
- queue saturation and transport write behavior;
- read/write/idle/keepalive deadlines;
- graceful close and shutdown escalation;
- lifecycle hook ordering and disconnect causes;
- rekey, replay, malformed input, and other protocol behavior.

Keep integration tests deterministic with explicit synchronization and deadlines. The package's [`runtime_integration_test.go`](../../pkg/dgpserver/runtime_integration_test.go) demonstrates a full handshake, authenticated dispatch, response, and shutdown.
