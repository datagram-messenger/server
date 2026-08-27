# Testing handlers

Most routing and business-policy tests do not need TCP, Noise, goroutines, or timers. Use `Dispatch` for receive-only behavior and `Recorder` when the handler sends.

## Test a typed route with `Dispatch`

```go
func TestAck(t *testing.T) {
    var router dgpserver.Router
    if err := router.HandleAck(func(ctx *dgpserver.Context, ack *dgproto.Ack) error {
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
        &dgproto.Ack{Sequences: []uint64{7}},
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
        dgpserver.NewMetadata(dgproto.MessageTypeEncryptedData, time.Now()),
        dgpserver.Params{},
    )

    err := handler(ctx, &dgproto.EncryptedData{StreamID: 9})
    if err != nil {
        t.Fatal(err)
    }
    sent := recorder.Snapshot()
    if len(sent) != 1 || sent[0].Message.(*dgproto.Ack).Sequences[0] != 9 {
        t.Fatalf("sent = %#v", sent)
    }
}
```

`Recorder` is bounded and concurrency-safe. `TrySend` returns `ErrRecorderFull` at capacity; blocking sends wait until `Drain`, cancellation, or `Close`. `Snapshot` does not release capacity; `Drain` does. Recorded `EncryptedData` and `Ack` slice data is defensively copied. `RecordedSend.Wait` distinguishes `SendAndWait` from queued sends; it simulates completion rather than network I/O.

Use a positive capacity. `NewRecorder(0)` panics by contract.

## What still needs integration tests

Use real loopback TCP and a `dgproto` client for:

- Noise identities and authentication rejection;
- session and wire interoperability;
- queue saturation and transport write behavior;
- read/write/idle/keepalive deadlines;
- graceful close and shutdown escalation;
- lifecycle hook ordering and disconnect causes;
- rekey, replay, malformed input, and other protocol behavior.

Keep integration tests deterministic with explicit synchronization and deadlines. The package's [`runtime_integration_test.go`](../../pkg/dgpserver/runtime_integration_test.go) demonstrates a full handshake, authenticated dispatch, response, and shutdown. [`abnormal_disconnect_integration_test.go`](../../pkg/dgpserver/abnormal_disconnect_integration_test.go) verifies that handler errors, recovered handler panics, and replay rejection reach `OnDisconnect` exactly once with an error preserving the terminal cause through `errors.Is`.

## Dispatch benchmarks

Run the deterministic, network- and crypto-free dispatch benchmarks from the repository root:

```sh
go test ./pkg/dgpserver -run '^$' -bench '^BenchmarkDispatchOverhead$' -benchmem -count=1
```

Baseline recorded on Windows/amd64 with Go 1.26.5 and an Intel Xeon E5-2689 0 @ 2.60 GHz:

```text
BenchmarkDispatchOverhead/Handler-16                           2.034 ns/op     0 B/op   0 allocs/op
BenchmarkDispatchOverhead/DispatchHelper-16                  197.1 ns/op     192 B/op   2 allocs/op
BenchmarkDispatchOverhead/FrozenTypedRouter-16                92.66 ns/op     0 B/op   0 allocs/op
BenchmarkDispatchOverhead/FrozenTypedRouterWithMiddleware-16 101.3 ns/op     0 B/op   0 allocs/op
BenchmarkDispatchOverhead/FrozenCommandRouter-16               46.49 ns/op     0 B/op   0 allocs/op
```

These numbers are machine- and toolchain-specific reference data, not a release threshold. Compare changes using repeated runs on the same controlled host; investigate evidence before optimizing implementation code.

## Registration and configuration fuzzing

Run the deterministic seed corpus and then each target separately from the repository root:

```sh
go test ./pkg/dgpserver -run '^Fuzz(ConfigValidationBoundaries|RouterRegistrationState|CommandRouterRegistrationState)$' -count=1
go test ./pkg/dgpserver -run '^$' -fuzz '^FuzzConfigValidationBoundaries$' -fuzztime=2s
go test ./pkg/dgpserver -run '^$' -fuzz '^FuzzRouterRegistrationState$' -fuzztime=2s
go test ./pkg/dgpserver -run '^$' -fuzz '^FuzzCommandRouterRegistrationState$' -fuzztime=2s
```

The targets are deliberately network- and crypto-free. Inputs select from bounded duration, queue, connection-limit, message-type, handler-form, duplicate, group, and freeze-state domains rather than treating arbitrary bytes as configuration. The invariants are: no panic; repeatable `New` error classification; application of the documented five-second disconnect default; rejection of a negative `DisconnectTimeout`; exact preservation of delegated DGP duration, queue, and connection-limit boundaries until runtime construction; and stable nil, unsupported, duplicate, and post-freeze registration errors. Command registration also checks conflicts across direct and grouped routes over the complete `uint8` command range.

A two-second target run is only a quick local smoke check. CI or scheduled verification should run the same targets separately with a materially longer fuzz time so a failure is attributable to one state model.

## Command decoder failure coverage

The decoder-path table/property tests run entirely through the public `Dispatch` safety boundary, while one package-level runtime test exercises `Server.handle` directly to avoid a timing-sensitive network setup. They cover sentinel and wrapped typed errors, codec-defined malformed payloads, unknown commands, typed-nil `EncryptedData`, decoder panic recovery, single decode/no handler invocation on failure, `errors.Is`/`errors.As` preservation, exactly-once `ErrorHandler` observation, and sanitized SDK wrapper formatting.

Run the deterministic cases and fuzz seed corpus, then the fuzz target separately:

```sh
go test ./pkg/dgpserver -run '^(TestCommandRouterDecoderFailureContract|TestCommandRouterNilMessageRejectedBeforeDecoder|TestCommandRouterDecoderPanicUsesDispatchSafetyBoundary|TestServerHandlePropagatesDecoderErrorToErrorHandlerExactlyOnce|FuzzCommandRouterDecoderPaths)$' -count=1
go test ./pkg/dgpserver -run '^$' -fuzz '^FuzzCommandRouterDecoderPaths$' -fuzztime=2s
```

The SDK remains codec-neutral: malformed application payloads are whatever the injected decoder rejects. Protocol-level `EncryptedData` parsing remains owned and tested by `github.com/datagram-messenger/dgproto-go`; the command router neither reparses nor adds a server codec setting. Concurrent shutdown/send races remain a separate open release gate.

## Shutdown/send concurrency properties

The deterministic property matrix covers `TrySend`, context-aware queued `Send`, and `SendAndWait` against close with ordered and simultaneous starts. Explicit channels establish barriers; the only timeout is a bounded deadlock guard. It verifies terminal rejection, caller-context precedence before termination, completion waiter release, concurrent close idempotence, stable terminal cause, and that control close is not queued behind a full application queue. SDK tests also cover handler cancellation, disconnect-context send rejection, and concurrent server `Shutdown`/`Close` before `Serve`.

```sh
go test ./pkg/dgpserver github.com/datagram-messenger/dgproto-go -run 'Test(ContextSendCancellationAndDisconnectProperties|ConcurrentServerShutdownAndCloseBeforeServe|SendShutdownStateMachineProperties|FullQueueWaitersAndControlCloseProperties|ConcurrentCloseIsIdempotentAndTerminalCauseStable|SendCancellationPrecedenceBeforeTerminalState)$' -count=20
```
