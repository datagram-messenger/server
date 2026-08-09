# Routing and middleware

## Typed DGP routing

A zero-value `Router` is ready for registration. The convenience methods preserve pointer-form inbound messages while preventing application type switches:

```go
var router dgpserver.Router
if err := router.HandleAck(func(ctx *dgpserver.Context, ack *dgpv1.Ack) error {
    // ack is already type checked.
    return nil
}); err != nil {
    return err
}
```

Equivalent generic registration is `dgpserver.Handle[dgpv1.Ack](&router, handler)` (type inference usually makes the explicit argument unnecessary). The type argument is the non-pointer message type; the callback receives `*T`. Registration rejects nil handlers, unsupported protocol types, duplicate routes, and mutation after freeze.

Inbound values passed to `Router.Dispatch` and `Dispatch` must be pointers. This matches `dgpv1.Session.Receive` and avoids ambiguous copies.

## Application command routing

`CommandRouter` is a second routing layer for `EncryptedData`. The application supplies a `CommandDecoder`, so the SDK does not dictate JSON, protobuf, TLV schemas, or another codec.

```go
commands := dgpserver.NewCommandRouter(dgpserver.CommandDecoderFunc(
    func(message *dgpv1.EncryptedData) (dgpserver.Command, any, error) {
        return dgpserver.Command(message.AppMessageType), message, nil
    },
))
if err := commands.Handle(0x01, dgpserver.HandlerFunc(
    func(ctx *dgpserver.Context, payload any) error {
        message, ok := payload.(*dgpv1.EncryptedData)
        if !ok {
            return dgpserver.ErrInvalidMessageForm
        }
        return ctx.Send(message)
    },
)); err != nil {
    return err
}
if err := router.HandleEncryptedData(commands.Handler()); err != nil {
    return err
}
```

Decoder errors are returned unchanged. An unknown command returns an error matching `ErrNotHandled`. The command router freezes on its first dispatch; finish command and group registration before serving.

## Groups

Groups are registration-time middleware scopes, not path trees. They are useful for applying authorization or rate-limit policy to a set of command IDs.

```go
err := commands.Group(func(group *dgpserver.CommandGroup) error {
    if err := group.Use(requireRole("admin")); err != nil {
        return err
    }
    return group.Handle(0x10, deleteUserHandler)
})
```

The callback runs synchronously; do not retain the group. A command ID can be registered only once across all groups.

## Middleware

Middleware wraps `Handler` and may inspect the context, transform the decoded command payload, short-circuit, or return an error:

```go
func requirePrincipal(next dgpserver.Handler) dgpserver.Handler {
    return dgpserver.HandlerFunc(func(ctx *dgpserver.Context, message any) error {
        if ctx.Principal() == nil {
            return dgpserver.ErrUnauthenticated
        }
        return next.Handle(ctx, message)
    })
}
```

For `Use(A, B)`, execution is `A before -> B before -> handler -> B after -> A after`. Command-router-wide middleware wraps group middleware. Chains compile once at freeze.

Middleware controls whether and how often it invokes `next`; the SDK does not enforce exactly-once invocation. Prefer zero or one call unless duplicate handler effects are explicitly intended. Middleware and handlers for one connection execute serially, but closures can be called concurrently by different connections.

## Registration errors

Treat registration errors as fatal startup configuration errors. Use `errors.Is` with:

- `ErrDuplicateHandler` for duplicate DGP or command routes;
- `ErrNilHandler` for nil handlers, middleware, decoder/router configuration;
- `ErrUnsupportedMessage` for runtime-owned or unknown DGP message types;
- `ErrServerStarted` for mutation after a router has frozen.
