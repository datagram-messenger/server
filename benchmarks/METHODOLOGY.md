# Benchmark methodology

## Messenger secure envelopes

`BenchmarkMessengerWireFormats` is a local in-memory envelope microbenchmark, not a full HTTP client/server or production messenger comparison. Each payload is serialized to UTF-8 JSON once before timing. Both cases therefore receive the exact same pre-serialized bytes; JSON marshal/unmarshal is excluded from both. The `text` field is deterministic ASCII of 64 B, 1 KiB, or 16 KiB, while reported throughput and wire overhead use the complete JSON length.

DGPv1 uses its mandatory encrypted data frame. The comparison is explicitly named `HTTP1-synthetic-secure-envelope`: it is **not ordinary HTTP and not TLS**. It forms a request line plus `Host`, `Content-Type: application/octet-stream`, `Content-Encoding: benchmark-chacha20poly1305`, and `Content-Length`, then protects the body with the same Go ChaCha20-Poly1305 implementation, zero key, 96-bit nonce shape, and one Seal/Open per operation. In each format the complete plaintext envelope header is AAD. AAD bytes necessarily differ because the framing formats differ.

Codec/AEAD construction and the fixed key are outside timed loops for both. Encode owns a fresh contiguous wire result each operation and advances a counter nonce. Decode receives one prebuilt wire representation, parses the full DGPv1 or HTTP envelope, validates lengths, and opens into a fresh output. End-to-end equality assertions run before timing. The benchmark reports `ns/op`, `B/op`, `allocs/op`, `wire-B/op`, and `overhead-B/op`. DGPv1 overhead is 56 B (40-byte header + 16-byte tag); synthetic HTTP overhead includes all listed request headers plus the 16-byte tag and changes with decimal `Content-Length`.

Excluded: JSON serialization, network I/O, sockets, HTTP library behavior, TLS records/handshake, Noise handshake, scheduling, compression, routing, persistence, and business logic. Results describe only these implementation boundaries and do not establish that either protocol is globally faster or better.

## Reproduction

On Ubuntu with GNU Make:

```sh
make benchmark BENCHTIME=1s COUNT=5
```

The runners record ignored machine-specific raw output under `benchmarks/results/`. Compare all repetitions and medians; rerun on the target CPU with a quiet machine, fixed power policy, and unchanged Go version before making claims.
