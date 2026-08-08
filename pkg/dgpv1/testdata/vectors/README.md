# DGPv1 JSON wire vectors

Each `*.json` file is a strict object with a `schema` value of `dgpv1-wire-v1` and a `vectors` array. Every vector has a unique `name`, a parser `kind`, lowercase `wire_hex`, `valid`, and, for malformed input, the expected typed `error` name. Message vectors also provide `message_type`.

Valid vectors must decode, validate where applicable, and re-encode to the exact canonical bytes. Malformed vectors must fail with the named sentinel error. The loader rejects unknown fields, trailing JSON, odd or non-lowercase hex, duplicate names, and inconsistent validity/error fields.
