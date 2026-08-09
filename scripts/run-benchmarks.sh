#!/usr/bin/env bash
set -euo pipefail

benchtime="${1:-${BENCHTIME:-2s}}"
count="${2:-${COUNT:-5}}"

if [[ ! -f go.mod || ! -d pkg/dgpv1 || ! -d benchmarks ]]; then
  echo "error: run this script from the repository root" >&2
  exit 1
fi

out="benchmarks/results"
mkdir -p "$out"
go version > "$out/go-version.txt"
go test ./pkg/dgpv1 -run '^$' -bench '^BenchmarkMessengerWireFormats$' -benchmem -benchtime "$benchtime" -count "$count" | tee "$out/latest.txt"
go test ./pkg/dgpv1 -run '^$' -bench '^BenchmarkMessengerWireFormats$' -benchmem -benchtime "$benchtime" -count "$count" -json > "$out/latest.jsonl"
