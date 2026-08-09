# Benchmark results

This directory keeps only this policy file in Git. Machine-specific raw files (`latest.txt`, `latest.jsonl`, `go-version.txt`) and generated summaries (`summary.csv`, `summary.json`) are ignored. Benchmark source, both runners, methodology, and the intentionally published deterministic portfolio SVG are committed.

Regenerate from the repository root:

```powershell
./scripts/run-benchmarks.ps1 -Benchtime 1s -Count 3
```

```sh
./scripts/run-benchmarks.sh 1s 3
# or: BENCHTIME=1s COUNT=3 ./scripts/run-benchmarks.sh
```

The runners write the same raw artifacts. Summary files and `benchmarks/dgpv1-benchmark.svg` are derived from `latest.jsonl`; publish an SVG only after checking its labels, machine metadata, and medians. Never treat a machine snapshot as a universal protocol ranking.
