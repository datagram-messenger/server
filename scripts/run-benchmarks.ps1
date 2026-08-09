param([string]$Benchtime = "2s", [int]$Count = 5)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$out = Join-Path $root "benchmarks/results"
New-Item -ItemType Directory -Force -Path $out | Out-Null
Push-Location $root
try {
  go version | Set-Content (Join-Path $out "go-version.txt")
  go test ./pkg/dgpv1 -run '^$' -bench '^BenchmarkMessengerWireFormats$' -benchmem -benchtime $Benchtime -count $Count | Tee-Object -FilePath (Join-Path $out "latest.txt")
  go test ./pkg/dgpv1 -run '^$' -bench '^BenchmarkMessengerWireFormats$' -benchmem -benchtime $Benchtime -count $Count -json | Set-Content (Join-Path $out "latest.jsonl")
} finally { Pop-Location }
