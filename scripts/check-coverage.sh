#!/bin/sh
set -eu

threshold=${1:-85}
profile=${2:-coverage.out}

case "$threshold" in
  ''|*[!0-9.]*|.*|*.*.*)
    echo "coverage threshold must be a non-negative number" >&2
    exit 2
    ;;
esac

# Measure production library/configuration packages. Command entrypoints are
# excluded because most only wire dependencies or are placeholders. There are
# currently no generated Go files, so no generated-code exclusion is applied.
packages=$(go list ./internal/... ./pkg/...)
if [ -z "$packages" ]; then
  echo "no coverage packages found" >&2
  exit 1
fi

# Intentional word splitting turns the newline-separated package list into args.
# shellcheck disable=SC2086
go test -covermode=atomic -coverprofile="$profile" $packages

total=$(go tool cover -func="$profile" | awk '/^total:/ {gsub(/%/, "", $3); print $3}')
if [ -z "$total" ]; then
  echo "could not determine total coverage" >&2
  exit 1
fi

printf 'total coverage: %s%% (required: %s%%)\n' "$total" "$threshold"
awk -v actual="$total" -v required="$threshold" 'BEGIN { exit !(actual + 0 >= required + 0) }' || {
  echo "coverage is below the required threshold" >&2
  exit 1
}
