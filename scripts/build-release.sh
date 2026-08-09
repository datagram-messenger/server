#!/bin/sh
set -eu

usage() {
  echo "usage: $0 --output DIR --version vMAJOR.MINOR.PATCH" >&2
  exit 2
}

output=
version=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --output) [ "$#" -ge 2 ] || usage; output=$2; shift 2 ;;
    --version) [ "$#" -ge 2 ] || usage; version=$2; shift 2 ;;
    *) usage ;;
  esac
done

[ -n "$output" ] && [ -n "$version" ] || usage
case "$version" in
  v0|v0.*[!0-9.]*|v[!0-9]*|*.*.*.*) echo "invalid version: $version" >&2; exit 2 ;;
esac
printf '%s\n' "$version" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || {
  echo "invalid version: $version (expected vMAJOR.MINOR.PATCH)" >&2
  exit 2
}

for tool in go git tar gzip sha256sum mktemp; do
  command -v "$tool" >/dev/null 2>&1 || { echo "required tool not found: $tool" >&2; exit 1; }
done

repo=$(git rev-parse --show-toplevel)
case "$output" in
  /*) out=$output ;;
  *) out=$PWD/$output ;;
esac
case "$out" in
  "$repo"|"$repo"/) echo "output must not be the repository root" >&2; exit 2 ;;
esac

commit=$(git -C "$repo" rev-parse HEAD)
epoch=${SOURCE_DATE_EPOCH:-$(git -C "$repo" show -s --format=%ct HEAD)}
build_date=$(date -u -d "@$epoch" '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date -u -r "$epoch" '+%Y-%m-%dT%H:%M:%SZ')
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
rm -rf "$out"
mkdir -p "$out"

ldflags="-s -w -X github.com/tr1xdev/datagram-server.git/internal/buildinfo.Version=$version -X github.com/tr1xdev/datagram-server.git/internal/buildinfo.Commit=$commit -X github.com/tr1xdev/datagram-server.git/internal/buildinfo.BuildDate=$build_date"

build_one() {
  goos=$1
  goarch=$2
  ext=$3
  name="api_datagram_${version}_${goos}_${goarch}"
  stage="$work/$name"
  mkdir -p "$stage"
  echo "building $goos/$goarch"
  (cd "$repo" && CGO_ENABLED=0 GOOS=$goos GOARCH=$goarch go build -trimpath -buildvcs=false -ldflags "$ldflags" -o "$stage/api_datagram$ext" ./cmd/api_datagram)
  cp "$repo/LICENSE" "$repo/README.md" "$repo/config.example.yaml" "$stage/"
  find "$stage" -exec touch -d "@$epoch" {} + 2>/dev/null || true
  tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@$epoch" -C "$work" -cf - "$name" | gzip -n >"$out/$name.tar.gz"
}

build_one linux amd64 ""
build_one linux arm64 ""
build_one windows amd64 .exe
build_one darwin amd64 ""
build_one darwin arm64 ""

(cd "$out" && sha256sum api_datagram_* > SHA256SUMS)
echo "release artifacts written to $out"
