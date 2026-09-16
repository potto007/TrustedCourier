#!/bin/sh
# Builds the release binaries: tc and the OpenBao Backend Plugin, static,
# stripped, and linked against Go's validated FIPS 140-3 module (ADR-0027),
# into the directory given as the first argument (default: dist). Run from
# the repository root, or from anywhere with the path to it in TC_SRC.
#
#   scripts/build-release.sh [out-dir]
#
# The binaries run outside containers on any Linux (or the build's GOOS and
# GOARCH); set GOOS and GOARCH to cross-compile. SHA256SUMS lists both, in
# the form tc plugin sha256 prints, for pinning the plugin in a config.
set -eu

out=${1:-dist}
src=${TC_SRC:-$(cd "$(dirname "$0")/.." && pwd)}
mkdir -p "$out"
out=$(cd "$out" && pwd)

export CGO_ENABLED=0
export GOFIPS140=${GOFIPS140:-certified}
set -- -trimpath -ldflags "-s -w" -buildvcs=false

(cd "$src" && go build "$@" -o "$out/tc" ./cmd/tc)
(cd "$src/plugins/openbao" && go build "$@" -o "$out/openbao-plugin" .)

(cd "$out" && sha256sum tc openbao-plugin > SHA256SUMS)
echo "built into $out:"
cat "$out/SHA256SUMS"
