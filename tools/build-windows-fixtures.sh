#!/bin/sh
set -eu

case "$#:${1-}" in
    1:--all) set -- debug release ;;
    2:--config)
        case "$2" in
            debug|release) set -- "$2" ;;
            *) echo "expected --config debug or --config release" >&2; exit 2 ;;
        esac ;;
    *) echo "usage: $0 --all | --config debug | --config release" >&2; exit 2 ;;
esac

repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
suite="$repo/tests/differential"
output="$repo/build/fixtures/windows-x64"
if git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    tracked=$(git -C "$repo" ls-files -- build/fixtures/windows-x64 'tests/differential/*.exe' 'tests/differential/*SHA256SUMS')
    if [ -n "$tracked" ]; then
        printf 'Generated fixture artifacts in the Git index:\n%s\n' "$tracked" >&2
        exit 1
    fi
    if ! git -C "$repo" check-ignore -q build/fixtures/windows-x64/debug/SHA256SUMS; then
        echo "The fixture export directory must be ignored by Git." >&2
        exit 1
    fi
fi
mkdir -p "$output"
image=$(docker build --platform linux/amd64 --target toolchain -q -t forge-windows-fixture-toolchain \
    -f "$suite/toolchain/Dockerfile" "$suite")
exec docker run --rm --platform linux/amd64 --network none --user "$(id -u):$(id -g)" \
    -v "$suite:/suite:ro" -v "$output:/output" "$image" python3 -B /suite/build.py "$@"
