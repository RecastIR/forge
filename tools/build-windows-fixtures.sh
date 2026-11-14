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
cd "$repo"
suite="$repo/tests/differential"
root=${BUILD_ROOT:-build}
output="$root/fixtures/windows-x64"
if git -C "$repo" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    tracked=$(git -C "$repo" ls-files -- 'tests/differential/*.exe' 'tests/differential/*SHA256SUMS')
    if [ -n "$tracked" ]; then
        printf 'Generated fixture artifacts in the Git index:\n%s\n' "$tracked" >&2
        exit 1
    fi
    # In-repository exports must be ignored. An intentional external root is also supported.
    relative=$(python3 -c 'import os,sys; print(os.path.relpath(os.path.realpath(sys.argv[1])))' "$output")
    case "$relative" in
        ../*) ;;
        *)
            if test -n "$(git ls-files -- "$relative")" || ! git check-ignore -q -- "$relative/debug/SHA256SUMS"; then
                echo "The fixture export directory must be ignored by Git: $output" >&2
                exit 1
            fi ;;
    esac
fi
image=$(python3 -B "$suite/fixture_images.py" --id toolchain)
mkdir -p "$output" "$root/tmp"
output=$(cd "$output" && pwd -P)
temporary=$(cd "$root/tmp" && pwd -P)
exec docker run --pull never --rm --platform linux/amd64 --network none --user "$(id -u):$(id -g)" \
    -e "FORGE_TOOLCHAIN_ID=$image" -e TMPDIR=/forge-tmp -v "$temporary:/forge-tmp" \
    -v "$suite:/suite:ro" -v "$output:/output" "$image" python3 -B /suite/build.py "$@"
