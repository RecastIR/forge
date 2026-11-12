#!/bin/sh
# Run the same mandatory stages locally and in Forge CI.
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"
test "$#" = 1 || { echo "usage: $0 --all | --native | --references | --differential" >&2; exit 2; }
suite=tests/differential
export FORGE_TEST_RUN_ID="${FORGE_TEST_RUN_ID:-$(python3 -c 'import uuid; print(uuid.uuid4())')}"
run_differential() (
    status=0
    CMAKE_GENERATOR=Xcode ./tools/run-differential.sh --all --config debug --forge build-sanitize/forge || status=1
    ./tools/run-differential.sh --all --config release || status=1
    python3 -B "$suite/test_native_differential.py" || status=1
    exit "$status"
)
case "$1" in
--native)
    test "$(uname -sm)" = 'Darwin arm64' || { echo "Full native tests require macOS arm64." >&2; exit 1; }
    make format-check
    make lint
    for tree in build build-sanitize; do
        result="$repo/$tree/required-tests.xml"
        # A fresh result is necessary even when reusing a configured build tree.
        if test -f "$result"; then unlink "$result"; fi
        if test "$tree" = build; then
            make test BUILD_DIR=build CONFIG=Debug BUILD_TESTING=ON CTEST_ARGS="--output-junit \"$result\""
        else
            make sanitize BUILD_DIR=build BUILD_TESTING=ON CTEST_ARGS="--output-junit \"$result\""
        fi
        python3 - "$result" <<'PY'
import sys
from xml.etree import ElementTree
tests = ElementTree.parse(sys.argv[1]).findall(".//testcase")
for name in ("native", "differential"):
    found = [t for t in tests if t.get("name") == name]
    if len(found) != 1 or found[0].get("status") != "run" or len(found[0].findall("skipped")):
        sys.exit(f"Required CTest {name} did not execute. Select a Python interpreter with Unicorn 2.1.4 via CMAKE_ARGS.")
PY
    done ;;
--references)
    docker info >/dev/null || { echo "Start a Docker engine with Linux amd64 support for the pinned MinGW and Wine images." >&2; exit 1; }
    python3 -B "$suite/manifests.py"
    ./tools/build-windows-fixtures.sh --all
    ./tools/run-windows-references.sh --all
    python3 -B "$suite/reference/test_wine.py" ;;
--differential)
    status=0
    run_differential || status=1
    # The hosted regression-gate independently verifies the downloaded evidence.
    if test "${GITHUB_ACTIONS:-}" != true; then
        outcome=success
        if test "$status" != 0; then outcome=failure; fi
        python3 -B "$suite/coverage_report.py" --comparison "$outcome" || status=1
    fi
    exit "$status" ;;
--all)
    native=success
    references=success
    compare=skipped
    "$repo/tools/test-forge.sh" --native || native=failure
    "$repo/tools/test-forge.sh" --references || references=failure
    if test "$native/$references" = success/success; then
        compare=success
        run_differential || compare=failure
    fi
    exec python3 -B "$suite/coverage_report.py" --local-jobs "$native" "$references" "$compare" ;;
*) echo "usage: $0 --all | --native | --references | --differential" >&2; exit 2 ;;
esac
