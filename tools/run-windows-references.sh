#!/bin/sh
set -eu
repo=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec python3 -B "$repo/tests/differential/reference/run.py" "$@"
