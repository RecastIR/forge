#!/bin/bash
set -eu

list=$1
dest=$2
test -s "$list"
mkdir "$dest"
while IFS= read -r pe; do
    cp "build/dev/fixtures/Debug/$pe" "$dest/"
done < "$list"

cd "$dest"
xargs shasum -a 256 < "$list" > SHA256SUMS
digest=$(shasum -a 256 SHA256SUMS)
echo "sha256=${digest%% *}" >> "$GITHUB_OUTPUT"
