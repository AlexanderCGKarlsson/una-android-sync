#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)

cd "$repo_dir"
./gradlew clean test assembleRelease
"$script_dir/check-runtime-vulnerabilities.sh"
