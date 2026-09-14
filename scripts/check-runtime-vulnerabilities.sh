#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
scanner=${UNA_OSV_SCANNER_BIN:-osv-scanner}

if ! command -v "$scanner" >/dev/null 2>&1; then
    echo "OSV-Scanner was not found. Install it or set UNA_OSV_SCANNER_BIN." >&2
    exit 1
fi

temp_dir=$(mktemp -d)
trap 'rm -rf "$temp_dir"' EXIT INT TERM
manifest="$temp_dir/runtime-osv-lock.json"

"$script_dir/create-runtime-osv-manifest.sh" "$manifest"

"$scanner" scan source \
    --offline-vulnerabilities \
    --download-offline-databases \
    --no-resolve \
    --lockfile="osv-scanner:$manifest"
