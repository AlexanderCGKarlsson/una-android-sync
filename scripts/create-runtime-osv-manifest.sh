#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
output_path=${1:-}

if [ -z "$output_path" ]; then
    echo "Usage: $0 OUTPUT_PATH" >&2
    exit 2
fi

case "$output_path" in
    /*) ;;
    *) output_path="$repo_dir/$output_path" ;;
esac

cd "$repo_dir"

awk -F= '
    /^[^#].*=/ && $2 ~ /(^|,)(releaseRuntimeClasspath|runtimeClasspath)(,|$)/ {
        split($1, coordinate, ":")
        if (length(coordinate) >= 3) {
            version = coordinate[length(coordinate)]
            name = coordinate[1] ":" coordinate[2]
            key = name SUBSEP version
            packages[key] = 1
        }
    }
    END {
        printf "{\"results\":[{\"packages\":["
        separator = ""
        for (key in packages) {
            split(key, parts, SUBSEP)
            printf "%s{\"package\":{\"name\":\"%s\",\"version\":\"%s\",\"ecosystem\":\"Maven\"}}", separator, parts[1], parts[2]
            separator = ","
        }
        print "]}]}"
    }
' \
    crypto-core/gradle.lockfile \
    android-keystore/gradle.lockfile \
    convex-sync/gradle.lockfile > "$output_path"
