#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
private_source_root=${UNA_ANDROID_SOURCE_ROOT:-}
core_mirror_root="$repo_dir/crypto-core/src/main/kotlin/app/una/android/crypto"
keystore_mirror_root="$repo_dir/android-keystore/src/main/kotlin/app/una/android/crypto"

if [ -z "$private_source_root" ]; then
    echo "Set UNA_ANDROID_SOURCE_ROOT to the private Android crypto source directory." >&2
    exit 2
fi

compare_files() {
    mirror_root=$1
    shift
    for source_name in "$@"
    do
        if [ ! -f "$private_source_root/$source_name" ]; then
            echo "Missing private source: $private_source_root/$source_name" >&2
            exit 2
        fi
        diff -u "$private_source_root/$source_name" "$mirror_root/$source_name"
    done
}

compare_files "$core_mirror_root" \
    UnaPayloadCrypto.kt \
    UnaDeviceEnvelope.kt \
    HouseholdKeyring.kt \
    AgentReadableKeyring.kt

compare_files "$keystore_mirror_root" \
    AndroidKeyringVault.kt \
    AndroidAgentReadableKeyringVault.kt \
    AndroidDeviceKeyManager.kt

echo "crypto-core and android-keystore match the private Una Android source."
