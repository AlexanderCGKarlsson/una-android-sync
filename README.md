# Una Android Encryption & Sync

This repository contains the Android encryption and ciphertext-sync boundary used by
[Una](https://unafamily.app), a privacy-first family planner. It exists so the security-sensitive
part of the Android client can be inspected and tested without publishing the rest of the
application.

## What is included

- `crypto-core`: the portable Kotlin/JCA implementation used by Una Android for AES-256-GCM
  payload encryption, P-256 ECDH device recovery envelopes, HKDF-SHA256 key derivation, household
  keyrings, and assistant-readable key separation.
- `android-keystore`: the Android-specific vaults and device-key manager used to protect exportable
  keyrings with device-bound Android Keystore keys and no-backup local storage.
- `convex-sync`: the narrow Android transport adapter that accepts ciphertext, nonce, key version,
  and explicitly server-visible indexed metadata. It has no plaintext or raw-key parameter.
- Cross-platform fixtures shared with Una's Apple implementation.
- Failure tests for wrong keys, other-device keys, tampering, malformed envelopes, and household
  keyring isolation.
- Dependency locking, checksum verification, and a runtime dependency CVE check.

The production crypto files are mirrored rather than reimplemented. Maintainers can run the source
parity check to confirm that this repository still matches the corresponding Una Android source
byte-for-byte.

## Verify the privacy claims

| Claim | Implementation | Test |
| --- | --- | --- |
| Household payloads are encrypted on-device with AES-256-GCM and a fresh nonce. | [`UnaPayloadCrypto.kt`](crypto-core/src/main/kotlin/app/una/android/crypto/UnaPayloadCrypto.kt) | [`UnaPayloadCryptoTest.kt`](crypto-core/src/test/kotlin/app/una/android/crypto/UnaPayloadCryptoTest.kt) |
| Another household key cannot decrypt the payload, and modified ciphertext is rejected. | [`UnaPayloadCrypto.kt`](crypto-core/src/main/kotlin/app/una/android/crypto/UnaPayloadCrypto.kt) | [`CryptoFailureModesTest.kt`](crypto-core/src/test/kotlin/app/una/android/crypto/CryptoFailureModesTest.kt) |
| A key wrapped for one device cannot be opened by another device key. | [`UnaDeviceEnvelope.kt`](crypto-core/src/main/kotlin/app/una/android/crypto/UnaDeviceEnvelope.kt) | [`DeviceEnvelopeFailureModesTest.kt`](crypto-core/src/test/kotlin/app/una/android/crypto/DeviceEnvelopeFailureModesTest.kt) |
| Local keyrings are protected by Android Keystore. | [`AndroidKeyringVault.kt`](android-keystore/src/main/kotlin/app/una/android/crypto/AndroidKeyringVault.kt) | [`AndroidKeystoreSecurityTest.kt`](android-keystore/src/androidTest/kotlin/app/una/android/crypto/AndroidKeystoreSecurityTest.kt) |
| The sync adapter cannot represent plaintext or raw household keys. | [`ConvexCiphertextSync.kt`](convex-sync/src/main/kotlin/app/una/android/sync/ConvexCiphertextSync.kt) | [`ConvexCiphertextSyncTest.kt`](convex-sync/src/test/kotlin/app/una/android/sync/ConvexCiphertextSyncTest.kt) |

These properties use standard platform cryptography. Una does not implement its own cipher or
random-number generator. The [public fixture](crypto-core/src/test/resources/una-crypto-v1.json)
contains only synthetic interoperability values, never production credentials or household data.

## Privacy boundary

User-entered household content is encrypted on an authorized device before a backend write and is
not stored there as plaintext. This includes the content inside household profiles, calendar
entries, lists, tasks, birthdays, notes, and attachments.

Una still retains the limited operational metadata required to authenticate members, authorize
household access, synchronize records, order results, and operate the service. Depending on the
feature, this can include record identifiers, membership relationships, timestamps, and selected
fields needed for ordering, filtering, or scheduling.

That distinction matters: the correct claim is that Una cannot read encrypted household content in
normal operation, not that the service receives zero information.

## Responsibility and limits

Una is responsible for using reviewed cryptography, encrypting household content before sync,
authorizing household access, protecting locally stored keys, and keeping plaintext out of backend
storage, logs, analytics, and server-side convenience fields.

Plaintext and decryption keys are available on an authorized household device because that device
must display and edit the family's information. Device owners are responsible for who they invite,
which devices they approve, and the security of those authorized devices. This library cannot
protect locally available content after an authorized device or its operating system is
compromised.

The published modules cover Android cryptography, local key protection, and the ciphertext
transport contract. Backend authorization, release-binary provenance, and the rest of the Una
application are reviewed separately.

## Build and test

Requirements:

- JDK 17
- Android SDK 36
- [OSV-Scanner](https://google.github.io/osv-scanner/) for the runtime dependency check

```sh
./gradlew clean test
./gradlew :android-keystore:connectedDebugAndroidTest
./scripts/check-runtime-vulnerabilities.sh
```

The Android Keystore test requires a running emulator or connected Android device. Test vectors
are synthetic and intentionally public; they are not Una credentials or live household data.

Maintainers with access to the private application source can also verify the mirror:

```sh
UNA_ANDROID_SOURCE_ROOT=/path/to/android/crypto ./scripts/check-source-parity.sh
```

Dependency locks and artifact checksums make version changes explicit. The runtime scan checks the
dependencies shipped with these modules; build and test tooling is maintained separately.

Current local verification includes portable cryptography tests, ciphertext-boundary tests,
Android Keystore instrumentation tests, cross-platform fixtures, source-parity checks, and a
runtime dependency scan. These are repeatable engineering checks, not an independent audit.

## What this repository does not prove

Publishing source makes the implementation reviewable. By itself, it does not prove that a
downloaded application binary was built from a particular commit, that a private backend is
configured correctly, or that the system has received an independent security audit.

Una maintains those as separate verification responsibilities and does not describe this
repository as a formal audit.

## Security reports

Please do not open a public issue for a suspected vulnerability. Use GitHub private vulnerability
reporting when available, or contact the Una maintainer privately. Never include real household
content, active invite links, tokens, or keys in a report.

## License

Licensed under the [Apache License 2.0](LICENSE).
