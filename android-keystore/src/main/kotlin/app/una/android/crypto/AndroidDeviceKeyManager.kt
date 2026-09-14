package app.una.android.crypto

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import androidx.annotation.RequiresApi
import java.nio.ByteBuffer
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Stable P-256 device key used for household-key recovery and rotation envelopes.
 *
 * Android 12+ keeps the ECDH private key non-exportable in Android Keystore. Older supported
 * versions use a software P-256 key whose encoded private value is encrypted by a device-bound
 * Android Keystore AES key in no-backup storage.
 */
class AndroidDeviceKeyManager(context: Context) {
    private val legacyFile = AtomicFile(context.noBackupFilesDir.resolve(LEGACY_FILE_NAME))

    fun publicKeyX963(): ByteArray = UnaDeviceEnvelope.publicKeyToX963(keyPair().public)

    fun deviceIdentifier(): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(publicKeyX963())
        return "android:" + Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    fun unwrap(envelope: ByteArray): ByteArray {
        val pair = keyPair()
        return UnaDeviceEnvelope.unwrap(
            envelope = envelope,
            recipientPrivateKey = pair.private,
            keyAgreementProvider = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                ANDROID_KEY_STORE
            } else {
                null
            },
        )
    }

    private fun keyPair(): KeyPair = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
        getOrCreateHardwareBackedPair()
    } else {
        getOrCreateEncryptedSoftwarePair()
    }

    @RequiresApi(Build.VERSION_CODES.S)
    private fun getOrCreateHardwareBackedPair(): KeyPair {
        val keyStore = keyStore()
        val privateKey = keyStore.getKey(DEVICE_KEY_ALIAS, null) as? PrivateKey
        val publicKey = keyStore.getCertificate(DEVICE_KEY_ALIAS)?.publicKey
        if (privateKey != null && publicKey != null) return KeyPair(publicKey, privateKey)

        return KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEY_STORE).run {
            initialize(
                KeyGenParameterSpec.Builder(
                    DEVICE_KEY_ALIAS,
                    KeyProperties.PURPOSE_AGREE_KEY,
                )
                    .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                    .build(),
            )
            generateKeyPair()
        }
    }

    private fun getOrCreateEncryptedSoftwarePair(): KeyPair {
        if (legacyFile.baseFile.exists()) {
            return decodeKeyPair(decryptLegacy(legacyFile.readFully()))
        }

        val pair = KeyPairGenerator.getInstance("EC").run {
            initialize(ECGenParameterSpec("secp256r1"))
            generateKeyPair()
        }
        val encoded = encodeKeyPair(pair)
        val record = encryptLegacy(encoded)
        val stream = legacyFile.startWrite()
        try {
            stream.write(record)
            legacyFile.finishWrite(stream)
        } catch (error: Throwable) {
            legacyFile.failWrite(stream)
            throw error
        }
        return pair
    }

    private fun encodeKeyPair(pair: KeyPair): ByteArray {
        val privateBytes = pair.private.encoded
        val publicBytes = pair.public.encoded
        return ByteBuffer.allocate(8 + privateBytes.size + publicBytes.size)
            .putInt(privateBytes.size)
            .put(privateBytes)
            .putInt(publicBytes.size)
            .put(publicBytes)
            .array()
    }

    private fun decodeKeyPair(encoded: ByteArray): KeyPair {
        val buffer = ByteBuffer.wrap(encoded)
        val privateSize = buffer.int
        require(privateSize in 1..buffer.remaining()) { "Stored device private key is invalid" }
        val privateBytes = ByteArray(privateSize).also(buffer::get)
        val publicSize = buffer.int
        require(publicSize in 1..buffer.remaining()) { "Stored device public key is invalid" }
        val publicBytes = ByteArray(publicSize).also(buffer::get)
        require(!buffer.hasRemaining()) { "Stored device key has trailing data" }
        val factory = KeyFactory.getInstance("EC")
        return KeyPair(
            factory.generatePublic(X509EncodedKeySpec(publicBytes)),
            factory.generatePrivate(PKCS8EncodedKeySpec(privateBytes)),
        )
    }

    private fun encryptLegacy(value: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateLegacyKek())
        return byteArrayOf(cipher.iv.size.toByte()) + cipher.iv + cipher.doFinal(value)
    }

    private fun decryptLegacy(record: ByteArray): ByteArray {
        require(record.isNotEmpty()) { "Stored device key is empty" }
        val nonceSize = record.first().toInt() and 0xff
        require(nonceSize == 12 && record.size > 1 + nonceSize + 16) { "Stored device key is invalid" }
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            getOrCreateLegacyKek(),
            GCMParameterSpec(128, record.copyOfRange(1, 1 + nonceSize)),
        )
        return cipher.doFinal(record.copyOfRange(1 + nonceSize, record.size))
    }

    private fun getOrCreateLegacyKek(): SecretKey {
        val keyStore = keyStore()
        (keyStore.getKey(LEGACY_KEK_ALIAS, null) as? SecretKey)?.let { return it }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE).run {
            init(
                KeyGenParameterSpec.Builder(
                    LEGACY_KEK_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
                )
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    .setRandomizedEncryptionRequired(true)
                    .build(),
            )
            generateKey()
        }
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply { load(null) }

    private companion object {
        const val ANDROID_KEY_STORE = "AndroidKeyStore"
        const val DEVICE_KEY_ALIAS = "app.una.android.device-recovery-ecdh.v1"
        const val LEGACY_KEK_ALIAS = "app.una.android.device-recovery-kek.v1"
        const val LEGACY_FILE_NAME = "device-recovery-key.v1"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
    }
}
