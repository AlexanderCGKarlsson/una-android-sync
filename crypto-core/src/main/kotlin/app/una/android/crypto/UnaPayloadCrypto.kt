package app.una.android.crypto

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

data class EncryptedPayload(
    val ciphertext: ByteArray,
    val nonce: ByteArray,
)

/**
 * Una payload contract:
 * - AES-256-GCM
 * - 12-byte nonce
 * - ciphertext is body followed by the 16-byte authentication tag
 * - no associated authenticated data
 */
object UnaPayloadCrypto {
    private const val KEY_SIZE_BYTES = 32
    private const val NONCE_SIZE_BYTES = 12
    private const val TAG_SIZE_BITS = 128

    fun encrypt(
        plaintext: ByteArray,
        key: ByteArray,
        secureRandom: SecureRandom = SecureRandom(),
    ): EncryptedPayload {
        require(key.size == KEY_SIZE_BYTES) { "Una payload keys must be 32 bytes" }
        val nonce = ByteArray(NONCE_SIZE_BYTES).also(secureRandom::nextBytes)
        return encryptWithNonce(plaintext, key, nonce)
    }

    internal fun encryptWithNonce(
        plaintext: ByteArray,
        key: ByteArray,
        nonce: ByteArray,
    ): EncryptedPayload {
        require(key.size == KEY_SIZE_BYTES) { "Una payload keys must be 32 bytes" }
        require(nonce.size == NONCE_SIZE_BYTES) { "Una payload nonces must be 12 bytes" }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(TAG_SIZE_BITS, nonce),
        )
        return EncryptedPayload(
            ciphertext = cipher.doFinal(plaintext),
            nonce = nonce.copyOf(),
        )
    }

    fun decrypt(payload: EncryptedPayload, key: ByteArray): ByteArray {
        require(key.size == KEY_SIZE_BYTES) { "Una payload keys must be 32 bytes" }
        require(payload.nonce.size == NONCE_SIZE_BYTES) { "Una payload nonces must be 12 bytes" }
        require(payload.ciphertext.size >= TAG_SIZE_BITS / 8) {
            "Una payload ciphertext is missing its authentication tag"
        }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(TAG_SIZE_BITS, payload.nonce),
        )
        return cipher.doFinal(payload.ciphertext)
    }
}
