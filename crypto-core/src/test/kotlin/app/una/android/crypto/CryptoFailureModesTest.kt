package app.una.android.crypto

import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Test

class CryptoFailureModesTest {
    @Test
    fun anotherHouseholdKeyCannotDecryptPayload() {
        val householdAKey = ByteArray(32) { 0x11 }
        val householdBKey = ByteArray(32) { 0x22 }
        val encrypted = UnaPayloadCrypto.encrypt(
            plaintext = "private household content".encodeToByteArray(),
            key = householdAKey,
            secureRandom = DeterministicSecureRandom(7),
        )

        assertThrows(AEADBadTagException::class.java) {
            UnaPayloadCrypto.decrypt(encrypted, householdBKey)
        }
    }

    @Test
    fun tamperedCiphertextIsRejected() {
        val key = ByteArray(32) { 0x33 }
        val encrypted = UnaPayloadCrypto.encrypt(
            "unaltered".encodeToByteArray(),
            key,
            DeterministicSecureRandom(8),
        )
        val tampered = encrypted.ciphertext.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }

        assertThrows(AEADBadTagException::class.java) {
            UnaPayloadCrypto.decrypt(encrypted.copy(ciphertext = tampered), key)
        }
    }

    @Test
    fun tamperedAuthenticationTagIsRejected() {
        val key = ByteArray(32) { 0x44 }
        val encrypted = UnaPayloadCrypto.encrypt(
            "unaltered".encodeToByteArray(),
            key,
            DeterministicSecureRandom(9),
        )
        val tampered = encrypted.ciphertext.copyOf().also {
            it[it.lastIndex] = (it.last().toInt() xor 1).toByte()
        }

        assertThrows(AEADBadTagException::class.java) {
            UnaPayloadCrypto.decrypt(encrypted.copy(ciphertext = tampered), key)
        }
    }

    @Test
    fun tamperedNonceIsRejected() {
        val key = ByteArray(32) { 0x55 }
        val encrypted = UnaPayloadCrypto.encrypt(
            "unaltered".encodeToByteArray(),
            key,
            DeterministicSecureRandom(10),
        )
        val tamperedNonce = encrypted.nonce.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }

        assertThrows(AEADBadTagException::class.java) {
            UnaPayloadCrypto.decrypt(encrypted.copy(nonce = tamperedNonce), key)
        }
    }

    @Test
    fun independentEncryptionsUseDifferentNonces() {
        val key = ByteArray(32) { 0x66 }
        val random = CountingSecureRandom()

        val first = UnaPayloadCrypto.encrypt("same".encodeToByteArray(), key, random)
        val second = UnaPayloadCrypto.encrypt("same".encodeToByteArray(), key, random)

        assertFalse(first.nonce.contentEquals(second.nonce))
    }

    @Test
    fun malformedPayloadSizesAreRejectedBeforeDecrypting() {
        assertThrows(IllegalArgumentException::class.java) {
            UnaPayloadCrypto.decrypt(EncryptedPayload(ByteArray(16), ByteArray(12)), ByteArray(31))
        }
        assertThrows(IllegalArgumentException::class.java) {
            UnaPayloadCrypto.decrypt(EncryptedPayload(ByteArray(16), ByteArray(11)), ByteArray(32))
        }
        assertThrows(IllegalArgumentException::class.java) {
            UnaPayloadCrypto.decrypt(EncryptedPayload(ByteArray(15), ByteArray(12)), ByteArray(32))
        }
    }

    private class DeterministicSecureRandom(private val value: Int) : SecureRandom() {
        override fun nextBytes(bytes: ByteArray) = bytes.fill(value.toByte())
    }

    private class CountingSecureRandom : SecureRandom() {
        private var value = 1

        override fun nextBytes(bytes: ByteArray) {
            bytes.fill(value.toByte())
            value += 1
        }
    }
}
