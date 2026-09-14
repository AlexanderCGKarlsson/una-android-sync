package app.una.android.crypto

import java.util.Base64
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class UnaPayloadCryptoTest {
    private val decoder = Base64.getDecoder()

    @Test
    fun decryptsCrossPlatformFixture() {
        val payload = EncryptedPayload(
            ciphertext = decoder.decode(CIPHERTEXT) + decoder.decode(TAG),
            nonce = decoder.decode(NONCE),
        )

        val plaintext = UnaPayloadCrypto.decrypt(payload, decoder.decode(KEY))

        assertEquals("{\"name\":\"Una Android probe\"}", plaintext.decodeToString())
    }

    @Test
    fun encryptionMatchesCrossPlatformFixture() {
        val encrypted = UnaPayloadCrypto.encryptWithNonce(
            plaintext = "{\"name\":\"Una Android probe\"}".encodeToByteArray(),
            key = decoder.decode(KEY),
            nonce = decoder.decode(NONCE),
        )

        assertArrayEquals(
            decoder.decode(CIPHERTEXT) + decoder.decode(TAG),
            encrypted.ciphertext,
        )
    }

    private companion object {
        const val KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
        const val NONCE = "EBESExQVFhcYGRob"
        const val CIPHERTEXT = "Btz2dySsGInoIGZ8LzgHN6U/J2o7siXehZzAGg=="
        const val TAG = "zfWl++RmHDqBzByYmOFtdw=="
    }
}
